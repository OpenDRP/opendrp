"""Per-user throttle for *manual* actions (Rescan / report generation).

``users.rate_limit_minutes`` bounds how often one account may trigger a manual
action, and the window is counted **per scope**: once per connector
(``dnstwist``, ``shodan``, ``hibp``, …) and once for the reports module. A
frequent breach rescan therefore never blocks report generation.

State lives in Redis only (``rl:manual:<user_id>:<scope>``, ``SET NX EX``), so
the API stays stateless and horizontally scalable. The counter is a
"last action" marker, not an incrementing counter: the window is a sliding
interval between two actions, which is what "not more often than once every N
minutes" means for an operator.

Failure mode is **fail-open**, matching the login limiter: if Redis is
unavailable the action proceeds and a warning is logged. Losing the throttle
for the duration of an outage is preferable to locking operators out of the
platform, and every blocked attempt is still recorded in the audit trail.
"""

from __future__ import annotations

import uuid

import structlog

from app.core.audit import AuditLogger
from app.core.exceptions import RateLimitException
from app.core.rate_limit import RateLimiter

log = structlog.get_logger()

MANUAL_RATE_LIMIT_PREFIX = "rl:manual:"

# Scope of the report module. Connector scopes use the connector name.
SCOPE_REPORTS = "reports"


def manual_rate_limit_key(user_id: uuid.UUID | str, scope: str) -> str:
    return f"{MANUAL_RATE_LIMIT_PREFIX}{user_id}:{scope}"


class ManualRateLimiter:
    @staticmethod
    async def acquire(
        user_id: uuid.UUID | str, scope: str, limit_minutes: int
    ) -> int | None:
        """Claim the window for ``(user, scope)``.

        Returns ``None`` when the action is allowed (and the window is now
        claimed), or the number of seconds the caller must wait when it is
        blocked.
        """
        limit = int(limit_minutes or 0)
        if limit <= 0:
            return None
        client = RateLimiter._get_client()
        if client is None:
            return None
        key = manual_rate_limit_key(user_id, scope)
        window = limit * 60
        try:
            claimed = await client.set(key, "1", nx=True, ex=window)
        except Exception as e:  # pragma: no cover - depends on Redis health
            log.warning("manual_rate_limit_redis_error", err=str(e)[:200])
            RateLimiter._reset_client()
            return None
        if claimed:
            return None
        try:
            ttl = int(await client.ttl(key))
        except Exception:  # pragma: no cover - depends on Redis health
            log.warning("manual_rate_limit_ttl_error", scope=scope)
            ttl = window
        return ttl if ttl > 0 else window

    @staticmethod
    async def reset(user_id: uuid.UUID | str, scope: str) -> None:
        """Drop the window for ``(user, scope)`` — used by tests and support."""
        client = RateLimiter._get_client()
        if client is None:
            return
        try:
            await client.delete(manual_rate_limit_key(user_id, scope))
        except Exception as e:  # pragma: no cover - depends on Redis health
            log.warning("manual_rate_limit_reset_error", err=str(e)[:200])


async def enforce_manual_rate_limit(
    *,
    db,
    user,
    scope: str,
    action: str,
    ip_address: str | None,
) -> None:
    """Raise 429 and audit when ``user`` is inside the window for ``scope``."""
    limit = int(getattr(user, "rate_limit_minutes", 0) or 0)
    user_id = getattr(user, "id", None)
    if user_id is None:
        # No identity to key the window on: never invent one, just allow.
        return
    remaining = await ManualRateLimiter.acquire(user_id, scope, limit)
    if remaining is None:
        return
    wait_minutes = max(1, -(-remaining // 60))
    log.warning(
        "manual_action_rate_limited",
        user_id=str(user_id),
        scope=scope,
        action=action,
        retry_after=remaining,
    )
    await AuditLogger.emit(
        db,
        action="rate_limit.manual_action_blocked",
        ip_address=ip_address,
        user_id=user_id,
        details={
            "action": action,
            "scope": scope,
            "limit_minutes": limit,
            "retry_after_seconds": remaining,
        },
    )
    raise RateLimitException(
        detail=(
            f"Rate limit: {action} is limited to once every {limit} minute(s) "
            f"for scope '{scope}'. Try again in about {wait_minutes} minute(s)."
        ),
        retry_after=remaining,
    )
