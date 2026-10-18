"""Refused authorizations, recorded once per account and route.

Why this exists
---------------
A 403 used to leave no trace at all: the role predicates raised
``ForbiddenException``, the exception handler answered, and a viewer asking for
``POST /api/v1/users`` forty times produced nothing anywhere — not in
``drp_audit_logs``, not on stdout. For a platform whose product *is* the trail,
that is a blind spot exactly on the boundary the trail is supposed to describe:
"an analyst tried to administer accounts" was unanswerable.

Auditing every refusal, on the other hand, turns the mechanism into an amplifier:
the cheapter it is to be refused, the more rows a client ignoring ``403`` writes,
and the load lands on the database that serves the rest of the platform. So a
refusal is recorded **once per account, method and route inside a window** — the
same shape the request throttle already uses for its own block notice
(``SET NX EX``), with one addition: when Redis is unavailable the camera stays on.
A bounded in-process map enforces the same window per replica, because "the
counter store is down" must not silently mean "authorization refusals are no
longer recorded". Multiple replicas may each write one row during such an outage;
that is the deliberate direction of the error — a duplicated signal, never a
missing one.

What is *not* recorded here
---------------------------
The second-factor policy refusal stays ``auth.mfa.required``: that event already
exists, describes the account rather than the route, and two names for one
refusal would split a SIEM rule in half.
"""

from __future__ import annotations

import time

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditLogger
from app.core.rate_limit import RateLimiter
from app.models.user import User

log = structlog.get_logger()

#: One window, five minutes. Long enough that a script hammering an admin route
#: is one event, short enough that a genuine change of intent the same morning is
#: a second one.
_WINDOW_SECONDS = 300

_REDIS_PREFIX = "rl:authz:"

#: Cap on the in-process fallback. A refused flood is bounded by the account's
#: request limit anyway; the cap keeps a pathological run from growing the map
#: without bound in a process that has lost Redis.
_LOCAL_MAX_ENTRIES = 1024
_local_claims: dict[str, float] = {}


def _purge_local(now: float) -> None:
    expired = [key for key, expires_at in _local_claims.items() if expires_at <= now]
    for key in expired:
        _local_claims.pop(key, None)


def _claim_locally(key: str, now: float) -> bool:
    _purge_local(now)
    if key in _local_claims:
        return False
    if len(_local_claims) >= _LOCAL_MAX_ENTRIES:
        oldest = min(_local_claims, key=lambda item: _local_claims[item])
        _local_claims.pop(oldest, None)
    _local_claims[key] = now + _WINDOW_SECONDS
    return True


async def _claim_window(key: str) -> bool:
    """True when this refusal is the first one of the window."""
    client = RateLimiter._get_client()
    if client is not None:
        try:
            claimed = await client.set(
                f"{_REDIS_PREFIX}{key}", "1", nx=True, ex=_WINDOW_SECONDS
            )
            return bool(claimed)
        except Exception as e:
            log.warning("authorization_audit_redis_error", err=str(e)[:200])
            RateLimiter._reset_client()
    return _claim_locally(key, time.monotonic())


def reset_local_claims() -> None:
    """Drop the in-process fallback state — used by tests."""
    _local_claims.clear()


async def audit_denied_authorization(
    db: AsyncSession,
    *,
    user: User,
    required: str,
    path: str,
    method: str,
    ip_address: str,
    target_id: str | None = None,
) -> None:
    """Record one ``authz.denied`` row, at most once per window per route.

    Best-effort by design: a refusal must never turn into a 500 because the audit
    write failed, and the caller is about to raise the 403 regardless.
    """
    key = f"{user.id}:{method}:{path}"
    try:
        if not await _claim_window(key):
            return
        details: dict[str, object] = {
            "path": path,
            "method": method,
            "role": str(getattr(user.role, "value", user.role)),
            "required": required,
        }
        if target_id:
            details["target_id"] = target_id
        await AuditLogger.emit(
            db,
            action="authz.denied",
            ip_address=ip_address,
            user_id=user.id,
            details=details,
        )
    except Exception as e:  # pragma: no cover - depends on database health
        log.warning("authorization_audit_write_failed", err=str(e)[:200])


__all__ = ["audit_denied_authorization", "reset_local_claims"]
