"""Account-scoped, atomic request budgets shared across module workers."""

from datetime import datetime, timezone
import uuid
from typing import Any, Awaitable, cast

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rate_limit import RateLimiter
from app.models.connector import Connector
from app.models.source_account import SourceAccount
from app.models.job import Job, JobStatus
from app.services.module_registry import require_enabled_module

LIMITS = {
    "requests_per_minute": (1, 600, 10),
    "daily_budget": (1, 100000, 100),
    "max_requests": (1, 1000, 20),
    "max_pages": (1, 100, 3),
    "max_results": (1, 5000, 100),
    "max_targets": (1, 1000, 20),
    "scan_timeout_seconds": (10, 3600, 300),
    "cooldown_seconds": (0, 86400, 60),
}

#: Ceilings a connector may declare about itself, and the range each is checked
#: against. They belong to the connector's config rather than to the core: a
#: provider's hard limit is a fact about that provider's account, and the core
#: naming one provider to apply it to left the next provider with no way to say
#: its own (AUD-021). A declaration only ever lowers the account's window, never
#: raises it.
CAPS = {
    "requests_per_minute_ceiling": (1, 600),
    "certificate_requests_per_minute": (1, 60),
}

#: The certificate operation's ceiling when a connector declares none. The
#: operation itself is declared in readiness like every other bucket; this is
#: only the rate it is charged at.
DEFAULT_CERTIFICATE_REQUESTS_PER_MINUTE = 3
SCRIPT = """
local now = tonumber(ARGV[1])

-- The window is read from the key's own name (`:minute`, `:day`, `:job:<id>`),
-- never from its position. Positional selection made adding a window or
-- reordering the list a silent redefinition of an existing budget: a fourth
-- key pushed the day bucket out of slot 2 and the daily allowance became a
-- minute one, with no test and no log to say so.
local function window_of(key)
 if string.find(key, ':job:', 1, true) then
  return 86400000, 86401
 end
 local suffix = string.match(key, ':([%w%-]+)$')
 if suffix == 'day' then
  return 86400000, 86401
 end
 return 60000, 120
end

local day_index = nil
for i=1,#KEYS do
 if string.match(KEYS[i], ':day$') then day_index = i end
 local window = window_of(KEYS[i])
 redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now-window)
 local limit = tonumber(ARGV[i+1])
 if redis.call('ZCARD', KEYS[i]) >= limit then
  local first = redis.call('ZRANGE', KEYS[i], 0, 0, 'WITHSCORES')
  return {0, math.ceil((tonumber(first[2])+window-now)/1000)}
 end
end
for i=1,#KEYS do
 redis.call('ZADD', KEYS[i], now, ARGV[#KEYS+2])
 local _, ttl = window_of(KEYS[i])
 redis.call('EXPIRE', KEYS[i], ttl)
end
-- The remainder is the day bucket's headroom, and the bucket is found by name
-- for the same reason its window is: the answer must not depend on the order
-- the caller happened to build the key list in. A caller that passes no day
-- bucket gets 0, which the API reports as "no remainder measured".
if not day_index then
 return {1,0,0}
end
local used_today = redis.call('ZCARD', KEYS[day_index])
return {1,0, math.max(0, tonumber(ARGV[day_index+1]) - used_today)}
"""


def validate_policy(config: dict) -> None:
    ranges = {key: (low, high) for key, (low, high, _) in LIMITS.items()}
    ranges.update(CAPS)
    for key, (low, high) in ranges.items():
        value = config.get(key)
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not low <= value <= high
        ):
            raise ValueError(f"{key} must be an integer {low}..{high}")


async def reserve(
    db: AsyncSession, caller: Connector, bucket: str, *, job: Job
) -> dict:
    if not caller.provider or not caller.source_account_id:
        raise HTTPException(403, "Provider quota identity is not provisioned")
    if not caller.is_enabled:
        raise HTTPException(409, "Source disabled; stop provider requests")
    await require_enabled_module(db, caller.connector_type)
    now = datetime.now(timezone.utc)
    expiry = job.lease_expires_at
    if expiry and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    started = job.started_at
    if started and started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    if (
        job.status != JobStatus.running
        or job.connector_id != caller.id
        or not expiry
        or expiry <= now
    ):
        raise HTTPException(403, "Active owned job lease required")
    params = job.params if isinstance(job.params, dict) else {}
    try:
        queued_account_id = uuid.UUID(str(params.get("source_account_id") or ""))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(
            403, "Queued job has no valid provider account identity"
        ) from exc
    account = await db.get(SourceAccount, queued_account_id)
    if (
        account is None
        or account.source_id != caller.provider
        or (account.policy or {}).get("approved") is not True
    ):
        from app.core.audit import AuditLogger

        await AuditLogger.emit_background(
            db,
            action="source_account.quota_denied",
            ip_address=None,
            user_id=None,
            details={
                "connector_id": str(caller.id),
                "account_id": str(queued_account_id),
                "reason": "approval_revoked_or_missing",
            },
        )
        raise HTTPException(403, "Operator-approved account policy required")
    policy = params.get("config_snapshot", caller.config or {})
    validate_policy(policy)
    if not started or (now - started).total_seconds() >= policy.get(
        "scan_timeout_seconds", 300
    ):
        raise HTTPException(409, "Scan deadline exceeded")
    validate_policy(account.policy)
    # Account approval is a live kill switch, but approved quotas are frozen
    # into each queued job so edits affect future scans only.
    rpm = int(policy.get("requests_per_minute", 10))
    daily = int(policy.get("daily_budget", 100))
    # A ceiling the connector declares about its provider's API lowers the
    # account's window; it never raises it, because the account is the approval.
    ceiling = policy.get("requests_per_minute_ceiling")
    if ceiling is not None:
        rpm = min(rpm, int(ceiling))
    operations = set((caller.readiness or {}).get("operations") or [])
    if bucket not in operations:
        raise HTTPException(400, "Unsupported operation bucket")
    client = RateLimiter._get_client()
    if client is None:
        raise HTTPException(503, "Provider quota backend unavailable")
    prefix = f"provider-quota:account:{account.id}"
    # Check and charge every applicable window in the same atomic operation. The
    # suffix is the window's identity — the script reads it, so the order here is
    # presentation only and adding a window cannot redefine another one.
    keys = [prefix + ":minute", prefix + ":day"]
    limits = [rpm, daily]
    if bucket == "certificate":
        # The bucket's own rate is configuration too: a provider that allows only a
        # few certificate reads a minute declares that, and one that declares
        # nothing gets the documented default rather than an unbounded bucket.
        certificate_cap = policy.get(
            "certificate_requests_per_minute", DEFAULT_CERTIFICATE_REQUESTS_PER_MINUTE
        )
        keys.append(prefix + ":cert-minute")
        limits.append(min(rpm, int(certificate_cap)))
    keys.append(prefix + ":job:" + str(job.id))
    limits.append(policy.get("max_requests", 20))
    try:
        outcome = await cast(
            Awaitable[Any],
            client.eval(
                SCRIPT,
                len(keys),
                *keys,
                str(int(datetime.now(timezone.utc).timestamp() * 1000)),
                *(str(limit) for limit in limits),
                uuid.uuid4().hex,
            ),
        )
    except Exception as exc:
        raise HTTPException(503, "Provider quota backend unavailable") from exc
    if not int(outcome[0]):
        delay = outcome[1] if len(outcome) > 1 else 0
        raise HTTPException(
            429,
            "Provider request budget exhausted",
            headers={"Retry-After": str(max(1, int(delay)))},
        )
    # The script's third value is the account's remaining requests for the day. A Redis
    # that answered without it (an older script, a test double) is not a failure: the
    # caller reports the ceiling it already knows and says the remainder is unknown,
    # rather than computing a number nobody measured.
    try:
        remaining = max(0, int(outcome[2]))
    except (IndexError, TypeError, ValueError):
        remaining = None
    return {
        "reserved": True,
        "account": str(account.id),
        "billing_credits": "unknown",
        "request_budget": daily,
        "remaining_today": remaining,
    }


#: The day window in milliseconds, the same span the reservation script trims with.
_DAY_WINDOW_MS = 86400000


async def remaining_today(db: AsyncSession, caller: Connector) -> dict:
    """The day bucket's headroom for the account this connector is bound to.

    Derived from the counter ``reserve`` already charges, so the answer costs one
    read and no provider request: the headroom is a fact about the budget, not
    about the provider's own idea of what is left. Nothing is written and no
    audit row is produced — the health page asks this on every refresh, and an
    audit line per read would turn observability into volume.

    The budget is read the way ``reserve`` reads it: the account's approved policy
    layered over the connector's config. Reading the connector's config alone
    answered with a budget the reservation never enforces, so the page could print
    "none left" beside a scan that was still admitted (AUD-020).

    ``remaining_today`` is ``None`` when there is nothing to measure: a connector
    with no provider account, or a Redis that cannot answer. ``reason`` then says
    which, so a missing number is not mistaken for an exhausted budget.
    """
    if not caller.provider or not caller.source_account_id:
        return {
            "remaining_today": None,
            "request_budget": None,
            "reason": "provider_account_missing",
        }
    policy = dict(caller.config) if isinstance(caller.config, dict) else {}
    account = await db.get(SourceAccount, caller.source_account_id)
    if account is None and caller.provider:
        account = (
            await db.execute(
                select(SourceAccount).where(
                    SourceAccount.source_id == caller.provider,
                    SourceAccount.name == (caller.quota_group or "default"),
                )
            )
        ).scalar_one_or_none()
    if account is not None and isinstance(account.policy, dict):
        policy = {**policy, **account.policy}
    try:
        budget = int(policy.get("daily_budget", LIMITS["daily_budget"][2]))
    except (TypeError, ValueError):
        budget = LIMITS["daily_budget"][2]
    client = RateLimiter._get_client()
    if client is None:
        return {
            "remaining_today": None,
            "request_budget": budget,
            "reason": "quota_backend_unavailable",
        }
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    key = f"provider-quota:account:{caller.source_account_id}:day"
    try:
        used = int(await client.zcount(key, now_ms - _DAY_WINDOW_MS, now_ms))
    except Exception:
        return {
            "remaining_today": None,
            "request_budget": budget,
            "reason": "quota_backend_unavailable",
        }
    return {
        "remaining_today": max(0, budget - used),
        "request_budget": budget,
        "reason": None,
    }
