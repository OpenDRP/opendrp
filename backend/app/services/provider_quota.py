"""Account-scoped, atomic request budgets shared across module workers."""

from datetime import datetime, timezone
import uuid
from typing import Any, Awaitable, cast

from fastapi import HTTPException
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
SCRIPT = """
local now = tonumber(ARGV[1])
for i=1,#KEYS do
 local window = (i == 2 or string.find(KEYS[i], ':job:')) and 86400000 or 60000
 redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now-window)
 local limit = tonumber(ARGV[i+1])
 if redis.call('ZCARD', KEYS[i]) >= limit then
  local first = redis.call('ZRANGE', KEYS[i], 0, 0, 'WITHSCORES')
  return {0, math.ceil((tonumber(first[2])+window-now)/1000)}
 end
end
for i=1,#KEYS do
 redis.call('ZADD', KEYS[i], now, ARGV[#KEYS+2])
 redis.call('EXPIRE', KEYS[i], (i == 2 or string.find(KEYS[i], ':job:')) and 86401 or 120)
end
return {1,0}
"""


def validate_policy(config: dict) -> None:
    for key, (low, high, _) in LIMITS.items():
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
    if caller.provider == "netlas":
        rpm = min(rpm, 60)
    operations = set((caller.readiness or {}).get("operations") or [])
    if bucket not in operations:
        raise HTTPException(400, "Unsupported operation bucket")
    if bucket == "certificate" and caller.provider != "netlas":
        raise HTTPException(400, "Unsupported provider operation bucket")
    if bucket == "certificate" and caller.provider == "netlas" and "certificate" not in operations:
        raise HTTPException(400, "Unsupported provider operation bucket")
    client = RateLimiter._get_client()
    if client is None:
        raise HTTPException(503, "Provider quota backend unavailable")
    prefix = f"provider-quota:account:{account.id}"
    # Check and charge every applicable window in the same atomic operation.
    keys = [prefix + ":minute", prefix + ":day"]
    limits = [rpm, daily]
    if bucket == "certificate" and caller.provider == "netlas":
        keys.append(prefix + ":cert-minute")
        limits.append(min(rpm, 3))
    keys.append(prefix + ":job:" + str(job.id))
    limits.append(policy.get("max_requests", 20))
    try:
        allowed, delay = await cast(
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
    if not int(allowed):
        raise HTTPException(
            429,
            "Provider request budget exhausted",
            headers={"Retry-After": str(max(1, int(delay)))},
        )
    return {
        "reserved": True,
        "account": str(account.id),
        "billing_credits": "unknown",
        "request_budget": daily,
    }
