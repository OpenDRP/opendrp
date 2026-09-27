"""Per-user throttle for authenticated request volume.

Why this exists
---------------
Login was bounded (``app.core.rate_limit``) and manual actions were bounded
(``app.core.manual_rate_limit``), but nothing bounded how many requests one
*authenticated* account could make. Every read endpoint writes an audit row and
commits it, so a single credential — or one runaway client — could amplify load
on the database and flood the audit pipeline that the same account is supposed
to be described by. This is the missing bound.

What it bounds
--------------
Requests, not bytes and not concurrency: a fixed-window counter per user in
Redis (``rl:req:<user_id>:<window>``), where the window is a wall-clock minute.
Fixed windows need no reset job and are a single atomic ``INCR``+``EXPIRE``
pipeline, which is why the counter is able to protect the database rather than
add to its load.

Auditing a block without amplifying it
--------------------------------------
The block is recorded in the audit trail, but only for the **first** rejection
of each window (``rl:reqnotify:<user_id>:<window>``, ``SET NX EX``). Auditing
every rejected request would reproduce exactly the amplification this module
exists to prevent: a client that ignores ``429`` would keep writing audit rows
at full request rate. Later rejections in the same window are logged to stdout
instead — same event, no database write.

Failure mode is **fail-open**, matching the other two limiters: if Redis is
unavailable the request proceeds and a warning is logged. Losing the throttle
during an outage is preferable to locking every operator out of the platform,
and the deployment still has nginx-level limits in front of it.

``AUTHENTICATED_RATE_LIMIT_PER_MINUTE=0`` disables the check entirely.
"""

from __future__ import annotations

import time
import uuid

import structlog

from app.core.rate_limit import RateLimiter

log = structlog.get_logger()

REQUEST_RATE_LIMIT_PREFIX = "rl:req:"
_BLOCK_NOTICE_PREFIX = "rl:reqnotify:"
_WINDOW_SECONDS = 60


def request_window_bucket(now: float | None = None) -> int:
    """Index of the current fixed window. Takes ``now`` so tests can pin edges."""
    return int(now if now is not None else time.time()) // _WINDOW_SECONDS


def seconds_until_next_window(now: float) -> int:
    """Seconds left in the window containing ``now``, never below 1."""
    return max(1, _WINDOW_SECONDS - int(now) % _WINDOW_SECONDS)


class RequestRateLimitVerdict:
    """Outcome of one check.

    ``retry_after`` lets the caller send an accurate ``Retry-After`` header.
    ``first_block_in_window`` is True only for the first rejection of a window —
    the one block worth a database audit row.
    """

    __slots__ = ("allowed", "first_block_in_window", "retry_after")

    def __init__(
        self,
        *,
        allowed: bool,
        retry_after: int | None = None,
        first_block_in_window: bool = False,
    ) -> None:
        self.allowed = allowed
        self.retry_after = retry_after
        self.first_block_in_window = first_block_in_window


class RequestRateLimiter:
    @staticmethod
    async def check(
        user_id: uuid.UUID | str,
        *,
        limit_per_minute: int,
        now: float | None = None,
    ) -> RequestRateLimitVerdict:
        """Count one request and decide whether it is allowed."""
        limit = int(limit_per_minute or 0)
        if limit <= 0:
            # Disabled by configuration: never touch Redis, never add latency.
            return RequestRateLimitVerdict(allowed=True)
        client = RateLimiter._get_client()
        if client is None:
            # TESTING mode, or Redis is unavailable: fail open.
            return RequestRateLimitVerdict(allowed=True)

        moment = now if now is not None else time.time()
        bucket = int(moment) // _WINDOW_SECONDS
        key = f"{REQUEST_RATE_LIMIT_PREFIX}{user_id}:{bucket}"
        try:
            async with client.pipeline(transaction=True) as pipe:
                # Registered as statements rather than chained; see the note in
                # app.core.rate_limit on redis-py's union-typed chaining.
                pipe.incr(key)
                pipe.expire(key, _WINDOW_SECONDS * 2)
                result = await pipe.execute()
            count = int(result[0])
        except Exception as e:
            log.warning("request_rate_limit_redis_error", err=str(e)[:200])
            RateLimiter._reset_client()
            return RequestRateLimitVerdict(allowed=True)

        if count <= limit:
            return RequestRateLimitVerdict(allowed=True)

        return RequestRateLimitVerdict(
            allowed=False,
            retry_after=seconds_until_next_window(moment),
            first_block_in_window=await RequestRateLimiter._claim_block_notice(user_id, bucket),
        )

    @staticmethod
    async def _claim_block_notice(user_id: uuid.UUID | str, bucket: int) -> bool:
        """True only for the first rejection inside ``bucket``."""
        client = RateLimiter._get_client()
        if client is None:
            return False
        key = f"{_BLOCK_NOTICE_PREFIX}{user_id}:{bucket}"
        try:
            claimed = await client.set(key, "1", nx=True, ex=_WINDOW_SECONDS * 2)
        except Exception as e:
            log.warning("request_rate_limit_notice_error", err=str(e)[:200])
            return False
        return bool(claimed)

    @staticmethod
    async def reset(user_id: uuid.UUID | str, *, now: float | None = None) -> None:
        """Drop a user's current window — used by tests and support."""
        client = RateLimiter._get_client()
        if client is None:
            return
        bucket = request_window_bucket(now)
        try:
            await client.delete(
                f"{REQUEST_RATE_LIMIT_PREFIX}{user_id}:{bucket}",
                f"{_BLOCK_NOTICE_PREFIX}{user_id}:{bucket}",
            )
        except Exception as e:  # pragma: no cover - depends on Redis health
            log.warning("request_rate_limit_reset_error", err=str(e)[:200])


__all__ = [
    "REQUEST_RATE_LIMIT_PREFIX",
    "RequestRateLimitVerdict",
    "RequestRateLimiter",
    "request_window_bucket",
    "seconds_until_next_window",
]
