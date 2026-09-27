from __future__ import annotations

import os
import time
from datetime import timedelta

import structlog

from app.core.config import settings

log = structlog.get_logger()

_MAX_FAILS_DEFAULT = 5
_LOCK_WINDOW_SEC_DEFAULT = 15 * 60

try:
    from redis.asyncio import Redis as _Redis

    _HAS_REDIS = True
except Exception:  # pragma: no cover - redis is listed in requirements, fallback only
    _HAS_REDIS = False
    _Redis = None  # type: ignore


_RATE_LIMIT_PREFIX_LOCK = "rl:lock:"
_RATE_LIMIT_PREFIX_FAILS = "rl:fails:"


def _testing_mode() -> bool:
    return os.environ.get("TESTING") == "1" or os.environ.get("APP_ENV") == "test"


class RateLimiter:
    """
    Redis-backed login rate limiter with graceful degradation.

    Two keys per subject (email or IP):
      - rl:fails:<subject>   — INCR counter, TTL = lock_window_seconds
      - rl:lock:<subject>    — SET EX when fails >= max_fails
    """

    _CLIENT_CACHE: "_Redis | None" = None
    _CLIENT_TS: float = 0.0
    _CLIENT_TTL: float = 30.0

    def __init__(
        self,
        *,
        max_fails: int = _MAX_FAILS_DEFAULT,
        lock_window: timedelta = timedelta(seconds=_LOCK_WINDOW_SEC_DEFAULT),
    ) -> None:
        self.max_fails = max_fails
        self.lock_window_seconds = int(lock_window.total_seconds())

    @classmethod
    def reset_client_cache(cls) -> None:
        cls._CLIENT_CACHE = None
        cls._CLIENT_TS = 0.0

    @classmethod
    def _get_client(cls) -> "_Redis | None":
        if _testing_mode():
            return None
        if not _HAS_REDIS:
            return None
        now = time.monotonic()
        if cls._CLIENT_CACHE is not None and (now - cls._CLIENT_TS) < cls._CLIENT_TTL:
            return cls._CLIENT_CACHE
        try:
            url = settings.REDIS_URL
            client = _Redis.from_url(url, socket_timeout=1.2, socket_connect_timeout=1.0)
            cls._CLIENT_CACHE = client
            cls._CLIENT_TS = now
            return client
        except Exception as e:
            log.warning("rate_limit_redis_unavailable", err=str(e)[:200])
            cls._CLIENT_CACHE = None
            return None

    @classmethod
    def _reset_client(cls) -> None:
        cls._CLIENT_CACHE = None
        cls._CLIENT_TS = 0.0

    async def is_locked(self, subject: str) -> bool:
        client = self._get_client()
        if client is None:
            return False
        try:
            return bool(await client.exists(f"{_RATE_LIMIT_PREFIX_LOCK}{subject}"))
        except Exception as e:
            log.warning("rate_limit_redis_error", err=str(e)[:200])
            self._reset_client()
            return False

    async def incr_failure(self, subject: str) -> int:
        client = self._get_client()
        if client is None:
            return 0
        fails_key = f"{_RATE_LIMIT_PREFIX_FAILS}{subject}"
        lock_key = f"{_RATE_LIMIT_PREFIX_LOCK}{subject}"
        try:
            async with client.pipeline(transaction=True) as pipe:
                # Queue as statements (not chained): redis-py's Pipeline
                # methods return union types when untyped, and chaining adds
                # no semantic value over sequential command registration.
                pipe.incr(fails_key)
                pipe.expire(fails_key, self.lock_window_seconds)
                res = await pipe.execute()
            new_count = int(res[0])
            if new_count >= self.max_fails:
                try:
                    await client.setex(lock_key, self.lock_window_seconds, "1")
                except Exception as le:
                    log.warning("rate_limit_lock_set_error", err=str(le)[:200])
            return new_count
        except Exception as e:
            log.warning("rate_limit_redis_incr_error", err=str(e)[:200])
            self._reset_client()
            return 0

    async def reset(self, subject: str) -> None:
        client = self._get_client()
        if client is None:
            return
        try:
            async with client.pipeline(transaction=True) as pipe:
                pipe.delete(f"{_RATE_LIMIT_PREFIX_FAILS}{subject}")
                pipe.delete(f"{_RATE_LIMIT_PREFIX_LOCK}{subject}")
                await pipe.execute()
        except Exception as e:
            log.warning("rate_limit_redis_reset_error", err=str(e)[:200])
            self._reset_client()
