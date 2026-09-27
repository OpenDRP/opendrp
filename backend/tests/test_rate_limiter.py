"""Characterization tests: core rate limiter (Step 9).

Pins the CURRENT behavior of ``app.core.rate_limit.RateLimiter`` — the
Redis-backed login lockout primitive used by the auth router:

* TESTING mode (``_testing_mode()``) forces ``_get_client()`` to ``None`` —
  every method degrades to a no-op (locked=False, count=0, reset silent);
* the 30s class-level client cache: fresh cache reuses the client without
  reconnecting; a stale cache reconnects via ``Redis.from_url``; a
  ``from_url`` failure logs, returns None and keeps the cache empty;
* ``is_locked`` — True only when the ``rl:lock:<subject>`` key exists;
  Redis errors return False and reset the cached client;
* ``incr_failure`` — INCR+EXPIRE pipeline; reaching ``max_fails`` sets the
  lock key with ``SET EX`` = lock window; a failing ``SETEX`` still returns
  the count; a Redis failure returns 0 and resets the client;
* ``reset`` — deletes both ``rl:fails:`` and ``rl:lock:`` keys; Redis
  failures are swallowed and the client is reset;
* constructor: custom ``max_fails`` and ``lock_window`` are honored
  (defaults 5 fails / 900s).
"""

from __future__ import annotations

import time
from datetime import timedelta

import pytest

from app.core.rate_limit import (
    _RATE_LIMIT_PREFIX_FAILS,
    _RATE_LIMIT_PREFIX_LOCK,
    RateLimiter,
)


class _FakePipeline:
    def __init__(self, owner: "_FakeRedis") -> None:
        self._owner = owner
        self._ops: list[tuple[str, tuple]] = []

    def incr(self, key: str) -> "_FakePipeline":
        self._ops.append(("incr", (key,)))
        return self

    def expire(self, key: str, ttl: int) -> "_FakePipeline":
        self._ops.append(("expire", (key, ttl)))
        return self

    def delete(self, *keys: str) -> "_FakePipeline":
        self._ops.append(("delete", keys))
        return self

    async def execute(self) -> list:
        out: list = []
        for op, args in self._ops:
            if op == "incr":
                self._owner.store[args[0]] = self._owner.store.get(args[0], 0) + 1
                out.append(self._owner.store[args[0]])
            elif op == "expire":
                if self._owner.fail_execute:
                    raise RuntimeError("redis pipeline exploded")
                out.append(True)
            elif op == "delete":
                if self._owner.fail_execute:
                    raise RuntimeError("redis pipeline exploded")
                n = 0
                for k in args:
                    if k in self._owner.store:
                        del self._owner.store[k]
                        n += 1
                    if k in self._owner.locks:
                        del self._owner.locks[k]
                        n += 1
                out.append(n)
        return out


class _PipelineCtx:
    def __init__(self, pipe: _FakePipeline) -> None:
        self._pipe = pipe

    async def __aenter__(self) -> _FakePipeline:
        return self._pipe

    async def __aexit__(self, *exc) -> bool:
        return False


class _FakeRedis:
    """Minimal async-redis stand-in for the limiter contract."""

    def __init__(self) -> None:
        self.store: dict[str, int] = {}
        self.locks: dict[str, str] = {}
        self.setex_calls: list[tuple[str, int, str]] = []
        self.exists_calls: list[str] = []
        self.fail_execute = False
        self.fail_exists = False

    def pipeline(self, transaction: bool = True) -> _PipelineCtx:
        return _PipelineCtx(_FakePipeline(self))

    async def exists(self, key: str) -> int:
        self.exists_calls.append(key)
        if self.fail_exists:
            raise RuntimeError("redis exists exploded")
        return 1 if key in self.locks else 0

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.setex_calls.append((key, ttl, value))
        self.locks[key] = value


def _activate_fake(monkeypatch: pytest.MonkeyPatch, fake: _FakeRedis) -> None:
    """Force the non-testing path with a fresh, pre-seeded client cache."""
    monkeypatch.setattr("app.core.rate_limit._testing_mode", lambda: False)
    monkeypatch.setattr(RateLimiter, "_CLIENT_CACHE", fake)
    monkeypatch.setattr(RateLimiter, "_CLIENT_TS", time.monotonic())


class TestTestingModeNoOps:
    @pytest.mark.asyncio
    async def test_all_methods_noop_in_testing_mode(self):
        # conftest sets TESTING=1; the limiter must fully degrade.
        rl = RateLimiter()
        assert await rl.is_locked("a@b.example") is False
        assert await rl.incr_failure("a@b.example") == 0
        await rl.reset("a@b.example")  # must not raise
        assert RateLimiter._get_client() is None

    def test_testing_mode_detection(self, monkeypatch):
        from app.core.rate_limit import _testing_mode

        monkeypatch.setenv("TESTING", "1")
        assert _testing_mode() is True
        monkeypatch.delenv("TESTING", raising=False)
        monkeypatch.delenv("APP_ENV", raising=False)
        assert _testing_mode() is False
        monkeypatch.setenv("APP_ENV", "test")
        assert _testing_mode() is True


class TestClientCache:
    def test_fresh_cache_reuses_client_without_reconnect(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        fake = _FakeRedis()
        _activate_fake(monkeypatch, fake)

        def _must_not_connect(*a, **kw):
            raise AssertionError("from_url must not be called within TTL")

        monkeypatch.setattr("app.core.rate_limit._Redis.from_url", _must_not_connect)

        assert RateLimiter._get_client() is fake
        assert RateLimiter._get_client() is fake  # cached, same instance

    def test_stale_cache_reconnects(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        fake = _FakeRedis()
        replacement = _FakeRedis()
        monkeypatch.setattr("app.core.rate_limit._testing_mode", lambda: False)
        monkeypatch.setattr(RateLimiter, "_CLIENT_CACHE", fake)
        monkeypatch.setattr(RateLimiter, "_CLIENT_TS", time.monotonic() - 100.0)

        seen: list = []

        def _from_url(url, **kw):
            seen.append(url)
            return replacement

        monkeypatch.setattr("app.core.rate_limit._Redis.from_url", _from_url)

        client = RateLimiter._get_client()
        assert client is replacement
        assert len(seen) == 1
        # The new client is now cached (within TTL).
        assert RateLimiter._get_client() is replacement

    def test_from_url_failure_returns_none_and_keeps_cache_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr("app.core.rate_limit._testing_mode", lambda: False)
        monkeypatch.setattr(RateLimiter, "_CLIENT_CACHE", None)
        monkeypatch.setattr(RateLimiter, "_CLIENT_TS", 0.0)

        def _boom(*a, **kw):
            raise RuntimeError("redis down")

        monkeypatch.setattr("app.core.rate_limit._Redis.from_url", _boom)
        assert RateLimiter._get_client() is None
        assert RateLimiter._CLIENT_CACHE is None

    def test_no_redis_lib_returns_none(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr("app.core.rate_limit._testing_mode", lambda: False)
        monkeypatch.setattr("app.core.rate_limit._HAS_REDIS", False)
        assert RateLimiter._get_client() is None


class TestIsLocked:
    @pytest.mark.asyncio
    async def test_true_only_when_lock_key_exists(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        fake = _FakeRedis()
        _activate_fake(monkeypatch, fake)
        rl = RateLimiter()

        assert await rl.is_locked("user@example.com") is False
        assert fake.exists_calls == [f"{_RATE_LIMIT_PREFIX_LOCK}user@example.com"]

        fake.locks[f"{_RATE_LIMIT_PREFIX_LOCK}user@example.com"] = "1"
        assert await rl.is_locked("user@example.com") is True

    @pytest.mark.asyncio
    async def test_redis_error_returns_false_and_resets_client(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        fake = _FakeRedis()
        fake.fail_exists = True
        _activate_fake(monkeypatch, fake)
        rl = RateLimiter()

        assert await rl.is_locked("user@example.com") is False
        assert RateLimiter._CLIENT_CACHE is None  # client was reset


class TestIncrFailure:
    @pytest.mark.asyncio
    async def test_counts_up_and_locks_at_threshold(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        fake = _FakeRedis()
        _activate_fake(monkeypatch, fake)
        rl = RateLimiter(max_fails=3, lock_window=timedelta(seconds=90))

        assert await rl.incr_failure("user@example.com") == 1
        assert await rl.incr_failure("user@example.com") == 2
        assert fake.setex_calls == []  # below threshold: no lock yet

        assert await rl.incr_failure("user@example.com") == 3
        assert len(fake.setex_calls) == 1
        key, ttl, value = fake.setex_calls[0]
        assert key == f"{_RATE_LIMIT_PREFIX_LOCK}user@example.com"
        assert ttl == 90  # lock_window honored, not the default 900
        assert value == "1"

    @pytest.mark.asyncio
    async def test_counts_past_threshold_relock_on_every_increment(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        fake = _FakeRedis()
        _activate_fake(monkeypatch, fake)
        rl = RateLimiter(max_fails=2)
        await rl.incr_failure("u@example.com")
        assert fake.setex_calls == []  # below threshold
        await rl.incr_failure("u@example.com")
        await rl.incr_failure("u@example.com")
        assert await rl.incr_failure("u@example.com") == 4
        # Pin current semantics: SETEX fires on EVERY increment at-or-past
        # the threshold (effectively refreshing the lock TTL on continued
        # failures), not only on the first crossing.
        assert len(fake.setex_calls) == 3

    @pytest.mark.asyncio
    async def test_lock_set_error_still_returns_count(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        fake = _FakeRedis()

        async def _setex_boom(key, ttl, value):
            raise RuntimeError("setex exploded")

        fake.setex = _setex_boom  # type: ignore[method-assign]
        _activate_fake(monkeypatch, fake)
        rl = RateLimiter(max_fails=1)

        # The INCR result is returned even when setting the lock fails.
        assert await rl.incr_failure("u@example.com") == 1
        # Client stays usable (the pipeline phase did not fail).
        assert RateLimiter._CLIENT_CACHE is fake

    @pytest.mark.asyncio
    async def test_redis_error_returns_zero_and_resets_client(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        fake = _FakeRedis()
        fake.fail_execute = True
        _activate_fake(monkeypatch, fake)
        rl = RateLimiter()

        assert await rl.incr_failure("u@example.com") == 0
        assert RateLimiter._CLIENT_CACHE is None


class TestReset:
    @pytest.mark.asyncio
    async def test_deletes_fails_and_lock_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        fake = _FakeRedis()
        _activate_fake(monkeypatch, fake)
        rl = RateLimiter()

        fk = f"{_RATE_LIMIT_PREFIX_FAILS}u@example.com"
        lk = f"{_RATE_LIMIT_PREFIX_LOCK}u@example.com"
        fake.store[fk] = 2
        fake.locks[lk] = "1"

        await rl.reset("u@example.com")
        assert fk not in fake.store
        assert lk not in fake.locks

    @pytest.mark.asyncio
    async def test_redis_error_swallows_and_resets_client(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        fake = _FakeRedis()
        fake.fail_execute = True
        _activate_fake(monkeypatch, fake)
        rl = RateLimiter()

        await rl.reset("u@example.com")  # must not raise
        assert RateLimiter._CLIENT_CACHE is None


class TestConstructorDefaults:
    def test_defaults_are_5_fails_15_minutes(self):
        rl = RateLimiter()
        assert rl.max_fails == 5
        assert rl.lock_window_seconds == 15 * 60

    def test_custom_values(self):
        rl = RateLimiter(max_fails=10, lock_window=timedelta(minutes=1))
        assert rl.max_fails == 10
        assert rl.lock_window_seconds == 60
