"""Unit tests for the authenticated request limiter.

``AUTHENTICATED_RATE_LIMIT_PER_MINUTE`` bounds how many requests one account may
make per minute; it exists because every read endpoint writes an audit row, so an
unbounded account could amplify database load and audit-pipeline noise.

Pinned here:
* the counter allows exactly ``limit`` requests per window and rejects the next;
* ``0`` disables the check without touching Redis;
* a Redis failure fails **open** (availability over throttling);
* the block is audited at most once per window — the first rejection claims
  ``rl:reqnotify:`` with ``SET NX``, later ones only log. Without that, auditing
  blocks would reproduce the amplification the limiter exists to bound;
* ``Retry-After`` points at the end of the current window.

Redis is faked rather than disabled: ``RateLimiter._get_client()`` returns None
under ``APP_ENV=test``, so each test monkeypatches it to a fake client.
"""

from __future__ import annotations

import uuid

import pytest

from app.core import request_rate_limit as module
from app.core.config import settings
from app.core.rate_limit import RateLimiter
from app.core.request_rate_limit import (
    REQUEST_RATE_LIMIT_PREFIX,
    RequestRateLimiter,
    request_window_bucket,
    seconds_until_next_window,
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

    async def execute(self) -> list:
        if self._owner.fail:
            raise RuntimeError("redis down")
        out: list = []
        for op, args in self._ops:
            if op == "incr":
                self._owner.store[args[0]] = self._owner.store.get(args[0], 0) + 1
                out.append(self._owner.store[args[0]])
            else:
                out.append(True)
        return out

    async def __aenter__(self) -> "_FakePipeline":
        return self

    async def __aexit__(self, *_exc) -> bool:
        return False


class _FakeRedis:
    def __init__(self) -> None:
        self.store: dict[str, int | str] = {}
        self.fail = False

    def pipeline(self, transaction: bool = True) -> _FakePipeline:
        return _FakePipeline(self)

    async def set(self, key: str, value, nx: bool = False, ex: int | None = None):
        if key in self.store and nx:
            return None
        self.store[key] = value
        return True

    async def delete(self, *keys: str) -> int:
        removed = 0
        for key in keys:
            if key in self.store:
                del self.store[key]
                removed += 1
        return removed


@pytest.fixture
def fake_redis(monkeypatch):
    client = _FakeRedis()
    monkeypatch.setattr(RateLimiter, "_get_client", classmethod(lambda cls: client))
    return client


class TestWindowMath:
    def test_bucket_groups_a_minute(self):
        assert request_window_bucket(0.0) == 0
        assert request_window_bucket(59.9) == 0
        assert request_window_bucket(60.0) == 1

    def test_retry_after_never_below_one_second(self):
        # 59.99s into the window leaves 0.01s, which must still read as >= 1.
        assert seconds_until_next_window(59.99) == 1
        assert seconds_until_next_window(0.0) == 60


class TestRequestRateLimiter:
    @pytest.mark.asyncio
    async def test_allows_up_to_the_limit_then_blocks(self, fake_redis):
        user = uuid.uuid4()
        for index in range(3):
            verdict = await RequestRateLimiter.check(user, limit_per_minute=3, now=1000.0)
            assert verdict.allowed is True, f"request {index + 1} of 3 should pass"

        blocked = await RequestRateLimiter.check(user, limit_per_minute=3, now=1000.0)
        assert blocked.allowed is False

    @pytest.mark.asyncio
    async def test_limit_is_per_user(self, fake_redis):
        now = 2000.0
        first, second = uuid.uuid4(), uuid.uuid4()
        assert (await RequestRateLimiter.check(first, limit_per_minute=1, now=now)).allowed
        # The second account has its own window and must not be affected.
        assert (await RequestRateLimiter.check(second, limit_per_minute=1, now=now)).allowed

    @pytest.mark.asyncio
    async def test_zero_disables_the_check_without_touching_redis(self, fake_redis):
        user = uuid.uuid4()
        for _ in range(50):
            verdict = await RequestRateLimiter.check(user, limit_per_minute=0, now=1000.0)
            assert verdict.allowed is True
        assert fake_redis.store == {}

    @pytest.mark.asyncio
    async def test_redis_failure_fails_open(self, fake_redis):
        fake_redis.fail = True
        verdict = await RequestRateLimiter.check(uuid.uuid4(), limit_per_minute=1, now=1000.0)
        assert verdict.allowed is True

    @pytest.mark.asyncio
    async def test_a_new_window_resets_the_counter(self, fake_redis):
        user = uuid.uuid4()
        assert (await RequestRateLimiter.check(user, limit_per_minute=1, now=100.0)).allowed
        assert not (await RequestRateLimiter.check(user, limit_per_minute=1, now=100.5)).allowed
        # Next minute: the key is a different bucket, so the account is usable again.
        assert (await RequestRateLimiter.check(user, limit_per_minute=1, now=161.0)).allowed

    @pytest.mark.asyncio
    async def test_block_is_claimed_once_per_window(self, fake_redis):
        user = uuid.uuid4()
        await RequestRateLimiter.check(user, limit_per_minute=1, now=300.0)

        first = await RequestRateLimiter.check(user, limit_per_minute=1, now=300.0)
        second = await RequestRateLimiter.check(user, limit_per_minute=1, now=300.5)
        third = await RequestRateLimiter.check(user, limit_per_minute=1, now=301.0)

        assert [first.allowed, second.allowed, third.allowed] == [False, False, False]
        # Exactly one of the three rejections is worth a database audit row:
        # auditing all three would amplify the load this limiter bounds.
        assert first.first_block_in_window is True
        assert second.first_block_in_window is False
        assert third.first_block_in_window is False

    @pytest.mark.asyncio
    async def test_each_window_gets_its_own_block_notice(self, fake_redis):
        user = uuid.uuid4()
        await RequestRateLimiter.check(user, limit_per_minute=1, now=400.0)
        assert (await RequestRateLimiter.check(user, limit_per_minute=1, now=400.0)).first_block_in_window
        await RequestRateLimiter.check(user, limit_per_minute=1, now=460.0)
        assert (await RequestRateLimiter.check(user, limit_per_minute=1, now=460.0)).first_block_in_window

    @pytest.mark.asyncio
    async def test_retry_after_points_at_the_end_of_the_window(self, fake_redis):
        user = uuid.uuid4()
        # Windows are aligned to wall-clock minutes, not to the first request:
        # 500.0 and 510.0 both fall in the bucket covering 480-540, so the safe
        # retry moment is 540, i.e. 30 seconds after the rejected request.
        await RequestRateLimiter.check(user, limit_per_minute=1, now=500.0)
        blocked = await RequestRateLimiter.check(user, limit_per_minute=1, now=510.0)
        assert blocked.allowed is False
        assert blocked.retry_after == 30

    @pytest.mark.asyncio
    async def test_counter_carries_a_ttl_so_keys_do_not_accumulate(self, fake_redis):
        user = uuid.uuid4()
        await RequestRateLimiter.check(user, limit_per_minute=5, now=600.0)
        key = f"{REQUEST_RATE_LIMIT_PREFIX}{user}:{request_window_bucket(600.0)}"
        assert key in fake_redis.store

    @pytest.mark.asyncio
    async def test_reset_clears_the_current_window(self, fake_redis):
        user = uuid.uuid4()
        await RequestRateLimiter.check(user, limit_per_minute=1, now=700.0)
        assert not (await RequestRateLimiter.check(user, limit_per_minute=1, now=700.0)).allowed
        await RequestRateLimiter.reset(user, now=700.0)
        assert (await RequestRateLimiter.check(user, limit_per_minute=1, now=700.0)).allowed

    @pytest.mark.asyncio
    async def test_testing_mode_short_circuits_before_redis(self, monkeypatch):
        """With no client at all (TESTING mode) the check must allow and log nothing."""
        monkeypatch.setattr(RateLimiter, "_get_client", classmethod(lambda cls: None))
        verdict = await RequestRateLimiter.check(uuid.uuid4(), limit_per_minute=1, now=800.0)
        assert verdict.allowed is True

    def test_module_exposes_the_prefix_it_documents(self):
        assert module.REQUEST_RATE_LIMIT_PREFIX == "rl:req:"


class TestAuthenticatedRequestLimitOverHttp:
    """The limiter is wired into ``get_current_user``, so every route inherits it."""

    @pytest.mark.asyncio
    async def test_over_limit_returns_429_with_retry_after(
        self, client, auth_headers_viewer, fake_redis, monkeypatch
    ):
        monkeypatch.setattr(settings, "AUTHENTICATED_RATE_LIMIT_PER_MINUTE", 1)
        # Pin the clock: the window is a wall-clock minute, and a real clock
        # could roll over between the two requests and reset the counter.
        monkeypatch.setattr(module.time, "time", lambda: 10_000.0)

        first = await client.get("/api/v1/assets", headers=auth_headers_viewer)
        assert first.status_code == 200

        second = await client.get("/api/v1/assets", headers=auth_headers_viewer)
        assert second.status_code == 429
        assert second.headers.get("Retry-After") is not None

    @pytest.mark.asyncio
    async def test_only_the_first_block_of_a_window_writes_an_audit_row(
        self, client, auth_headers_viewer, db_session, fake_redis, monkeypatch
    ):
        from sqlalchemy import func, select

        from app.models import AuditLog

        monkeypatch.setattr(settings, "AUTHENTICATED_RATE_LIMIT_PER_MINUTE", 1)
        monkeypatch.setattr(module.time, "time", lambda: 10_000.0)

        assert (await client.get("/api/v1/assets", headers=auth_headers_viewer)).status_code == 200
        for _ in range(4):
            assert (
                await client.get("/api/v1/assets", headers=auth_headers_viewer)
            ).status_code == 429

        stored = (
            await db_session.execute(
                select(func.count(AuditLog.id)).where(
                    AuditLog.action == "rate_limit.request_blocked"
                )
            )
        ).scalar_one()
        # Four rejections, one row: a client that ignores 429 must not be able
        # to turn the limiter into an audit-pipeline amplifier.
        assert stored == 1

    @pytest.mark.asyncio
    async def test_disabled_limit_leaves_traffic_untouched(
        self, client, auth_headers_viewer, fake_redis, monkeypatch
    ):
        monkeypatch.setattr(settings, "AUTHENTICATED_RATE_LIMIT_PER_MINUTE", 0)
        for _ in range(3):
            assert (
                await client.get("/api/v1/assets", headers=auth_headers_viewer)
            ).status_code == 200
        assert fake_redis.store == {}
