"""The alert health probe cache: one answer per TTL, never a new failure mode.

These tests run against an in-memory stand-in for Redis. The endpoint's own
contributions — `checked_at`, `from_cache`, `probe_state` — are asserted in
``test_alert_channel_probes.py``; this file is about the cache's rules:

* an answer is reused inside the TTL and re-probed after it;
* the key carries the settings fingerprint, so a changed host or token is a new
  question rather than a stale answer;
* concurrent callers share one probe instead of stampeding SMTP;
* a missing or broken cache falls back to probing, and still reports the truth.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.services import alert_health_cache as cache


class _FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.expires: dict[str, float] = {}
        self.now = 0.0
        self.sets: list[tuple[str, int | None]] = []

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return None
        self.values[key] = value
        if ex is not None:
            self.expires[key] = self.now + float(ex)
        self.sets.append((key, ex))
        return True

    async def get(self, key):
        deadline = self.expires.get(key)
        if deadline is not None and deadline <= self.now:
            self.values.pop(key, None)
            self.expires.pop(key, None)
            return None
        return self.values.get(key)

    async def delete(self, key):
        self.values.pop(key, None)
        self.expires.pop(key, None)
        return 1


class _BrokenRedis:
    async def set(self, *_args, **_kwargs):
        raise ConnectionError("redis is down")

    async def get(self, *_args, **_kwargs):
        raise ConnectionError("redis is down")

    async def delete(self, *_args, **_kwargs):
        raise ConnectionError("redis is down")


def _probe(**overrides) -> SimpleNamespace:
    base = {
        "health": "healthy",
        "message": "SMTP connection is available",
        "latency_ms": 12,
        "blocked_reason": None,
        "probe_state": "ok",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


async def _call(*, fingerprint: str = "fp", ttl: int = 60, probe, budget: float = 1.0):
    return await cache.probe_with_cache(
        channel="email",
        fingerprint=fingerprint,
        ttl_seconds=ttl,
        wait_budget_seconds=budget,
        probe=probe,
    )


@pytest.mark.asyncio
async def test_a_second_call_within_the_ttl_reuses_the_answer(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(cache, "_client", lambda: fake)
    calls: list[str] = []

    async def probe():
        calls.append("probe")
        return _probe()

    first = await _call(probe=probe)
    second = await _call(probe=probe)

    assert calls == ["probe"]
    assert first.from_cache is False
    assert second.from_cache is True
    assert second.checked_at == first.checked_at
    assert second.health == first.health


@pytest.mark.asyncio
async def test_a_changed_fingerprint_is_a_new_question(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(cache, "_client", lambda: fake)
    calls: list[str] = []

    async def probe():
        calls.append("probe")
        return _probe()

    await _call(fingerprint="host-a", probe=probe)
    second = await _call(fingerprint="host-b", probe=probe)

    assert calls == ["probe", "probe"]
    assert second.from_cache is False


@pytest.mark.asyncio
async def test_an_expired_answer_is_probed_again(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(cache, "_client", lambda: fake)
    calls: list[str] = []

    async def probe():
        calls.append("probe")
        return _probe()

    await _call(ttl=30, probe=probe)
    fake.now = 31.0
    second = await _call(ttl=30, probe=probe)

    assert calls == ["probe", "probe"]
    assert second.from_cache is False


@pytest.mark.asyncio
async def test_zero_ttl_disables_the_cache(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(cache, "_client", lambda: fake)
    calls: list[str] = []

    async def probe():
        calls.append("probe")
        return _probe()

    await _call(ttl=0, probe=probe)
    await _call(ttl=0, probe=probe)

    assert calls == ["probe", "probe"]
    assert fake.sets == []


@pytest.mark.asyncio
async def test_an_unavailable_cache_still_answers(monkeypatch):
    """No Redis is not an outage of the health page."""
    monkeypatch.setattr(cache, "_client", lambda: None)
    calls: list[str] = []

    async def probe():
        calls.append("probe")
        return _probe()

    first = await _call(probe=probe)
    second = await _call(probe=probe)

    assert calls == ["probe", "probe"]
    assert (first.from_cache, second.from_cache) == (False, False)
    assert first.checked_at and second.checked_at


@pytest.mark.asyncio
async def test_a_broken_cache_still_answers(monkeypatch):
    monkeypatch.setattr(cache, "_client", lambda: _BrokenRedis())
    calls: list[str] = []

    async def probe():
        calls.append("probe")
        return _probe()

    first = await _call(probe=probe)
    second = await _call(probe=probe)

    assert calls == ["probe", "probe"]
    assert (first.from_cache, second.from_cache) == (False, False)


@pytest.mark.asyncio
async def test_an_unreadable_entry_is_treated_as_absent(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(cache, "_client", lambda: fake)
    calls: list[str] = []

    async def probe():
        calls.append("probe")
        return _probe()

    first = await _call(probe=probe)
    key = next(iter(fake.values))
    fake.values[key] = "{not json"
    second = await _call(probe=probe)

    assert calls == ["probe", "probe"]
    assert second.from_cache is False
    assert first.checked_at


@pytest.mark.asyncio
async def test_concurrent_callers_share_one_probe(monkeypatch):
    """The first burst after the TTL is one handshake, not one per caller."""
    fake = _FakeRedis()
    monkeypatch.setattr(cache, "_client", lambda: fake)
    calls: list[str] = []
    started = asyncio.Event()
    release = asyncio.Event()

    async def probe():
        calls.append("probe")
        started.set()
        await release.wait()
        return _probe()

    first = asyncio.create_task(_call(probe=probe, budget=2.0))
    await started.wait()
    second = asyncio.create_task(_call(probe=probe, budget=2.0))
    await asyncio.sleep(0.1)
    release.set()
    outcomes = await asyncio.gather(first, second)

    assert calls == ["probe"]
    assert sorted(outcome.from_cache for outcome in outcomes) == [False, True]
    assert outcomes[0].checked_at == outcomes[1].checked_at


@pytest.mark.asyncio
async def test_a_saturated_probe_keeps_its_marker_when_replayed(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(cache, "_client", lambda: fake)

    async def probe():
        return _probe(health="unknown", message="SMTP health check is busy", probe_state="saturated")

    await _call(probe=probe)
    cached = await _call(probe=probe)

    assert cached.from_cache is True
    assert cached.health == "unknown"
    assert cached.probe_state == "saturated"


class _RedisType:
    """Stands in for ``redis.asyncio.Redis`` in the process-client tests."""

    urls: list[str] = []
    failure: Exception | None = None

    @classmethod
    def from_url(cls, url, **_kwargs):
        cls.urls.append(url)
        if cls.failure is not None:
            raise cls.failure
        return SimpleNamespace(url=url)


def test_the_process_client_is_built_once_and_reused_inside_its_ttl(monkeypatch):
    _RedisType.urls = []
    _RedisType.failure = None
    monkeypatch.setattr(cache, "_testing_mode", lambda: False)
    monkeypatch.setattr(cache, "_redis_type", lambda: _RedisType)
    monkeypatch.setattr(cache, "_CLIENT", None)
    monkeypatch.setattr(cache, "_CLIENT_TS", 0.0)

    first = cache._client()
    second = cache._client()

    assert first is not None
    assert second is first
    assert _RedisType.urls == [settings.REDIS_URL]

    # Past the TTL the client is built again rather than reused forever.
    monkeypatch.setattr(cache, "_CLIENT_TS", time.monotonic() - cache._CLIENT_TTL_SECONDS - 1)
    third = cache._client()

    assert third is not first
    assert len(_RedisType.urls) == 2


def test_a_client_that_cannot_be_built_degrades_to_probing(monkeypatch):
    _RedisType.urls = []
    _RedisType.failure = ConnectionError("redis is unreachable")
    monkeypatch.setattr(cache, "_testing_mode", lambda: False)
    monkeypatch.setattr(cache, "_redis_type", lambda: _RedisType)
    monkeypatch.setattr(cache, "_CLIENT", None)

    assert cache._client() is None
    assert cache._CLIENT is None
    _RedisType.failure = None


def test_a_runtime_without_redis_answers_without_a_client(monkeypatch):
    monkeypatch.setattr(cache, "_testing_mode", lambda: False)
    monkeypatch.setattr(cache, "_redis_type", lambda: None)

    assert cache._client() is None


def test_reset_client_cache_forgets_the_process_client():
    cache._CLIENT = object()
    cache._CLIENT_TS = 123.0

    cache.reset_client_cache()

    assert cache._CLIENT is None
    assert cache._CLIENT_TS == 0.0


async def test_a_failed_write_is_logged_rather_than_raised():
    outcome = cache.ProbeOutcome(
        health="healthy",
        message="ok",
        latency_ms=1,
        blocked_reason=None,
        probe_state="ok",
        checked_at=cache._now(),
    )

    # The broken client raises on every call; the cache must not turn that into a
    # failed health page.
    await cache._write(_BrokenRedis(), "key", outcome, 60)
    await cache._release(_BrokenRedis(), "lock")


def test_the_process_client_is_disabled_under_the_test_runner():
    # This is the branch every other test relies on: no Redis in the test runner.
    assert cache._client() is None
