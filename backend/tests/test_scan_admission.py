from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.services import scan_admission


class FakeRedis:
    def __init__(self, claimed: bool = True):
        self.claimed = claimed
        self.set = AsyncMock(return_value=claimed)
        self.eval = AsyncMock(return_value=1)


@pytest.mark.asyncio
async def test_testing_mode_bypasses_redis(monkeypatch):
    client = FakeRedis()
    monkeypatch.setattr(scan_admission.RateLimiter, "_get_client", classmethod(lambda cls: client))
    monkeypatch.setenv("TESTING", "1")

    assert await scan_admission.acquire("shodan", ttl_seconds=1) is None
    await scan_admission.release("shodan", "ignored")
    client.set.assert_not_awaited()
    client.eval.assert_not_awaited()


@pytest.mark.asyncio
async def test_acquire_resets_client_when_redis_set_fails(monkeypatch):
    client = FakeRedis()
    client.set.side_effect = RuntimeError("redis down")
    reset = AsyncMock()
    monkeypatch.setattr(scan_admission.RateLimiter, "_get_client", classmethod(lambda cls: client))
    monkeypatch.setattr(scan_admission.RateLimiter, "_reset_client", reset)
    monkeypatch.delenv("TESTING", raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)

    with pytest.raises(scan_admission.ScanAdmissionUnavailable):
        await scan_admission.acquire("shodan", ttl_seconds=1)
    reset.assert_called_once()


@pytest.mark.asyncio
async def test_release_is_noop_without_client_or_token(monkeypatch):
    monkeypatch.setattr(scan_admission.RateLimiter, "_get_client", classmethod(lambda cls: None))
    monkeypatch.delenv("TESTING", raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)
    await scan_admission.release("shodan")


@pytest.mark.asyncio
async def test_release_resets_client_when_eval_fails(monkeypatch):
    client = FakeRedis()
    client.eval.side_effect = RuntimeError("redis down")
    reset = AsyncMock()
    monkeypatch.setattr(scan_admission.RateLimiter, "_get_client", classmethod(lambda cls: client))
    monkeypatch.setattr(scan_admission.RateLimiter, "_reset_client", reset)
    monkeypatch.delenv("TESTING", raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)
    await scan_admission.release("shodan", "owned-token")
    reset.assert_called_once()


@pytest.mark.asyncio
async def test_acquire_rejects_a_second_scan_for_the_same_connector(monkeypatch):
    client = FakeRedis(claimed=False)
    monkeypatch.setattr(scan_admission.RateLimiter, "_get_client", classmethod(lambda cls: client))
    monkeypatch.delenv("TESTING", raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)

    with pytest.raises(scan_admission.ScanAlreadyRunning) as raised:
        await scan_admission.acquire("shodan", ttl_seconds=3600)

    assert raised.value.status_code == 409
    client.set.assert_awaited_once()


@pytest.mark.asyncio
async def test_release_uses_compare_and_delete_script(monkeypatch):
    client = FakeRedis()
    monkeypatch.setattr(scan_admission.RateLimiter, "_get_client", classmethod(lambda cls: client))
    monkeypatch.delenv("TESTING", raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)

    await scan_admission.release("dnstwist", "owned-token")

    client.eval.assert_awaited_once()
    args = client.eval.await_args.args
    assert args[1:] == (1, "scan:admission:dnstwist", "owned-token")


@pytest.mark.asyncio
async def test_admission_fails_closed_when_redis_is_unavailable(monkeypatch):
    monkeypatch.setattr(scan_admission.RateLimiter, "_get_client", classmethod(lambda cls: None))
    monkeypatch.delenv("TESTING", raising=False)
    monkeypatch.delenv("APP_ENV", raising=False)

    with pytest.raises(scan_admission.ScanAdmissionUnavailable) as raised:
        await scan_admission.acquire("hibp", ttl_seconds=3600)

    assert raised.value.status_code == 503
    assert raised.value.headers["Retry-After"] == "10"
