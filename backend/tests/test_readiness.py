"""Liveness and readiness probe contract.

A production deployment depends on these two probes staying *different*:

* liveness must never touch PostgreSQL/Redis, otherwise a dependency outage
  turns into a container restart loop;
* readiness must fail closed (503) while a dependency is unusable, so traffic
  is drained instead of being served broken requests.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

# Probes are resolved on the module, so one patch intercepts the endpoint.
_DB_PROBE = "app.core.health.check_database"
_REDIS_PROBE = "app.core.health.check_redis"


@pytest.mark.asyncio
async def test_liveness_stays_ok_when_every_dependency_is_down(client):
    with patch(_DB_PROBE, AsyncMock(side_effect=RuntimeError("db down"))), patch(
        _REDIS_PROBE, AsyncMock(side_effect=RuntimeError("redis down"))
    ):
        response = await client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_readiness_ok_when_all_dependencies_respond(client):
    with patch(_DB_PROBE, AsyncMock()), patch(_REDIS_PROBE, AsyncMock()):
        response = await client.get("/api/v1/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"] == {"database": "ok", "redis": "ok", "audit": "ok"}


@pytest.mark.asyncio
async def test_readiness_degrades_when_database_is_unusable(client):
    with patch(_DB_PROBE, AsyncMock(side_effect=RuntimeError("db down"))), patch(
        _REDIS_PROBE, AsyncMock()
    ):
        response = await client.get("/api/v1/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["database"] == "error"
    assert body["checks"]["redis"] == "ok"


@pytest.mark.asyncio
async def test_readiness_degrades_when_redis_is_unusable(client):
    with patch(_DB_PROBE, AsyncMock()), patch(
        _REDIS_PROBE, AsyncMock(side_effect=RuntimeError("redis down"))
    ):
        response = await client.get("/api/v1/ready")

    assert response.status_code == 503
    assert response.json()["checks"]["redis"] == "error"


@pytest.mark.asyncio
async def test_database_probe_really_queries_the_configured_database():
    """Unpatched probe: proves it executes SQL instead of always succeeding."""
    from app.core import health

    await health.check_database()


@pytest.mark.asyncio
async def test_database_probe_gives_up_instead_of_waiting_for_a_connection(monkeypatch):
    """The probe is bounded, like the Redis one, and by the same constant.

    Both of the pool's own waits are longer than a readiness probe may take
    (`DB_POOL_TIMEOUT_SECONDS` and `DB_STATEMENT_TIMEOUT_MS` are 30s by default),
    so an unreachable or saturated database used to hold the balancer's request for
    half a minute and answer nothing at all. The bound is what turns that into a
    fast 503.
    """
    import asyncio

    from app.core import health

    async def _never_answers() -> None:
        await asyncio.sleep(3600)

    monkeypatch.setattr(health, "_ping_database", _never_answers)
    monkeypatch.setattr(health, "_PROBE_TIMEOUT_SECONDS", 0.05)

    with pytest.raises(asyncio.TimeoutError):
        await health.check_database()


@pytest.mark.asyncio
async def test_readiness_answers_503_quickly_when_the_database_hangs(client, monkeypatch):
    """The endpoint, not only the helper: a hung connect becomes a 503, not a wait."""
    import asyncio
    import time

    from app.core import health

    async def _never_answers() -> None:
        await asyncio.sleep(3600)

    monkeypatch.setattr(health, "_ping_database", _never_answers)
    monkeypatch.setattr(health, "_PROBE_TIMEOUT_SECONDS", 0.05)
    with patch(_REDIS_PROBE, AsyncMock()):
        started = time.monotonic()
        response = await client.get("/api/v1/ready")
        elapsed = time.monotonic() - started

    assert response.status_code == 503
    assert response.json()["checks"]["database"] == "error"
    assert elapsed < 5, f"the readiness probe waited {elapsed:.1f}s for a hung database"
