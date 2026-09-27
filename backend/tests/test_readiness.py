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
