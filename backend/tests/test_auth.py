import pytest


@pytest.mark.anyio
async def test_health_public(client):
    r = await client.get("/api/v1/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "version" in data
