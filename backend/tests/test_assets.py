import pytest


@pytest.mark.anyio
async def test_assets_requires_auth(client):
    r = await client.get("/api/v1/assets")
    assert r.status_code == 401
