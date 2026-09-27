import pytest

ANY_ROLE = object()


@pytest.mark.anyio
class TestPublicEndpoints:
    async def test_health_public_no_auth_200(self, client):
        r = await client.get("/api/v1/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "version" in body and "timestamp" in body

    @pytest.mark.parametrize(
        "method,url",
        [
            ("GET", "/api/v1/assets"),
            ("GET", "/api/v1/settings"),
            ("GET", "/api/v1/auth/me"),
            ("GET", "/api/v1/reports"),
            ("GET", "/api/v1/dashboard/stats"),
        ],
    )
    async def test_private_endpoints_require_bearer_401(self, client, method, url):
        r = await client.request(method, url)
        assert r.status_code == 401


@pytest.mark.anyio
class TestAuthMeEndpoint:
    async def test_database_role_wins_over_tampered_jwt_role_claim(
        self, client, test_admin
    ):
        from app.core.security import create_access_token

        token, _ = create_access_token({"sub": str(test_admin.id), "role": "viewer"})
        response = await client.get(
            "/api/v1/settings", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200

        token, _ = create_access_token({"sub": str(test_admin.id), "role": "analyst"})
        response = await client.get(
            "/api/v1/users", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200

    async def test_admin_me_returns_own_user(self, client, test_admin, auth_headers_admin):
        r = await client.get("/api/v1/auth/me", headers=auth_headers_admin)
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == test_admin.email
        assert data["role"] == "admin"
        assert data["is_active"] is True
        assert "id" in data and "password_hash" not in data

    async def test_inactive_user_rejected_401(self, client, test_inactive_admin):
        from app.core.security import create_access_token
        tok, _ = create_access_token({"sub": str(test_inactive_admin.id)})
        r = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"}
        )
        assert r.status_code == 401

    async def test_refresh_token_rejected_as_access_401(self, client, test_admin):
        from app.core.security import create_refresh_token
        tok, _, _, _ = create_refresh_token({"sub": str(test_admin.id)})
        r = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"}
        )
        assert r.status_code == 401


@pytest.mark.anyio
class TestSettingsAdminOnly:
    async def test_admin_get_settings_200(self, client, auth_headers_admin):
        r = await client.get("/api/v1/settings", headers=auth_headers_admin)
        assert r.status_code == 200
        body = r.json()
        assert "shodan_api_key" not in body
        assert "hibp_api_key" not in body
        assert "id" in body

    async def test_analyst_cannot_get_settings_403(self, client, auth_headers_analyst):
        r = await client.get("/api/v1/settings", headers=auth_headers_analyst)
        assert r.status_code == 403

    async def test_viewer_cannot_get_settings_403(self, client, auth_headers_viewer):
        r = await client.get("/api/v1/settings", headers=auth_headers_viewer)
        assert r.status_code == 403


@pytest.mark.anyio
class TestAssetsRoleMatrix:
    async def test_assets_get_admin_200(
        self, client, auth_headers_admin
    ):
        r = await client.get("/api/v1/assets", headers=auth_headers_admin)
        assert r.status_code == 200

    async def test_assets_get_analyst_200(
        self, client, auth_headers_analyst
    ):
        r = await client.get("/api/v1/assets", headers=auth_headers_analyst)
        assert r.status_code == 200

    async def test_assets_get_viewer_200(
        self, client, auth_headers_viewer
    ):
        r = await client.get("/api/v1/assets", headers=auth_headers_viewer)
        assert r.status_code == 200

    async def test_analyst_can_create_asset_201(self, client, auth_headers_analyst):
        r = await client.post(
            "/api/v1/assets",
            headers=auth_headers_analyst,
            json={"asset_type": "domain", "asset_value": "example-analyst.com"},
        )
        assert r.status_code == 201
        assert r.json()["asset_value"] == "example-analyst.com"

    async def test_viewer_create_asset_rejected_403(self, client, auth_headers_viewer):
        r = await client.post(
            "/api/v1/assets",
            headers=auth_headers_viewer,
            json={"asset_type": "domain", "asset_value": "nope.com"},
        )
        assert r.status_code == 403


@pytest.mark.anyio
class TestReportDeleteAdminOnly:
    async def test_viewer_delete_report_is_403(self, client, auth_headers_viewer):
        import uuid
        r = await client.delete(
            f"/api/v1/reports/{uuid.uuid4()}", headers=auth_headers_viewer
        )
        assert r.status_code == 403
