"""Production wire contract of the browser authentication flow.

The unit suites pin behaviour; these tests pin the contract a deployment
depends on: refresh credential isolation (HttpOnly cookie only), the CSRF
pairing required for cookie-backed refresh, and cookie cleanup on logout.

Pure backend, no external services: they run in the standard suite.
"""

from __future__ import annotations

import pytest

from app.core.config import settings

PASSWORD = "TestPass123!"


def _set_cookie_headers(response, name: str) -> list[str]:
    """Return every ``Set-Cookie`` header issued for ``name``."""
    return [
        value.decode()
        for key, value in response.headers.raw
        if key.lower() == b"set-cookie" and f"{name}=" in value.decode()
    ]


async def _login(client, email: str):
    return await client.post(
        "/api/v1/auth/login", json={"email": email, "password": PASSWORD}
    )


class TestBrowserAuthWireContract:
    @pytest.mark.asyncio
    async def test_login_sets_isolated_refresh_cookie_and_no_token_in_body(
        self, client, test_admin
    ):
        response = await _login(client, test_admin.email)
        assert response.status_code == 200, response.text

        # The long-lived credential must not be readable by browser JavaScript.
        assert "refresh_token" not in response.json()

        refresh_headers = _set_cookie_headers(response, "opendrp_refresh")
        assert len(refresh_headers) == 1
        refresh = refresh_headers[0].lower()
        assert "httponly" in refresh
        assert "samesite=lax" in refresh
        # Scoped to the auth endpoints: it is not attached to ordinary API calls.
        assert "path=/api/v1/auth" in refresh
        # Secure must follow configuration (true in production, validated there).
        assert ("secure" in refresh) is settings.AUTH_COOKIE_SECURE

        csrf_headers = _set_cookie_headers(response, "opendrp_csrf")
        assert len(csrf_headers) == 1
        csrf = csrf_headers[0].lower()
        # The SPA has to read this one to echo it back in X-CSRF-Token.
        assert "httponly" not in csrf
        assert "path=/" in csrf

    @pytest.mark.asyncio
    async def test_cookie_refresh_with_csrf_pair_rotates_the_session(
        self, client, test_admin
    ):
        login = await _login(client, test_admin.email)
        refresh = login.cookies.get("opendrp_refresh")
        csrf = login.cookies.get("opendrp_csrf")
        assert refresh and csrf

        refreshed = await client.post(
            "/api/v1/auth/refresh",
            cookies={"opendrp_refresh": refresh, "opendrp_csrf": csrf},
            headers={"X-CSRF-Token": csrf},
        )
        assert refreshed.status_code == 200, refreshed.text

        body = refreshed.json()
        assert "refresh_token" not in body
        assert refreshed.cookies.get("opendrp_refresh") != refresh

        # The rotated access token must actually authorize a protected call.
        me = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {body['access_token']}"},
        )
        assert me.status_code == 200, me.text
        assert me.json()["email"] == test_admin.email

    @pytest.mark.asyncio
    async def test_logout_expires_both_cookies_on_their_own_paths(
        self, client, test_admin
    ):
        login = await _login(client, test_admin.email)
        refresh = login.cookies.get("opendrp_refresh")
        csrf = login.cookies.get("opendrp_csrf")
        assert refresh and csrf

        response = await client.post(
            "/api/v1/auth/logout",
            cookies={"opendrp_refresh": refresh, "opendrp_csrf": csrf},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 204, response.text

        # A deletion sent with the wrong Path leaves the cookie alive.
        deletions = " ".join(
            _set_cookie_headers(response, "opendrp_refresh")
            + _set_cookie_headers(response, "opendrp_csrf")
        ).lower()
        assert "path=/api/v1/auth" in deletions
        assert "path=/" in deletions
