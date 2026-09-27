"""Characterization tests: auth defense-in-depth branches (Step 3).

Pins the CURRENT behavior of ``app/api/v1/routers/auth.py`` refresh/logout
guard paths that had no direct coverage. Existing suites already pin login
success/failure, lockout, rotation and refresh-reuse revocation; this module
completes the security matrix:

* refresh for a user that was deleted or deactivated after login;
* refresh where the token's ``family_id`` is not a UUID / has no family row;
* refresh with a family revoked via logout (reason ``logout``);
* refresh where the family belongs to a *different* user (mismatch must NOT
  revoke the family — only reuse detection does);
* CSRF enforcement when the refresh token arrives via cookie only;
* logout with a refresh token revokes the family and blocks later refreshes.

Everything here is pinned before any refactor of ``auth.py``.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.core.security import create_refresh_token, decode_token
from app.models.audit import AuditLog
from app.models.token import RefreshTokenFamily
from app.models.user import User

PASSWORD = "TestPass123!"


async def _login(client, email: str):
    return await client.post(
        "/api/v1/auth/login", json={"email": email, "password": PASSWORD}
    )


def _refresh_from(response) -> str:
    refresh = response.cookies.get("opendrp_refresh")
    assert refresh
    return refresh


async def _last_refresh_failure_reason(db, reason: str) -> AuditLog | None:
    rows = list(
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.action == "auth.refresh.failure")
                .order_by(AuditLog.timestamp.desc())
            )
        ).scalars()
    )
    for row in rows:
        if row.details.get("reason") == reason:
            return row
    return None


@pytest.mark.asyncio
async def test_refresh_for_deleted_user_401(client, db_session, test_viewer):
    login = await _login(client, test_viewer.email)
    assert login.status_code == 200, login.text
    refresh = _refresh_from(login)

    await db_session.delete(
        (await db_session.execute(select(User).where(User.id == test_viewer.id))).scalar_one()
    )
    await db_session.commit()

    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401, r.text
    assert "not found or inactive" in r.json()["detail"].lower()
    row = await _last_refresh_failure_reason(db_session, "user_missing_or_inactive")
    assert row is not None


@pytest.mark.asyncio
async def test_refresh_for_deactivated_user_401(client, db_session, test_viewer):
    login = await _login(client, test_viewer.email)
    refresh = _refresh_from(login)

    user = (
        await db_session.execute(select(User).where(User.id == test_viewer.id))
    ).scalar_one()
    user.is_active = False
    await db_session.commit()

    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401, r.text
    row = await _last_refresh_failure_reason(db_session, "user_missing_or_inactive")
    assert row is not None


@pytest.mark.asyncio
async def test_refresh_with_non_uuid_family_id_401(client, test_admin):
    login = await _login(client, test_admin.email)
    assert login.status_code == 200, login.text

    tok, _, _, _ = create_refresh_token(
        {"sub": str(test_admin.id), "role": "admin"}, family_id="not-a-uuid"
    )
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": tok})
    assert r.status_code == 401, r.text
    assert "payload" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_refresh_with_unknown_family_401_and_audited(client, db_session, test_admin):
    login = await _login(client, test_admin.email)
    assert login.status_code == 200, login.text

    tok, _, _, _ = create_refresh_token(
        {"sub": str(test_admin.id), "role": "admin"}, family_id=str(uuid.uuid4())
    )
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": tok})
    assert r.status_code == 401, r.text
    assert "unknown" in r.json()["detail"].lower()
    row = await _last_refresh_failure_reason(db_session, "family_not_found")
    assert row is not None
    assert row.details.get("family_id")


@pytest.mark.asyncio
async def test_refresh_after_logout_revoked_family_401(client, auth_headers_admin, db_session, test_admin):
    login = await _login(client, test_admin.email)
    refresh = _refresh_from(login)

    r = await client.post(
        "/api/v1/auth/logout",
        headers=auth_headers_admin,
        json={"refresh_token": refresh},
    )
    assert r.status_code == 204, r.text

    fam = (
        await db_session.execute(
            select(RefreshTokenFamily).where(RefreshTokenFamily.user_id == test_admin.id)
        )
    ).scalar_one()
    assert fam.revoked is True
    assert fam.revoked_reason == "logout"

    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 401, r.text
    assert "revoked" in r.json()["detail"].lower()
    row = await _last_refresh_failure_reason(db_session, "family_revoked")
    assert row is not None
    assert row.details.get("revoked_reason") == "logout"


@pytest.mark.asyncio
async def test_refresh_family_of_another_user_401_family_not_revoked(
    client, db_session, test_admin, test_viewer
):
    """Cross-user family: the token is rejected and the family survives.

    Pinned nuance: only *reuse detection* revokes a family; a user mismatch
    leaves it intact (the legitimate owner can keep refreshing).
    """
    login = await _login(client, test_admin.email)
    refresh = _refresh_from(login)
    stolen_family_id = decode_token(refresh)["family_id"]

    tok, _, _, _ = create_refresh_token(
        {"sub": str(test_viewer.id), "role": "viewer"}, family_id=stolen_family_id
    )
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": tok})
    assert r.status_code == 401, r.text
    assert "match" in r.json()["detail"].lower()
    row = await _last_refresh_failure_reason(db_session, "family_user_mismatch")
    assert row is not None

    fam = (
        await db_session.execute(
            select(RefreshTokenFamily).where(
                RefreshTokenFamily.family_id == uuid.UUID(stolen_family_id)
            )
        )
    ).scalar_one()
    assert fam.revoked is False


class TestRefreshCsrfCookieFlow:
    @pytest.fixture
    def app(self):
        from app.main import app as fastapi_app

        return fastapi_app

    async def _login_with_cookies(self, app) -> tuple[str, dict]:
        """Login over HTTP, return (refresh_token, cookie jar from the login)."""
        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            login = await c.post(
                "/api/v1/auth/login",
                json={"email": "test_admin@example.com", "password": PASSWORD},
            )
            assert login.status_code == 200, login.text
            refresh = _refresh_from(login)
            return refresh, dict(c.cookies)

    async def _post_with_cookies(self, app, cookies: dict, extra_headers: dict | None = None):
        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://t", cookies=cookies
        ) as c:
            return await c.post(
                "/api/v1/auth/refresh",
                headers=dict(extra_headers or {}),
            )

    @pytest.mark.asyncio
    async def test_cookie_refresh_without_csrf_pair_401(self, app, test_admin):
        refresh, _ = await self._login_with_cookies(app)

        r = await self._post_with_cookies(app, {"opendrp_refresh": refresh})
        assert r.status_code == 401, r.text
        assert "csrf" in r.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_login_csrf_cookie_is_available_to_frontend_root_path(self, client, test_admin):
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": PASSWORD},
        )
        assert response.status_code == 200, response.text
        csrf_headers = [
            value
            for key, value in response.headers.raw
            if key.lower() == b"set-cookie" and b"opendrp_csrf=" in value
        ]
        assert csrf_headers
        assert b"Path=/" in csrf_headers[0]

    @pytest.mark.asyncio
    async def test_cookie_refresh_with_mismatched_csrf_401(self, app, test_admin):
        refresh, _ = await self._login_with_cookies(app)

        r = await self._post_with_cookies(
            app,
            {"opendrp_refresh": refresh, "opendrp_csrf": "aaa"},
            extra_headers={"X-CSRF-Token": "bbb"},
        )
        assert r.status_code == 401, r.text
        assert "csrf" in r.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_cookie_refresh_accepts_empty_json_body(self, app, test_admin):
        """The SPA sends ``{}`` because the refresh credential is HttpOnly.

        The schema must not require ``refresh_token`` in that form: doing so
        produces 422 before the cookie-authentication code can run, and the
        frontend correctly interprets the resulting failed restore as a logout.
        """
        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://t") as c:
            login = await c.post(
                "/api/v1/auth/login",
                json={"email": "test_admin@example.com", "password": PASSWORD},
            )
            assert login.status_code == 200, login.text
            csrf = c.cookies.get("opendrp_csrf")
            assert csrf
            refreshed = await c.post(
                "/api/v1/auth/refresh",
                json={},
                headers={"X-CSRF-Token": csrf},
            )

        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()["access_token"]

    @pytest.mark.asyncio
    async def test_cookie_refresh_accepts_no_body(self, app, test_admin):
        """Cookie authentication also works when the request has no body."""
        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://t") as c:
            login = await c.post(
                "/api/v1/auth/login",
                json={"email": "test_admin@example.com", "password": PASSWORD},
            )
            assert login.status_code == 200, login.text
            csrf = c.cookies.get("opendrp_csrf")
            assert csrf
            refreshed = await c.post(
                "/api/v1/auth/refresh",
                headers={"X-CSRF-Token": csrf},
            )

        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()["access_token"]


@pytest.mark.asyncio
async def test_logout_revokes_family_even_without_access_token(client, test_admin):
    """Logout with only a refresh token (no Bearer header) still revokes."""
    login = await _login(client, test_admin.email)
    refresh = _refresh_from(login)

    r = await client.post("/api/v1/auth/logout", json={"refresh_token": refresh})
    assert r.status_code == 204, r.text

    # Second logout with the same (now revoked) token must still be 204.
    r2 = await client.post("/api/v1/auth/logout", json={"refresh_token": refresh})
    assert r2.status_code == 204, r2.text


class TestRefusedRefreshStopsPresentingTheCookie:
    """A refused cookie token is deleted, so the browser stops sending it.

    The SPA cannot read an ``HttpOnly`` cookie, so it asks ``/auth/refresh`` on
    every page load whether it is still signed in (the stored user is only a hint
    for the first paint). Presenting a token this endpoint will never accept again
    — expired, tampered, or a revoked family — would otherwise be retried, and
    audited as ``auth.refresh.failure``, once per load until it expired.

    The refusals that are *not* about the token keep it: a failed CSRF pair means
    the request is wrong while the token is still good, and a token presented in
    the body belongs to a caller that holds it deliberately, so refusing that one
    must not sign this browser out.
    """

    @pytest.fixture
    def app(self):
        from app.main import app as fastapi_app

        return fastapi_app

    @staticmethod
    def _cookie_deletion(response) -> bytes | None:
        """The ``Set-Cookie`` that clears the refresh cookie, if one was sent."""
        for key, value in response.headers.raw:
            if key.lower() != b"set-cookie" or not value.startswith(b"opendrp_refresh="):
                continue
            if b"Max-Age=0" in value:
                return value
        return None

    async def _refresh_with(self, app, cookies: dict, **kwargs):
        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://t", cookies=cookies
        ) as c:
            return await c.post("/api/v1/auth/refresh", **kwargs)

    async def _login_jar(self, app) -> dict:
        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            login = await c.post(
                "/api/v1/auth/login",
                json={"email": "test_admin@example.com", "password": PASSWORD},
            )
            assert login.status_code == 200, login.text
            return dict(c.cookies)

    @pytest.mark.asyncio
    async def test_token_the_api_will_refuse_is_deleted_from_the_browser(
        self, app, test_admin
    ):
        jar = await self._login_jar(app)
        jar["opendrp_refresh"] = "not-a-token"

        r = await self._refresh_with(app, jar, headers={"X-CSRF-Token": jar["opendrp_csrf"]})

        assert r.status_code == 401, r.text
        deleted = self._cookie_deletion(r)
        assert deleted is not None, "the refused token must not be presented again"
        assert b"Path=/api/v1/auth" in deleted

    @pytest.mark.asyncio
    async def test_revoked_family_is_deleted_from_the_browser(self, app, test_admin):
        jar = await self._login_jar(app)

        from httpx import ASGITransport, AsyncClient

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://t", cookies=jar
        ) as c:
            out = await c.post(
                "/api/v1/auth/logout", headers={"X-CSRF-Token": jar["opendrp_csrf"]}
            )
        assert out.status_code == 204, out.text

        r = await self._refresh_with(app, jar, headers={"X-CSRF-Token": jar["opendrp_csrf"]})

        assert r.status_code == 401, r.text
        assert self._cookie_deletion(r) is not None

    @pytest.mark.asyncio
    async def test_csrf_refusal_keeps_the_token(self, app, test_admin):
        jar = await self._login_jar(app)

        # No X-CSRF-Token header: the request is wrong, the token is not.
        r = await self._refresh_with(app, jar)

        assert r.status_code == 401, r.text
        assert "csrf" in r.json()["detail"].lower()
        assert self._cookie_deletion(r) is None

    @pytest.mark.asyncio
    async def test_body_token_refusal_does_not_sign_the_browser_out(
        self, app, test_admin
    ):
        jar = await self._login_jar(app)

        r = await self._refresh_with(app, jar, json={"refresh_token": "not-a-token"})

        assert r.status_code == 401, r.text
        assert self._cookie_deletion(r) is None

    @pytest.mark.asyncio
    async def test_no_token_at_all_sends_no_cookie_header(self, app, test_admin):
        """The anonymous case — the first load of every visitor — stays headerless.

        It is the most common request this endpoint sees, and there is nothing to
        delete, so clearing the cookie here would be noise on every page load.
        """
        r = await self._refresh_with(app, {})

        assert r.status_code == 401, r.text
        assert self._cookie_deletion(r) is None
