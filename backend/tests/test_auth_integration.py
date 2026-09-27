from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


BASE = "http://test"


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest.fixture()
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    from app.api.deps import get_db

    async def _get_db_override():
        yield db_session

    app.dependency_overrides[get_db] = _get_db_override
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url=BASE,
        ) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_db, None)


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_json_admin_ok_200_tokens_match_identity(self, client, test_admin):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": "TestPass123!"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["token_type"] == "bearer"
        assert body["expires_in"] > 0
        assert isinstance(body["access_token"], str) and len(body["access_token"]) > 20
        assert "refresh_token" not in body
        assert r.cookies.get("opendrp_refresh")
        assert body["user"]["email"] == test_admin.email
        assert body["user"]["role"] == "admin"
        assert body["user"]["is_active"] is True

    @pytest.mark.asyncio
    async def test_login_inactive_user_401(self, client, test_inactive_admin):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": test_inactive_admin.email, "password": "TestPass123!"},
        )
        assert r.status_code == 401
        detail = r.json()["detail"].lower()
        assert ("disabled" in detail) or ("invalid" in detail)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "email,password,expected_status",
        [
            # Invalid email format is rejected by schema validation.
            ("not-an-email", "GoodPass1!", 422),
            # Password *strength* rules deliberately do NOT apply at login:
            # weak guesses must reach the handler so they are rate-limited and
            # audited like every other failed attempt.
            ("unknown@example.com", "tooshort1", 401),
            ("unknown@example.com", "NO_DIGITS_HERE", 401),
            ("unknown@example.com", "12345678", 401),
            # Missing credentials are handled by the endpoint itself.
            (None, None, 422),
        ],
    )
    async def test_login_validation_matrix_422(
        self, client, email, password, expected_status
    ):
        payload = {}
        if email is not None:
            payload["email"] = email
        if password is not None:
            payload["password"] = password
        r = await client.post("/api/v1/auth/login", json=payload)
        assert r.status_code == expected_status, (r.status_code, r.text)

    @pytest.mark.asyncio
    async def test_weak_password_attempt_is_counted_and_audited(
        self, client, db_session, test_analyst
    ):
        """A weak-password guess must count toward lockout and be audited."""
        from sqlalchemy import select

        from app.models.audit import AuditLog
        from app.models.user import User

        for _ in range(2):
            r = await client.post(
                "/api/v1/auth/login",
                json={"email": test_analyst.email, "password": "weak"},
            )
            assert r.status_code == 401, r.text

        user = (
            await db_session.execute(select(User).where(User.id == test_analyst.id))
        ).scalar_one()
        assert (user.failed_login_attempts or 0) >= 2

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "auth.login.failure")
                )
            ).scalars().all()
        )
        assert len(rows) >= 2


class TestRefreshAndLogout:
    @pytest.mark.asyncio
    async def test_refresh_valid_returns_new_access(self, client, test_admin):
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": "TestPass123!"},
        )
        refresh = login.cookies.get("opendrp_refresh")
        assert refresh
        r = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": refresh}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["user"]["email"] == test_admin.email
        assert "refresh_token" not in body
        assert r.cookies.get("opendrp_refresh") != refresh
        assert isinstance(body["access_token"], str) and len(body["access_token"]) > 20

    @pytest.mark.asyncio
    async def test_refresh_access_token_as_refresh_401(self, client, test_admin):
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": "TestPass123!"},
        )
        bad = login.json()["access_token"]
        r = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": bad}
        )
        assert r.status_code == 401
        assert "type" in r.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_refresh_tampered_garbage_401(self, client):
        r = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "not.a.valid.jwt.token.1234"},
        )
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_bad_uuid_sub_payload_401(self, client):
        from app.core.security import create_refresh_token
        tok, _, _, _ = create_refresh_token({"sub": "clearly-not-a-uuid", "role": "admin"})
        r = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": tok}
        )
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_security_sessions_and_activity_do_not_expose_tokens(self, client, test_admin):
        login = await client.post("/api/v1/auth/login", json={"email": test_admin.email, "password": "TestPass123!"})
        assert login.status_code == 200
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        sessions = await client.get("/api/v1/auth/sessions", headers=headers)
        assert sessions.status_code == 200
        assert sessions.json() and sessions.json()[0]["current"] is True
        assert "token" not in sessions.text.lower()
        activity = await client.get("/api/v1/auth/security-activity", headers=headers)
        assert activity.status_code == 200
        assert all("password" not in str(item.get("details", {})).lower() for item in activity.json())

    @pytest.mark.asyncio
    async def test_revoke_other_sessions_keeps_current_access_session(self, client, test_admin):
        first = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": "TestPass123!"},
        )
        second = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": "TestPass123!"},
        )
        assert first.status_code == 200 and second.status_code == 200
        headers = {"Authorization": f"Bearer {second.json()['access_token']}"}
        revoked = await client.post("/api/v1/auth/sessions/revoke-others", headers=headers)
        assert revoked.status_code == 200
        assert revoked.json()["revoked"] >= 1
        sessions = await client.get("/api/v1/auth/sessions", headers=headers)
        assert sessions.status_code == 200
        # The list answers with sessions that can still be used: the one this
        # request holds, and nothing else.
        assert [row["current"] for row in sessions.json()] == [True]

    @pytest.mark.asyncio
    async def test_a_signed_out_session_is_not_listed_as_a_device(self, client, test_admin):
        """A session that ended is an audit event, not a session.

        Every sign-in writes a family row and a password change rotates the
        session, so an account soon owns rows it can no longer use. Returning
        them here made the sessions somebody had already closed read as devices
        they did not recognise — the page is titled "active sessions".
        """
        first = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": "TestPass123!"},
        )
        second = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": "TestPass123!"},
        )
        assert first.status_code == 200 and second.status_code == 200
        headers = {"Authorization": f"Bearer {second.json()['access_token']}"}
        assert (await client.post("/api/v1/auth/sessions/revoke-others", headers=headers)).status_code == 200

        sessions = await client.get("/api/v1/auth/sessions", headers=headers)
        assert sessions.status_code == 200
        body = sessions.json()
        assert len(body) == 1
        assert body[0]["current"] is True
        # No state field about ending: the endpoint only returns rows that can
        # still be used, so the flag could never be anything but false.
        assert "revoked" not in body[0]

        # The ended sessions are still on record where an operator looks for
        # them, and the reason is part of the event rather than of the session.
        activity = await client.get("/api/v1/auth/security-activity", headers=headers)
        assert activity.status_code == 200
        assert any(row["action"] == "auth.sessions.revoked_others" for row in activity.json())

    @pytest.mark.asyncio
    async def test_revoke_unknown_session_is_idempotent(self, client, auth_headers_admin):
        import uuid

        response = await client.delete(
            f"/api/v1/auth/sessions/{uuid.uuid4()}", headers=auth_headers_admin
        )
        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_logout_204(self, client, auth_headers_admin):
        r = await client.post(
            "/api/v1/auth/logout",
            headers=auth_headers_admin,
        )
        assert r.status_code == 204
        assert r.content == b"" or r.text == ""
