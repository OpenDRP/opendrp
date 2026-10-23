"""The refusals in ``app/api/v1/routers/auth.py`` that the happy path never shows.

Coverage batch 01's second half. The suite in `test_auth.py` proves that a valid
sign-in, a refresh and a logout work; `test_mfa.py` proves the enrolment rules.
What neither executes is the set of answers a client gets when it is early, late,
replaying, or holding a session the core cannot identify — and each of those is a
security decision rather than a formatting one:

* a locked second factor must answer before the code is compared, or the lock is
  a suggestion;
* a logout presenting the refresh cookie without the CSRF header is a request a
  browser did not make;
* ``revoke-others`` cannot revoke "others" when it cannot tell which session is
  the caller's — guessing would sign the caller out;
* the lockout helpers compare naive timestamps too, because SQLite hands them
  back that way and an aware comparison would turn a refusal into a 500;
* a pending factor secret that cannot be decrypted must not become a 500 inside
  the authentication path;
* a password change has to end the sessions the old credential authorised, so a
  refresh token issued before it cannot be replayed afterwards.

The best-effort helpers are tested directly: a Redis outage must not fail a login,
and that property is a function's contract rather than a route's.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.routers import auth as auth_router
from app.models.audit import AuditLog
from app.models.token import RefreshTokenFamily

PASSWORD = "TestPass123!"


async def _audit_row(db_session, action: str) -> AuditLog | None:
    rows = (
        (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == action)
                .order_by(AuditLog.timestamp.desc())
                .limit(1)
            )
        )
        .scalars()
        .all()
    )
    return rows[0] if rows else None


class TestLockHelpers:
    """The two lockout predicates, on both timestamp shapes storage returns."""

    def test_an_expired_or_absent_mfa_lock_is_not_a_lock(self):
        now = datetime.now(timezone.utc)
        assert auth_router._mfa_is_locked(MagicMock(mfa_locked_until=None), now) is False
        assert (
            auth_router._mfa_is_locked(
                MagicMock(mfa_locked_until=now - timedelta(minutes=1)), now
            )
            is False
        )

    def test_a_naive_mfa_lock_is_compared_in_utc(self):
        """SQLite stores the column without a zone; comparing it must not raise."""
        now = datetime.now(timezone.utc)
        naive_future = (now + timedelta(minutes=5)).replace(tzinfo=None)
        assert auth_router._mfa_is_locked(MagicMock(mfa_locked_until=naive_future), now) is True

    def test_a_naive_database_lock_is_compared_in_utc(self):
        now = datetime.now(timezone.utc)
        naive_future = (now + timedelta(minutes=5)).replace(tzinfo=None)
        assert auth_router._user_is_db_locked(MagicMock(locked_until=naive_future), now) is True


class TestBestEffortLimiters:
    """A Redis outage is a lost counter, not a failed sign-in."""

    @pytest.mark.asyncio
    async def test_a_failed_failure_counter_is_logged_not_raised(self, caplog):
        with patch.object(
            auth_router._rate_limiter,
            "incr_failure",
            new=AsyncMock(side_effect=RuntimeError("redis down")),
        ):
            await auth_router._record_failed_login("user@example.com", "198.51.100.7")

    @pytest.mark.asyncio
    async def test_a_failed_reset_is_logged_not_raised(self):
        with patch.object(
            auth_router._rate_limiter,
            "reset",
            new=AsyncMock(side_effect=RuntimeError("redis down")),
        ):
            await auth_router._clear_login_rate_limit("user@example.com", "198.51.100.7")


class TestSessionIdentity:
    """``_current_family_id`` answers "which browser is this", or nothing."""

    def test_without_a_cookie_or_a_token_there_is_no_session(self):
        assert auth_router._current_family_id(None) is None

    def test_the_access_token_is_the_read_only_fallback(self):
        family = uuid.uuid4()
        request = MagicMock()
        request.headers.get.return_value = "Bearer access-token"
        with patch.object(
            auth_router, "decode_token", return_value={"family_id": str(family)}
        ):
            assert auth_router._current_family_id(None, request) == family

    def test_a_payload_without_a_family_is_no_session(self):
        with patch.object(auth_router, "decode_token", return_value={"sub": "x"}):
            assert auth_router._current_family_id("cookie") is None

    def test_a_family_that_is_not_a_uuid_is_no_session(self):
        with patch.object(
            auth_router, "decode_token", return_value={"family_id": "not-a-uuid"}
        ):
            assert auth_router._current_family_id("cookie") is None


class TestUndecryptableSecret:
    def test_a_secret_no_configured_key_can_read_is_absent(self):
        """The safe answer to "can this account prove possession" is no."""
        user = MagicMock(totp_secret="ciphertext-from-another-installation", id=uuid.uuid4())
        with patch.object(
            auth_router, "decrypt_value", side_effect=RuntimeError("no key")
        ):
            assert auth_router._decrypted_totp_secret(user) is None


class TestLoginRefusals:
    @pytest.mark.anyio
    async def test_a_body_that_is_not_credentials_is_a_bad_request(self, client):
        r = await client.post("/api/v1/auth/login")

        assert r.status_code == 400
        assert r.json()["detail"] == "Email and password are required"

    @pytest.mark.anyio
    async def test_a_locked_factor_answers_before_the_code_is_read(
        self, client, test_admin
    ):
        """The lock is a refusal, not a delay: a correct password still stops here."""
        test_admin.totp_enabled_at = datetime.now(timezone.utc)
        test_admin.mfa_locked_until = datetime.now(timezone.utc) + timedelta(minutes=5)

        r = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": PASSWORD, "totp_code": "123456"},
        )

        assert r.status_code == 429
        assert "Too many MFA attempts" in r.json()["detail"]


class TestSessionRefusals:
    @pytest.mark.anyio
    async def test_revoke_others_needs_to_know_which_session_is_the_caller(
        self, client, auth_headers_admin
    ):
        r = await client.post(
            "/api/v1/auth/sessions/revoke-others", headers=auth_headers_admin
        )

        assert r.status_code == 401
        assert "could not be identified" in r.json()["detail"]

    @pytest.mark.anyio
    async def test_a_cookie_logout_without_the_csrf_header_is_refused(self, client):
        """A cross-site form post cannot sign the browser out."""
        r = await client.post(
            "/api/v1/auth/logout",
            cookies={"opendrp_refresh": "a-refresh-token"},
        )

        assert r.status_code == 401
        assert "CSRF" in r.json()["detail"]

    @pytest.mark.anyio
    async def test_a_refresh_without_a_family_is_refused(self, client, test_admin):
        with patch.object(
            auth_router,
            "decode_token",
            return_value={"type": "refresh", "sub": str(test_admin.id)},
        ):
            r = await client.post(
                "/api/v1/auth/refresh", json={"refresh_token": "signed-but-famililess"}
            )

        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid token payload"


class TestSessionRevocation:
    @pytest.mark.anyio
    async def test_revoking_one_session_records_who_ended_it(
        self, client, test_admin, auth_headers_admin, db_session
    ):
        family = RefreshTokenFamily(
            id=uuid.uuid4(),
            family_id=uuid.uuid4(),
            user_id=test_admin.id,
            revoked=False,
        )
        db_session.add(family)
        await db_session.commit()

        r = await client.delete(
            f"/api/v1/auth/sessions/{family.family_id}", headers=auth_headers_admin
        )

        assert r.status_code == 204
        await db_session.refresh(family)
        assert family.revoked is True
        assert family.revoked_reason == "user_revoked"
        row = await _audit_row(db_session, "auth.session.revoked")
        assert row is not None
        assert row.details["scope"] == "single"

    @pytest.mark.anyio
    async def test_a_logout_with_an_unparsable_family_still_ends_the_browser_session(
        self, client
    ):
        """A token this build cannot read must not leave the cookies in place."""
        with patch.object(
            auth_router, "decode_token", return_value={"family_id": "not-a-uuid"}
        ):
            r = await client.post(
                "/api/v1/auth/logout", json={"refresh_token": "unreadable"}
            )

        assert r.status_code == 204
        assert r.cookies.get("opendrp_refresh") in (None, "")


class TestPasswordChangeInvalidation:
    """The old credential's sessions end with the credential."""

    @pytest.mark.anyio
    async def test_a_refresh_token_issued_before_the_change_is_refused(
        self, client, test_admin
    ):
        """Changing a password is what closes a leaked-session window."""
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": PASSWORD},
        )
        assert login.status_code == 200
        old_refresh = client.cookies.get("opendrp_refresh") or next(
            (
                header.split(";", 1)[0].split("=", 1)[1]
                for header in login.headers.get_list("set-cookie")
                if header.startswith("opendrp_refresh=")
            ),
            None,
        )
        assert old_refresh

        changed = await client.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": "FreshPass456!"},
            headers={"Authorization": f"Bearer {login.json()['access_token']}"},
        )
        assert changed.status_code == 200, changed.text

        replayed = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": old_refresh}
        )

        assert replayed.status_code == 401
        assert "revoked" in replayed.json()["detail"].lower()


class TestRefreshDurability:
    @pytest.mark.anyio
    async def test_a_rotation_that_cannot_be_committed_is_not_returned(
        self, client, test_admin
    ):
        """The new token is only a session once storage says it is."""
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": PASSWORD},
        )
        assert login.status_code == 200
        # The token is taken from the response rather than from the cookie jar:
        # the cookie is path- and ``Secure``-scoped for a browser, which a test
        # transport need not honour, and the body form is the same token a script
        # would present.
        refresh = client.cookies.get("opendrp_refresh") or next(
            (
                header.split(";", 1)[0].split("=", 1)[1]
                for header in login.headers.get_list("set-cookie")
                if header.startswith("opendrp_refresh=")
            ),
            None,
        )
        assert refresh

        with patch.object(AsyncSession, "commit", side_effect=RuntimeError("db down")):
            r = await client.post(
                "/api/v1/auth/refresh", json={"refresh_token": refresh}
            )

        assert r.status_code == 503
        assert "could not be committed" in r.json()["detail"]


class TestMfaRefusals:
    @pytest.mark.anyio
    async def test_setup_is_refused_while_the_factor_is_locked(
        self, client, test_admin, auth_headers_admin
    ):
        test_admin.mfa_locked_until = datetime.now(timezone.utc) + timedelta(minutes=5)

        r = await client.post(
            "/api/v1/auth/mfa/setup",
            json={"password": PASSWORD},
            headers=auth_headers_admin,
        )

        assert r.status_code == 429

    @pytest.mark.anyio
    async def test_qr_refuses_a_pending_secret_it_cannot_read(
        self, client, test_admin, auth_headers_admin
    ):
        test_admin.totp_secret = "ciphertext-from-another-installation"
        test_admin.totp_enabled_at = None
        test_admin.mfa_locked_until = None

        with patch.object(
            auth_router, "decrypt_value", side_effect=RuntimeError("no key")
        ):
            r = await client.get("/api/v1/auth/mfa/qr", headers=auth_headers_admin)

        assert r.status_code == 409
        assert "cannot be read" in r.json()["detail"]

    @pytest.mark.anyio
    async def test_enable_is_refused_while_the_factor_is_locked(
        self, client, test_admin, auth_headers_admin
    ):
        test_admin.totp_secret = "pending"
        test_admin.mfa_locked_until = datetime.now(timezone.utc) + timedelta(minutes=5)

        r = await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": PASSWORD, "code": "123456"},
            headers=auth_headers_admin,
        )

        assert r.status_code == 429

    @pytest.mark.anyio
    async def test_disable_is_refused_while_the_factor_is_locked(
        self, client, test_admin, auth_headers_admin
    ):
        test_admin.totp_enabled_at = datetime.now(timezone.utc)
        test_admin.mfa_locked_until = datetime.now(timezone.utc) + timedelta(minutes=5)

        r = await client.post(
            "/api/v1/auth/mfa/disable",
            json={"password": PASSWORD, "code": "123456"},
            headers=auth_headers_admin,
        )

        assert r.status_code == 429

    @pytest.mark.anyio
    async def test_disable_asks_for_the_code_after_verifying_the_password(
        self, client, test_admin, auth_headers_admin
    ):
        """A forgotten field is named, rather than reported as a wrong password."""
        test_admin.totp_enabled_at = datetime.now(timezone.utc)
        test_admin.mfa_locked_until = None

        r = await client.post(
            "/api/v1/auth/mfa/disable",
            json={"password": PASSWORD},
            headers=auth_headers_admin,
        )

        assert r.status_code == 400
        assert "code" in r.json()["detail"].lower()
