"""Second-factor tests: the RFC vectors, and the rules that make MFA worth having.

The rules being tested are the ones that decide whether a second factor actually
changes an attacker's options:

* a wrong password is still refused *before* a code is asked for, so the endpoint
  does not become an oracle for "this account has MFA";
* a wrong code counts towards the same lockout as a wrong password, because six
  digits is a small space;
* the code used to enrol cannot then be used to sign in, and a code cannot be
  replayed inside the accepted skew window;
* removing the factor needs the password *and* a live code, and an administrator
  cannot remove their own over the API.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.core import recovery_codes, totp
from app.core.audit import AUDIT_ALLOWED_ACTIONS
from app.core.crypto import encrypt_value
from app.core.security import hash_password
from app.models.audit import AuditLog
from app.models.token import RefreshTokenFamily
from app.models.user import User, UserRole

PASSWORD = "TestPass123!"

#: RFC 6238's SHA-1 test secret: the ASCII string "12345678901234567890".
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def _code_for(secret: str, step_offset: int = 0) -> str:
    return totp.code_at(secret, totp.current_step() + step_offset)


def _wrong_code(secret: str) -> str:
    """A code that is definitely not currently valid.

    Derived rather than hardcoded: a literal like "000000" has a one-in-a-million
    chance of being correct at the moment the test runs, and a flaky security test
    teaches people to re-run it rather than read it.
    """
    for candidate in range(0, 10):
        code = f"{candidate:06d}"
        if totp.verify(secret, code) is None:
            return code
    raise AssertionError("no invalid code found")  # pragma: no cover


class TestRfcVectors:
    """The implementation must be the algorithm, not an approximation of it."""

    @pytest.mark.parametrize(
        ("at", "expected"),
        [
            (59, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
            (20000000000, "353130"),
        ],
    )
    def test_sha1_vectors(self, at: int, expected: str):
        assert totp.code_at(RFC_SECRET, at // totp.STEP_SECONDS) == expected

    def test_a_secret_survives_the_formatting_a_human_types(self):
        spaced = " ".join(RFC_SECRET[i : i + 4] for i in range(0, len(RFC_SECRET), 4))
        assert totp.code_at(spaced.lower(), 1) == totp.code_at(RFC_SECRET, 1)

    def test_verify_returns_the_matching_step(self):
        step = totp.current_step()
        assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step)) == step

    def test_verify_accepts_one_step_of_clock_skew_either_way(self):
        now = 1_700_000_000.0
        step = totp.current_step(now)
        assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step - 1), at=now) == step - 1
        assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + 1), at=now) == step + 1
        assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + 3), at=now) is None

    def test_malformed_input_is_refused_rather_than_raising(self):
        assert totp.verify(RFC_SECRET, "") is None
        assert totp.verify(RFC_SECRET, "12345") is None
        assert totp.verify(RFC_SECRET, "abcdef") is None
        # A corrupt stored secret must deny the login, not break the endpoint.
        assert totp.verify("not-base32!", "123456") is None

    def test_provisioning_uri_carries_what_apps_need(self):
        uri = totp.provisioning_uri(RFC_SECRET, account="user@example.com", issuer="OpenDRP")
        assert uri.startswith("otpauth://totp/OpenDRP%3Auser%40example.com?")
        assert f"secret={RFC_SECRET}" in uri
        assert "issuer=" in uri and "period=30" in uri and "digits=6" in uri


class TestEnrolment:
    @pytest.mark.anyio
    async def test_setup_returns_a_secret_and_does_not_enable_anything(
        self, client, auth_headers_admin
    ):
        r = await client.post(
            "/api/v1/auth/mfa/setup",
            json={"password": PASSWORD},
            headers=auth_headers_admin,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["secret"] and body["otpauth_uri"]
        assert totp.verify(body["secret"], totp.code_at(body["secret"], totp.current_step())) is not None

        status = await client.get("/api/v1/auth/mfa", headers=auth_headers_admin)
        assert status.json() == {"enabled": False, "enabled_at": None}

    @pytest.mark.anyio
    async def test_pending_setup_can_be_rendered_as_svg_qr(self, client, auth_headers_admin):
        setup = await client.post(
            "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=auth_headers_admin
        )
        assert setup.status_code == 200
        qr = await client.get("/api/v1/auth/mfa/qr", headers=auth_headers_admin)
        assert qr.status_code == 200
        assert qr.headers["content-type"].startswith("image/svg+xml")
        assert qr.content.startswith(b"<?xml") or b"<svg" in qr.content[:500]

    @pytest.mark.anyio
    async def test_qr_requires_pending_setup(self, client, auth_headers_admin):
        qr = await client.get("/api/v1/auth/mfa/qr", headers=auth_headers_admin)
        assert qr.status_code == 409

    @pytest.mark.anyio
    async def test_setup_requires_the_password_not_just_a_session(
        self, client, auth_headers_admin
    ):
        r = await client.post(
            "/api/v1/auth/mfa/setup",
            json={"password": "NotThePassword1"},
            headers=auth_headers_admin,
        )
        assert r.status_code == 401

    @pytest.mark.anyio
    async def test_enable_rejects_a_code_that_does_not_match(self, client, auth_headers_admin):
        setup = await client.post(
            "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=auth_headers_admin
        )
        secret = setup.json()["secret"]

        r = await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": PASSWORD, "code": _wrong_code(secret)},
            headers=auth_headers_admin,
        )
        assert r.status_code == 401

        status = await client.get("/api/v1/auth/mfa", headers=auth_headers_admin)
        assert status.json()["enabled"] is False

    @pytest.mark.anyio
    async def test_enable_requires_a_pending_setup(self, client, auth_headers_admin):
        r = await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": PASSWORD, "code": "123456"},
            headers=auth_headers_admin,
        )
        assert r.status_code == 409

    @pytest.mark.anyio
    async def test_setup_is_refused_while_a_factor_is_active(self, client, auth_headers_admin):
        await _enrol(client, auth_headers_admin)

        r = await client.post(
            "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=auth_headers_admin
        )
        assert r.status_code == 409

    @pytest.mark.anyio
    async def test_endpoints_require_a_session(self, client):
        assert (await client.get("/api/v1/auth/mfa")).status_code == 401
        assert (
            await client.post("/api/v1/auth/mfa/setup", json={"password": PASSWORD})
        ).status_code == 401


class TestLoginEnforcement:
    @pytest.mark.anyio
    async def test_password_alone_still_works_without_a_factor(self, client, test_admin):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": PASSWORD},
        )
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_a_wrong_password_is_refused_before_a_code_is_requested(
        self, client, test_admin, auth_headers_admin
    ):
        await _enrol(client, auth_headers_admin)
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": "WrongPassword1"},
        )
        assert r.status_code == 401
        assert "MFA" not in r.json()["detail"]

    @pytest.mark.anyio
    async def test_login_without_a_code_says_a_code_is_required(
        self, client, test_admin, auth_headers_admin
    ):
        await _enrol(client, auth_headers_admin)
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": PASSWORD},
        )
        assert r.status_code == 401
        assert r.json()["detail"] == "MFA code required"

    @pytest.mark.anyio
    async def test_login_with_the_current_code_succeeds(
        self, client, test_admin, auth_headers_admin
    ):
        secret, _ = await _enrol(client, auth_headers_admin)
        r = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_admin.email,
                "password": PASSWORD,
                "totp_code": _code_for(secret, 1),
            },
        )
        assert r.status_code == 200
        assert r.json()["access_token"]

    @pytest.mark.anyio
    async def test_the_code_used_to_enrol_cannot_be_used_to_sign_in(
        self, client, test_admin, auth_headers_admin
    ):
        """Enrolment spends its code; otherwise watching the screen is enough.

        The exact code enrolment used is replayed, rather than one recomputed at
        this point: recomputing would make the test depend on where the 30-second
        step boundary happened to fall.
        """
        _, enrol_code = await _enrol(client, auth_headers_admin)
        r = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_admin.email,
                "password": PASSWORD,
                "totp_code": enrol_code,
            },
        )
        assert r.status_code == 401

    @pytest.mark.anyio
    async def test_a_code_cannot_be_replayed(self, client, test_admin, auth_headers_admin):
        secret, _ = await _enrol(client, auth_headers_admin)
        payload = {
            "email": test_admin.email,
            "password": PASSWORD,
            "totp_code": _code_for(secret, 1),
        }
        first = await client.post("/api/v1/auth/login", json=payload)
        assert first.status_code == 200
        second = await client.post("/api/v1/auth/login", json=payload)
        assert second.status_code == 401

    @pytest.mark.anyio
    async def test_wrong_codes_count_towards_the_lockout(
        self, client, test_admin, auth_headers_admin
    ):
        secret, _ = await _enrol(client, auth_headers_admin)
        wrong = _wrong_code(secret)
        for _ in range(5):
            r = await client.post(
                "/api/v1/auth/login",
                json={"email": test_admin.email, "password": PASSWORD, "totp_code": wrong},
            )
            assert r.status_code == 401

        # Five failures is the same threshold a wrong password carries; the
        # account is locked even though the password was right every time.
        locked = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_admin.email,
                "password": PASSWORD,
                "totp_code": _code_for(secret, 1),
            },
        )
        assert locked.status_code == 401

    @pytest.mark.anyio
    async def test_mfa_failures_are_audited(self, client, test_admin, db_session, auth_headers_admin):
        await _enrol(client, auth_headers_admin)
        await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": PASSWORD},
        )
        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "auth.mfa.failure")
            )
        ).scalars().all()
        assert rows, "a failed second-factor challenge must leave an audit record"
        assert rows[-1].details["reason"] == "code_missing"


class TestDisabling:
    @pytest.mark.anyio
    async def test_disable_requires_the_password_and_a_code(
        self, client, test_admin, auth_headers_admin
    ):
        secret, _ = await _enrol(client, auth_headers_admin)

        wrong_password = await client.post(
            "/api/v1/auth/mfa/disable",
            json={"password": "Nope12345", "code": _code_for(secret, 1)},
            headers=auth_headers_admin,
        )
        assert wrong_password.status_code == 401

        wrong_code = await client.post(
            "/api/v1/auth/mfa/disable",
            json={"password": PASSWORD, "code": _wrong_code(secret)},
            headers=auth_headers_admin,
        )
        assert wrong_code.status_code == 401

        ok = await client.post(
            "/api/v1/auth/mfa/disable",
            json={"password": PASSWORD, "code": _code_for(secret, 1)},
            headers=auth_headers_admin,
        )
        assert ok.status_code == 200
        assert ok.json()["enabled"] is False

        # And the factor is genuinely gone: password alone signs in again.
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": PASSWORD},
        )
        assert login.status_code == 200

    @pytest.mark.anyio
    async def test_disable_without_a_factor_is_a_conflict(self, client, auth_headers_admin):
        r = await client.post(
            "/api/v1/auth/mfa/disable",
            json={"password": PASSWORD, "code": "123456"},
            headers=auth_headers_admin,
        )
        assert r.status_code == 409


class TestAdministratorReset:
    @pytest.mark.anyio
    async def test_admin_can_clear_another_users_factor(
        self, client, test_admin, db_session, auth_headers_admin
    ):
        other = await _make_user_with_factor(db_session, "operator@example.com")
        family = RefreshTokenFamily(
            family_id=uuid.uuid4(),
            user_id=other.id,
            last_jti="old-jti",
            revoked=False,
        )
        db_session.add(family)
        other.mfa_recovery_codes = ["old-hash"]
        other.mfa_failed_attempts = 4
        other.mfa_locked_until = datetime.now(timezone.utc)
        await db_session.commit()

        r = await client.post(f"/api/v1/users/{other.id}/mfa/reset", headers=auth_headers_admin)
        assert r.status_code == 200

        await db_session.refresh(other)
        assert other.totp_secret is None and other.totp_enabled_at is None

        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "user.mfa.reset")
            )
        ).scalars().all()
        assert rows
        # The audited user is the administrator who acted, and the target is the
        # account whose factor was removed.
        assert str(rows[-1].user_id) == str(test_admin.id)
        assert rows[-1].details["target_user_id"] == str(other.id)
        assert rows[-1].details["was_enabled"] is True
        assert rows[-1].details["onboarding_required"] == ["mfa"]
        assert rows[-1].entry_hash
        assert other.mfa_recovery_codes is None
        assert other.mfa_failed_attempts == 0
        assert other.mfa_locked_until is None
        await db_session.refresh(family)
        assert family.revoked is True
        assert family.revoked_reason == "mfa_reset"
        assert rows[-1].details["refresh_families_revoked"] == 1
        assert str(rows[-1].user_id) == str(test_admin.id)
        assert rows[-1].details["target_user_id"] == str(other.id)

    @pytest.mark.anyio
    async def test_an_admin_cannot_clear_their_own_factor_over_the_api(
        self, client, test_admin, auth_headers_admin
    ):
        await _enrol(client, auth_headers_admin)
        r = await client.post(
            f"/api/v1/users/{test_admin.id}/mfa/reset", headers=auth_headers_admin
        )
        assert r.status_code == 409

    @pytest.mark.anyio
    async def test_a_non_admin_cannot_reset_anyones_factor(
        self, client, test_viewer, auth_headers_viewer
    ):
        r = await client.post(
            f"/api/v1/users/{test_viewer.id}/mfa/reset", headers=auth_headers_viewer
        )
        assert r.status_code == 403

    @pytest.mark.anyio
    async def test_reset_without_a_configured_factor_is_a_conflict(
        self, client, test_viewer, auth_headers_admin
    ):
        r = await client.post(
            f"/api/v1/users/{test_viewer.id}/mfa/reset", headers=auth_headers_admin
        )
        assert r.status_code == 409


class TestEnforcementGate:
    """`REQUIRE_MFA_FOR_ADMINS` makes the factor a condition, not a feature.

    Off by default, because an installation must not be able to lock its own
    administrator out. When it is on, the gate is a property of *admin routes*:
    the pages that fix the situation and the sign-in path itself must keep
    working, or the account has no way out except the CLI.
    """

    @pytest.mark.anyio
    async def test_off_by_default_so_an_admin_without_a_factor_still_works(
        self, client, auth_headers_admin
    ):
        r = await client.get("/api/v1/users", headers=auth_headers_admin)
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_admin_without_a_factor_is_refused_admin_routes(
        self, client, auth_headers_admin, monkeypatch
    ):
        from app.core.config import settings

        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)

        r = await client.get("/api/v1/users", headers=auth_headers_admin)
        assert r.status_code == 403
        # The marker, not the prose, is what the frontend keys on.
        assert "mfa_required" in r.json()["detail"]

    @pytest.mark.anyio
    async def test_the_refusal_is_audited(
        self, client, auth_headers_admin, db_session, monkeypatch
    ):
        from app.core.config import settings

        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)

        r = await client.get("/api/v1/users", headers=auth_headers_admin)
        assert r.status_code == 403

        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "auth.mfa.required")
            )
        ).scalars().all()
        assert rows
        assert rows[-1].details["path"] == "/api/v1/users"

    @pytest.mark.anyio
    async def test_an_enrolled_admin_passes_the_gate(
        self, client, auth_headers_admin, monkeypatch
    ):
        from app.core.config import settings

        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)
        await _enrol(client, auth_headers_admin)

        r = await client.get("/api/v1/users", headers=auth_headers_admin)
        assert r.status_code == 200

    @pytest.mark.anyio
    async def test_the_enrolment_endpoints_stay_reachable_behind_the_gate(
        self, client, auth_headers_admin, monkeypatch
    ):
        # If `/auth/mfa/*` were gated too, the gate would be a lockout: the one
        # page that clears it would itself be behind it.
        from app.core.config import settings

        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)

        assert (await client.get("/api/v1/auth/mfa", headers=auth_headers_admin)).status_code == 200
        secret, _ = await _enrol(client, auth_headers_admin)
        assert secret

    @pytest.mark.anyio
    async def test_the_gate_does_not_touch_non_admin_routes(
        self, client, auth_headers_viewer, monkeypatch
    ):
        from app.core.config import settings

        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)

        r = await client.get("/api/v1/assets", headers=auth_headers_viewer)
        assert r.status_code == 200


def test_every_mfa_action_is_in_the_audit_allowlist():
    for action in (
        "auth.mfa.setup_started",
        "auth.mfa.setup_failed",
        "auth.mfa.enrolled",
        "auth.mfa.disabled",
        "auth.mfa.success",
        "auth.mfa.failure",
        "auth.mfa.required",
        "user.mfa.reset",
    ):
        assert action in AUDIT_ALLOWED_ACTIONS


class TestRecoveryCodes:
    @pytest.mark.anyio
    async def test_enrolment_returns_codes_and_one_code_can_sign_in_once(
        self, client, test_admin, auth_headers_admin, db_session
    ):
        setup = await client.post(
            "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=auth_headers_admin
        )
        secret = setup.json()["secret"]
        enabled = await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": PASSWORD, "code": _code_for(secret)},
            headers=auth_headers_admin,
        )
        assert enabled.status_code == 200
        codes = enabled.json()["recovery_codes"]
        assert len(codes) == 10
        assert all(len(code) == 12 and code.isupper() for code in codes)

        login = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": PASSWORD, "recovery_code": codes[0]},
        )
        assert login.status_code == 200, login.text
        replay = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": PASSWORD, "recovery_code": codes[0]},
        )
        assert replay.status_code == 401
        await db_session.refresh(test_admin)
        assert len(test_admin.mfa_recovery_codes or []) == 9
        # New codes are HMAC digests, not bcrypt: ten bcrypt hashes cost ~2.3 s at
        # enrolment and up to ten comparisons to check one code.
        stored = test_admin.mfa_recovery_codes or []
        assert stored and all(not recovery_codes.is_bcrypt_hash(item) for item in stored)

    @pytest.mark.anyio
    async def test_a_bcrypt_code_from_an_earlier_release_still_signs_in(
        self, client, test_admin, auth_headers_admin, db_session
    ):
        """RWI-08: the primitive changed; nobody's printed list stopped working."""
        await _enrol(client, auth_headers_admin)
        bcrypt_code = "LEGACYCODE23"
        await db_session.refresh(test_admin)
        remaining = list(test_admin.mfa_recovery_codes or [])[1:]
        test_admin.mfa_recovery_codes = [*remaining, hash_password(bcrypt_code)]
        await db_session.commit()

        login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_admin.email,
                "password": PASSWORD,
                "recovery_code": bcrypt_code,
            },
        )
        assert login.status_code == 200, login.text

        await db_session.refresh(test_admin)
        left = test_admin.mfa_recovery_codes or []
        assert len(left) == 9, "the code that was used must be spent"
        assert all(not recovery_codes.is_bcrypt_hash(item) for item in left), (
            "the list is HMAC once the last bcrypt entry has been consumed"
        )

        replay = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_admin.email,
                "password": PASSWORD,
                "recovery_code": bcrypt_code,
            },
        )
        assert replay.status_code == 401, "a consumed bcrypt code must not verify again"

    @pytest.mark.anyio
    async def test_mfa_failure_budget_locks_even_missing_code(
        self, client, auth_headers_admin, test_admin, db_session
    ):
        await _enrol(client, auth_headers_admin)
        for _ in range(5):
            response = await client.post(
                "/api/v1/auth/login", json={"email": test_admin.email, "password": PASSWORD}
            )
            assert response.status_code == 401
        await db_session.refresh(test_admin)
        assert test_admin.mfa_locked_until is not None


class TestSessionsThatPredateTheFactor:
    """A refresh token minted before enrolment must not outlive the factor.

    The project map claims MFA cannot be skipped by a token minted before
    enrolment. An access token is short-lived, so the credential that matters is
    the refresh token: it mints access tokens for its whole lifetime without ever
    asking for a code, which would turn "the password leaked, so I turned on MFA"
    into a change the holder of the old session can ignore. Enrolment therefore
    ends every *other* session, in the same transaction as the factor itself.
    """

    @pytest.mark.anyio
    async def test_enrolment_ends_a_session_that_predates_the_factor(self, test_admin):
        from app.main import app
        from httpx import ASGITransport, AsyncClient

        async def _browser():
            browser = AsyncClient(transport=ASGITransport(app=app), base_url="http://t")
            login = await browser.post(
                "/api/v1/auth/login",
                json={"email": test_admin.email, "password": PASSWORD},
            )
            assert login.status_code == 200, login.text
            return browser, login

        holder, holder_login = await _browser()
        stale_browser, stale_login = await _browser()
        try:
            headers = {"Authorization": f"Bearer {holder_login.json()['access_token']}"}
            await _enrol(holder, headers)

            stale_refresh = stale_login.cookies.get("opendrp_refresh")
            assert stale_refresh
            stale = await stale_browser.post(
                "/api/v1/auth/refresh", json={"refresh_token": stale_refresh}
            )
            assert stale.status_code == 401, stale.text
            assert "revoked" in stale.json()["detail"].lower()

            # The browser that enrolled the factor keeps its session: it is the
            # one the account holder is sitting in front of.
            current = await holder.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": holder_login.cookies.get("opendrp_refresh")},
            )
            assert current.status_code == 200, current.text
        finally:
            await holder.aclose()
            await stale_browser.aclose()


class TestFactorAttemptBudget:
    """Every endpoint that checks a six-digit code spends the same budget.

    Six digits is a small space; the lockout only bounds it if *every* code check
    counts. The sign-in path does (`test_mfa_failure_budget_locks_even_missing_code`);
    these pin the two endpoints that used to check the counter without ever
    incrementing it.
    """

    @pytest.mark.anyio
    async def test_wrong_codes_on_disable_lock_the_account(
        self, client, auth_headers_admin, test_admin, db_session
    ):
        secret, _spent = await _enrol(client, auth_headers_admin)
        for _ in range(5):
            r = await client.post(
                "/api/v1/auth/mfa/disable",
                json={"password": PASSWORD, "code": _wrong_code(secret)},
                headers=auth_headers_admin,
            )
            assert r.status_code == 401, r.text

        await db_session.refresh(test_admin)
        assert test_admin.mfa_locked_until is not None
        assert test_admin.totp_enabled_at is not None, "guessing must not remove the factor"

        # The correct next code is refused by the lock, not accepted because the
        # password was right.
        blocked = await client.post(
            "/api/v1/auth/mfa/disable",
            json={"password": PASSWORD, "code": _code_for(secret, 1)},
            headers=auth_headers_admin,
        )
        assert blocked.status_code == 429, blocked.text

    @pytest.mark.anyio
    async def test_wrong_codes_on_recovery_code_rotation_lock_the_account(
        self, client, auth_headers_admin, test_admin, db_session
    ):
        secret, _spent = await _enrol(client, auth_headers_admin)
        await db_session.refresh(test_admin)
        original_codes = list(test_admin.mfa_recovery_codes or [])
        assert original_codes

        for _ in range(5):
            r = await client.post(
                "/api/v1/auth/mfa/recovery-codes/rotate",
                json={"password": PASSWORD, "code": _wrong_code(secret)},
                headers=auth_headers_admin,
            )
            assert r.status_code == 401, r.text

        await db_session.refresh(test_admin)
        assert test_admin.mfa_locked_until is not None

        blocked = await client.post(
            "/api/v1/auth/mfa/recovery-codes/rotate",
            json={"password": PASSWORD, "code": _code_for(secret, 1)},
            headers=auth_headers_admin,
        )
        assert blocked.status_code == 429, blocked.text
        await db_session.refresh(test_admin)
        assert test_admin.mfa_recovery_codes == original_codes


async def _enrol(client, headers) -> tuple[str, str]:
    """Complete enrolment; returns the secret and the code that was spent."""
    setup = await client.post(
        "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=headers
    )
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    enrol_code = _code_for(secret, 0)
    enabled = await client.post(
        "/api/v1/auth/mfa/enable",
        json={"password": PASSWORD, "code": enrol_code},
        headers=headers,
    )
    assert enabled.status_code == 200, enabled.text
    return secret, enrol_code


async def _make_user(db_session, email: str) -> User:
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(PASSWORD),
        role=UserRole.viewer,
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


async def _make_user_with_factor(db_session, email: str) -> User:
    """A user who already has a second factor, without going through enrolment."""
    user = await _make_user(db_session, email)
    user.totp_secret = encrypt_value(totp.generate_secret())
    user.totp_enabled_at = datetime.now(timezone.utc)
    await db_session.commit()
    await db_session.refresh(user)
    return user


async def _last_audit(db_session, action: str) -> AuditLog | None:
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


class TestEnrolmentEdges:
    """The second step of an enrolment that a client can reach by mistake.

    Every branch here answers a request that is well-formed and authenticated:
    enrolling twice, confirming without a code, confirming with the wrong
    password, and confirming after the pending secret is gone. The first three are
    what a retrying client produces; the last is what a database restore or a
    cleared column produces, and it must not look like a wrong code — the account
    holder has done nothing wrong and needs to be told to start again.
    """

    @pytest.mark.anyio
    async def test_enable_is_refused_once_a_factor_is_active(
        self, client, auth_headers_admin
    ):
        await _enrol(client, auth_headers_admin)

        again = await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": PASSWORD, "code": "123456"},
            headers=auth_headers_admin,
        )

        assert again.status_code == 409
        assert "already enabled" in again.json()["detail"]

    @pytest.mark.anyio
    async def test_enable_asks_for_the_code_before_checking_the_password(
        self, client, auth_headers_admin
    ):
        """The field a client forgot is named, rather than reported as a bad login."""
        setup = await client.post(
            "/api/v1/auth/mfa/setup",
            json={"password": PASSWORD},
            headers=auth_headers_admin,
        )
        assert setup.status_code == 200

        r = await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": PASSWORD},
            headers=auth_headers_admin,
        )

        assert r.status_code == 400
        assert "code" in r.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_a_wrong_password_at_the_second_step_is_audited(
        self, client, auth_headers_admin, db_session
    ):
        setup = await client.post(
            "/api/v1/auth/mfa/setup",
            json={"password": PASSWORD},
            headers=auth_headers_admin,
        )
        secret = setup.json()["secret"]

        r = await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": "NotThePassword1", "code": _code_for(secret)},
            headers=auth_headers_admin,
        )

        assert r.status_code == 401
        row = await _last_audit(db_session, "auth.mfa.setup_failed")
        assert row is not None, "a failed second step must leave a trail"
        assert row.details["reason"] == "invalid_password"

    @pytest.mark.anyio
    async def test_a_lost_pending_secret_says_to_start_the_enrolment_again(
        self, client, test_admin, auth_headers_admin, db_session
    ):
        setup = await client.post(
            "/api/v1/auth/mfa/setup",
            json={"password": PASSWORD},
            headers=auth_headers_admin,
        )
        assert setup.status_code == 200

        await db_session.refresh(test_admin)
        test_admin.totp_secret = None
        await db_session.commit()

        r = await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": PASSWORD, "code": "123456"},
            headers=auth_headers_admin,
        )

        assert r.status_code == 409
        assert "Start the enrolment" in r.json()["detail"]


class TestRecoveryCodeRotationEdges:
    """Rotation answers three different refusals, and one of them is a replay."""

    @pytest.mark.anyio
    async def test_rotation_requires_an_enabled_factor(
        self, client, auth_headers_admin
    ):
        r = await client.post(
            "/api/v1/auth/mfa/recovery-codes/rotate",
            json={"password": PASSWORD, "code": "123456"},
            headers=auth_headers_admin,
        )

        assert r.status_code == 409
        assert "second factor" in r.json()["detail"].lower()

    @pytest.mark.anyio
    async def test_rotation_with_the_wrong_password_is_refused_and_audited(
        self, client, auth_headers_admin, db_session
    ):
        await _enrol(client, auth_headers_admin)

        r = await client.post(
            "/api/v1/auth/mfa/recovery-codes/rotate",
            json={"password": "Nope12345", "code": "000000"},
            headers=auth_headers_admin,
        )

        assert r.status_code == 401
        row = await _last_audit(db_session, "auth.mfa.failure")
        assert row is not None
        assert row.details["reason"] == "invalid_password_on_recovery_codes"

    @pytest.mark.anyio
    async def test_rotation_cannot_replay_the_code_that_enrolled_the_factor(
        self, client, auth_headers_admin
    ):
        """The enrolment code is spent; rotating with it must not mint a new set."""
        _secret, enrol_code = await _enrol(client, auth_headers_admin)

        r = await client.post(
            "/api/v1/auth/mfa/recovery-codes/rotate",
            json={"password": PASSWORD, "code": enrol_code},
            headers=auth_headers_admin,
        )

        assert r.status_code == 401
        assert r.json()["detail"] == "Invalid MFA code"

    @pytest.mark.anyio
    async def test_rotation_replaces_every_code_and_records_the_change(
        self, client, auth_headers_admin, db_session
    ):
        secret, _enrol_code = await _enrol(client, auth_headers_admin)

        r = await client.post(
            "/api/v1/auth/mfa/recovery-codes/rotate",
            json={"password": PASSWORD, "code": _code_for(secret, 1)},
            headers=auth_headers_admin,
        )

        assert r.status_code == 200
        assert len(r.json()["codes"]) == 10
        row = await _last_audit(db_session, "auth.mfa.recovery_codes.rotated")
        assert row is not None
        assert row.details["count"] == 10
