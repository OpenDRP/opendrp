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

from app.core import totp
from app.core.audit import AUDIT_ALLOWED_ACTIONS
from app.core.crypto import encrypt_value
from app.core.security import hash_password
from app.models.audit import AuditLog
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
