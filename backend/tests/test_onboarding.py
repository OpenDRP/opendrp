"""Credential onboarding: what happens when somebody else chose your credentials.

Two situations produce this state, and both used to leave an account the way an
administrator left it rather than the way its owner needed it:

* a password assigned *for* the holder — the account was created over the API, an
  administrator reset it, or the CLI set it. That password is a shared secret:
  whoever typed it, and anything that recorded the request, still holds it;
* a second factor removed *for* the holder — the administrator reset endpoint or
  the CLI recovery command. Clearing a factor and leaving it cleared turns
  recovery into a permanent downgrade.

The rules pinned here are the ones that make the flags worth having:

* every path that assigns a credential on somebody's behalf sets them, and no
  other path does — the demo seed and the test fixtures stay usable;
* while a step is pending every authenticated route is refused except the ones
  that complete it, and the *order* of the steps is enforced by the server: the
  enrolment endpoints re-check the password, so a factor must not be attached
  while a temporary password is in force;
* the refusal is a structured log line and deliberately not an audit row, because
  the state it reports was already audited when the administrator created it, and a
  row per refused request from a client that is merely following instructions is
  how an audit table stops being read;
* a step clears only by evidence — the endpoint that performs it, or a verified
  code from the new factor — never by intent, so an abandoned enrolment leaves the
  requirement standing;
* the deployment-wide admin policy (``REQUIRE_MFA_FOR_ADMINS``) is a *step of this
  flow*, not a filter on admin pages: an administrator who has no factor is refused
  everywhere but the enrolment page and is asked at sign-in, because "the account
  owes a credential" is one situation whichever reason put it there. It keeps its
  own marker and its own audit action, because there the refusal itself is the
  security signal and folding it into "account is not onboarded" would delete it.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.core import totp
from app.core.config import settings
from app.core.logging_config import configure_logging
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.token import RefreshTokenFamily
from app.models.user import User, UserRole

PASSWORD = "TestPass123!"
NEW_PASSWORD = "FreshPass456!"

#: The route every "is this account still refused?" assertion uses: it is a
#: reader-level endpoint, so a refusal there is the gate and not a role check.
GATED_ROUTE = "/api/v1/dashboard/stats"


def _code_for(secret: str, step_offset: int = 0) -> str:
    return totp.code_at(secret, totp.current_step() + step_offset)


def _headers(user: User) -> dict:
    token, _ = create_access_token({"sub": str(user.id), "role": str(user.role)})
    return {"Authorization": f"Bearer {token}"}


async def _user_with_flags(
    db_session,
    email: str,
    *,
    password: bool = False,
    mfa: bool = False,
    role: UserRole = UserRole.viewer,
) -> User:
    """A user in the state an administrator action leaves behind."""
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(PASSWORD),
        role=role,
        is_active=True,
        must_change_password=password,
        must_enrol_mfa=mfa,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


async def _audit_actions(db_session) -> list[str]:
    rows = (await db_session.execute(select(AuditLog.action))).scalars().all()
    return list(rows)


class TestFlagsFromAdministratorActions:
    """The flag is a fact about how a credential came to exist."""

    @pytest.mark.anyio
    async def test_creating_a_user_marks_the_password_as_temporary(
        self, client, auth_headers_admin
    ):
        r = await client.post(
            "/api/v1/users",
            json={"email": "newcomer@example.com", "password": PASSWORD, "role": "analyst"},
            headers=auth_headers_admin,
        )
        assert r.status_code == 201, r.text
        assert r.json()["must_change_password"] is True
        # Nothing about the second factor is implied by creating an account: it is
        # the password that the administrator chose.
        assert r.json()["must_enrol_mfa"] is False

    @pytest.mark.anyio
    async def test_resetting_a_password_marks_it_temporary_too(
        self, client, db_session, auth_headers_admin
    ):
        created = await client.post(
            "/api/v1/users",
            json={"email": "reset@example.com", "password": PASSWORD, "role": "analyst"},
            headers=auth_headers_admin,
        )
        target_id = created.json()["id"]

        r = await client.put(
            f"/api/v1/users/{target_id}",
            json={"new_password": NEW_PASSWORD},
            headers=auth_headers_admin,
        )
        assert r.status_code == 200, r.text
        assert r.json()["must_change_password"] is True

        # The audit row names the obligation, not just the new hash: a reader
        # asking "what is this account expected to do next" gets an answer, and
        # the reset and the requirement cannot drift apart in the trail.
        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "user.password_reset")
            )
        ).scalars().all()
        assert rows[-1].details["onboarding_required"] == ["password"]

    @pytest.mark.anyio
    async def test_clearing_a_factor_requires_the_owner_to_enrol_again(
        self, client, db_session, auth_headers_admin
    ):
        user = await _user_with_flags(db_session, "lostphone@example.com")
        user.totp_secret = "encrypted-placeholder"
        user.totp_enabled_at = datetime.now(timezone.utc)
        await db_session.commit()

        r = await client.post(f"/api/v1/users/{user.id}/mfa/reset", headers=auth_headers_admin)
        assert r.status_code == 200, r.text
        await db_session.refresh(user)
        assert user.totp_enabled_at is None
        assert user.must_enrol_mfa is True

        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "user.mfa.reset")
            )
        ).scalars().all()
        assert rows[-1].details["onboarding_required"] == ["mfa"]


class TestTheGate:
    """Refused everywhere except the page that fixes it."""

    @pytest.mark.anyio
    async def test_a_pending_password_refuses_the_platform(
        self, client, db_session
    ):
        user = await _user_with_flags(db_session, "pending@example.com", password=True)

        r = await client.get(GATED_ROUTE, headers=_headers(user))
        assert r.status_code == 403, r.text
        assert "onboarding_required" in r.json()["detail"]

    @pytest.mark.anyio
    async def test_the_endpoints_that_fix_it_stay_reachable(self, client, db_session):
        user = await _user_with_flags(db_session, "reachable@example.com", password=True)
        headers = _headers(user)

        assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200
        assert (await client.get("/api/v1/auth/mfa", headers=headers)).status_code == 200
        # Reachable means "not refused by the gate": a wrong current password is
        # the endpoint's own answer, which is the proof it ran at all.
        wrong_password = await client.post(
            "/api/v1/auth/password",
            json={"current_password": "NotThePassword1", "new_password": NEW_PASSWORD},
            headers=headers,
        )
        assert wrong_password.status_code == 401
        assert "onboarding_required" not in wrong_password.text

    @pytest.mark.anyio
    async def test_the_factor_step_is_shut_until_the_password_step_is_done(
        self, client, db_session
    ):
        user = await _user_with_flags(
            db_session, "bothsteps@example.com", password=True, mfa=True
        )
        headers = _headers(user)

        setup = await client.post(
            "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=headers
        )
        assert setup.status_code == 403
        assert "onboarding_required" in setup.json()["detail"]

    @pytest.mark.anyio
    async def test_a_pending_factor_refuses_the_platform_and_opens_its_own_step(
        self, client, db_session
    ):
        user = await _user_with_flags(db_session, "refactor@example.com", mfa=True)
        headers = _headers(user)

        assert (await client.get(GATED_ROUTE, headers=headers)).status_code == 403
        setup = await client.post(
            "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=headers
        )
        assert setup.status_code == 200, setup.text

    @pytest.mark.anyio
    async def test_the_refusal_is_a_log_line_and_not_an_audit_row(
        self, client, db_session, capsys
    ):
        """The one place this gate differs from the admin second-factor gate.

        The state it reports was audited when the administrator created it, and
        this is the expected consequence of that state — a row per refused request
        would be noise a reader has to filter out to find the original action.
        """
        # Re-bind the renderer to the stream this test captures: the logger holds
        # the stream it was configured with, which is the one pytest replaced.
        configure_logging(force=True)
        user = await _user_with_flags(db_session, "quietlog@example.com", password=True)
        r = await client.get(GATED_ROUTE, headers=_headers(user))
        assert r.status_code == 403

        assert not any(
            action.startswith("auth.onboarding") for action in await _audit_actions(db_session)
        )

        events = [
            json.loads(line)
            for line in capsys.readouterr().out.splitlines()
            if line.strip().startswith("{")
        ]
        matches = [e for e in events if e.get("event") == "credential_onboarding_required"]
        assert len(matches) == 1
        assert matches[0]["details"]["steps"] == ["password"]
        assert matches[0]["details"]["path"] == GATED_ROUTE

    @pytest.mark.anyio
    async def test_the_deployment_policy_keeps_its_own_marker_and_audit_action(
        self, client, db_session, monkeypatch
    ):
        """`REQUIRE_MFA_FOR_ADMINS` is not the same fact as a cleared factor.

        It refuses the request, it is audited, and it must not start masquerading as
        "this account owes a credential": an administrator acting without a second
        factor is exactly what that gate exists to put in the trail, and the marker
        is what the client routes on. The refusal is no longer limited to admin
        routes — see `TestTheDeploymentPolicyIsAStep` — but which *reason* refused
        is still reported separately, and that is what this pins.
        """
        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)
        admin = await _user_with_flags(
            db_session, "policyadmin@example.com", role=UserRole.admin
        )

        r = await client.get("/api/v1/users", headers=_headers(admin))
        assert r.status_code == 403
        assert "mfa_required" in r.json()["detail"]
        assert "onboarding_required" not in r.json()["detail"]

        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "auth.mfa.required")
            )
        ).scalars().all()
        assert rows and rows[-1].details["path"] == "/api/v1/users"
        # And it did not quietly set the account flag: the policy is a property of
        # the deployment, not of the account.
        await db_session.refresh(admin)
        assert admin.must_enrol_mfa is False


class TestTheDeploymentPolicyIsAStep:
    """`REQUIRE_MFA_FOR_ADMINS` obliges an account, it does not filter pages.

    The policy used to be enforced only on admin routes, which meant an
    administrator who turned it on was asked for a second factor the first time
    they happened to open an admin screen — and could browse the rest of the
    platform in the meantime. It is the same obligation as a temporary password, so
    it is the same gate, the same page and the same moment: sign-in. What it keeps
    to itself is the marker and the audit row, because there the refusal is the
    security signal rather than the consequence of an administrator's own action.
    """

    @pytest.mark.anyio
    async def test_an_admin_without_a_factor_is_refused_until_it_is_enrolled(
        self, client, db_session, monkeypatch
    ):
        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)
        admin = await _user_with_flags(db_session, "stepless@example.com", role=UserRole.admin)
        headers = _headers(admin)

        # A reader-level route, not an admin one: the point of the change is that
        # there is nowhere else to go and browse.
        refused = await client.get(GATED_ROUTE, headers=headers)
        assert refused.status_code == 403
        assert "mfa_required" in refused.json()["detail"]

        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "auth.mfa.required")
            )
        ).scalars().all()
        assert rows and rows[-1].details["path"] == GATED_ROUTE
        assert rows[-1].details["reason"] == "require_mfa_for_admins"
        # The role is the value, not the enum's repr: a detail written as
        # `"UserRole.admin"` matches no rule anyone would write against it.
        assert rows[-1].details["role"] == "admin"

        # The enrolment endpoints are the way out, and nothing else is open — the
        # password endpoint included, which is harmless but not needed here.
        assert (await client.get("/api/v1/assets", headers=headers)).status_code == 403

        setup = await client.post(
            "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=headers
        )
        assert setup.status_code == 200, setup.text
        secret = setup.json()["secret"]

        # Starting an enrolment is not enrolling: the account is still refused.
        assert (await client.get(GATED_ROUTE, headers=headers)).status_code == 403

        enabled = await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": PASSWORD, "code": _code_for(secret)},
            headers=headers,
        )
        assert enabled.status_code == 200, enabled.text

        # And the requirement clears itself: it was never a flag on the account.
        await db_session.refresh(admin)
        assert admin.must_enrol_mfa is False
        assert (await client.get(GATED_ROUTE, headers=headers)).status_code == 200
        me = await client.get("/api/v1/auth/me", headers=headers)
        assert me.json()["mfa_required_by_policy"] is False

    @pytest.mark.anyio
    async def test_the_sign_in_response_carries_the_requirement(
        self, client, db_session, monkeypatch
    ):
        """The client has to know before it asks for a page that will be refused.

        Without this the operator signs in, sees the dashboard, and discovers the
        requirement from a `403` on whichever page they open first — which is what
        made the policy look like a permissions problem rather than a step.
        """
        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)
        admin = await _user_with_flags(db_session, "signin-admin@example.com", role=UserRole.admin)
        analyst = await _user_with_flags(
            db_session, "signin-analyst@example.com", role=UserRole.analyst
        )

        login = await client.post(
            "/api/v1/auth/login", json={"email": admin.email, "password": PASSWORD}
        )
        assert login.status_code == 200, login.text
        assert login.json()["user"]["mfa_required_by_policy"] is True

        # Administrators only: the policy exists for the account that can create
        # users and change settings, not for everyone who can read an alert list.
        analyst_login = await client.post(
            "/api/v1/auth/login", json={"email": analyst.email, "password": PASSWORD}
        )
        assert analyst_login.status_code == 200, analyst_login.text
        assert analyst_login.json()["user"]["mfa_required_by_policy"] is False

    @pytest.mark.anyio
    async def test_nothing_is_required_when_the_installation_does_not_ask(
        self, client, db_session
    ):
        admin = await _user_with_flags(db_session, "unpoliced@example.com", role=UserRole.admin)

        me = await client.get("/api/v1/auth/me", headers=_headers(admin))
        assert me.status_code == 200
        assert me.json()["mfa_required_by_policy"] is False
        assert (await client.get(GATED_ROUTE, headers=_headers(admin))).status_code == 200

    @pytest.mark.anyio
    async def test_a_temporary_password_is_still_the_first_step(
        self, client, db_session, monkeypatch
    ):
        """Both obligations can land on one account, and the order is the server's.

        The factor must not be bound to a password its owner is about to discard,
        and the enrolment endpoints re-check the password for exactly that reason.
        """
        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)
        admin = await _user_with_flags(
            db_session, "fresh-admin@example.com", password=True, role=UserRole.admin
        )
        headers = _headers(admin)

        refused = await client.get(GATED_ROUTE, headers=headers)
        assert refused.status_code == 403
        # The account's own obligation is the one reported, and the trail for it is
        # the administrator action that created it, not this refusal.
        assert "onboarding_required" in refused.json()["detail"]
        assert "mfa_required" not in refused.json()["detail"]
        assert (
            await client.post(
                "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=headers
            )
        ).status_code == 403

        changed = await client.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            headers=headers,
        )
        assert changed.status_code == 200, changed.text
        # The session the change hands back already knows what is left, so the
        # operator goes to the enrolment step instead of the dashboard.
        assert changed.json()["user"]["must_change_password"] is False
        assert changed.json()["user"]["mfa_required_by_policy"] is True

        new_headers = {"Authorization": f"Bearer {changed.json()['access_token']}"}
        assert (await client.get(GATED_ROUTE, headers=new_headers)).status_code == 403
        assert (
            await client.post(
                "/api/v1/auth/mfa/setup",
                json={"password": NEW_PASSWORD},
                headers=new_headers,
            )
        ).status_code == 200

    @pytest.mark.anyio
    async def test_an_enrolled_admin_is_not_asked_at_all(
        self, client, db_session, monkeypatch
    ):
        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)
        admin = await _user_with_flags(db_session, "enrolled@example.com", role=UserRole.admin)
        headers = _headers(admin)

        setup = await client.post(
            "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=headers
        )
        await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": PASSWORD, "code": _code_for(setup.json()["secret"])},
            headers=headers,
        )

        # A signed-in administrator with a factor: the policy costs them one extra
        # field on the sign-in form and nothing else.
        assert (await client.get(GATED_ROUTE, headers=headers)).status_code == 200
        me = await client.get("/api/v1/auth/me", headers=headers)
        assert me.json()["mfa_required_by_policy"] is False


class TestChangingThePassword:
    """The only way an account holder gets to choose their own password."""

    @pytest.mark.anyio
    async def test_the_owner_replaces_it_and_the_platform_opens(self, client, db_session):
        user = await _user_with_flags(db_session, "owner@example.com", password=True)
        old_headers = _headers(user)
        assert (await client.get(GATED_ROUTE, headers=old_headers)).status_code == 403

        r = await client.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            headers=old_headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["user"]["must_change_password"] is False
        assert body["access_token"]

        await db_session.refresh(user)
        assert user.must_change_password is False

        # The returned token is a working session, which is what keeps the
        # onboarding page usable: the change revoked the old refresh cookie.
        new_headers = {"Authorization": f"Bearer {body['access_token']}"}
        assert (await client.get(GATED_ROUTE, headers=new_headers)).status_code == 200

        # And the new password is the one that signs in.
        login = await client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": NEW_PASSWORD},
        )
        assert login.status_code == 200
        assert (
            await client.post(
                "/api/v1/auth/login", json={"email": user.email, "password": PASSWORD}
            )
        ).status_code == 401

    @pytest.mark.anyio
    async def test_the_change_ends_every_other_session(self, client, db_session):
        user = await _user_with_flags(db_session, "sessions@example.com", password=True)
        stale = RefreshTokenFamily(
            id=uuid.uuid4(),
            family_id=uuid.uuid4(),
            user_id=user.id,
            last_jti="stale-jti",
            last_issued_at=datetime.now(timezone.utc),
            revoked=False,
        )
        db_session.add(stale)
        await db_session.commit()

        r = await client.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
            headers=_headers(user),
        )
        assert r.status_code == 200, r.text

        await db_session.refresh(stale)
        assert stale.revoked is True
        assert stale.revoked_reason == "password_change"

        # The session issued by the change itself is not revoked: a client that had
        # just rotated its password would otherwise be signed out by its own action.
        families = (
            await db_session.execute(
                select(RefreshTokenFamily).where(RefreshTokenFamily.user_id == user.id)
            )
        ).scalars().all()
        live = [f for f in families if not f.revoked]
        assert len(live) == 1

        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "auth.password.changed")
            )
        ).scalars().all()
        assert rows[-1].details["was_required"] is True
        assert rows[-1].details["refresh_families_revoked"] == 1

    @pytest.mark.anyio
    async def test_a_wrong_current_password_is_refused_and_audited(self, client, db_session):
        user = await _user_with_flags(db_session, "wrongcurrent@example.com", password=True)

        r = await client.post(
            "/api/v1/auth/password",
            json={"current_password": "NotThePassword1", "new_password": NEW_PASSWORD},
            headers=_headers(user),
        )
        assert r.status_code == 401

        await db_session.refresh(user)
        assert user.must_change_password is True
        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "auth.password.change_failed")
            )
        ).scalars().all()
        assert rows[-1].details["reason"] == "invalid_current_password"

    @pytest.mark.anyio
    async def test_choosing_the_same_password_is_not_a_change(self, client, db_session):
        user = await _user_with_flags(db_session, "sameagain@example.com", password=True)

        r = await client.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": PASSWORD},
            headers=_headers(user),
        )
        assert r.status_code == 409

        await db_session.refresh(user)
        assert user.must_change_password is True

    @pytest.mark.anyio
    async def test_the_strength_rules_apply_to_the_new_password(self, client, db_session):
        user = await _user_with_flags(db_session, "weak@example.com", password=True)

        for weak in ("short", "alllowercase1", "NoDigitsHere"):
            r = await client.post(
                "/api/v1/auth/password",
                json={"current_password": PASSWORD, "new_password": weak},
                headers=_headers(user),
            )
            assert r.status_code == 422, (weak, r.text)

    @pytest.mark.anyio
    async def test_the_endpoint_requires_a_session(self, client):
        r = await client.post(
            "/api/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        )
        assert r.status_code == 401


class TestEnrolmentClearsTheRequirement:
    """Cleared by evidence, never by intent."""

    @pytest.mark.anyio
    async def test_a_verified_factor_clears_the_requirement(self, client, db_session):
        user = await _user_with_flags(db_session, "enrolling@example.com", mfa=True)
        headers = _headers(user)
        assert (await client.get(GATED_ROUTE, headers=headers)).status_code == 403

        setup = await client.post(
            "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=headers
        )
        assert setup.status_code == 200, setup.text
        secret = setup.json()["secret"]

        # A started enrolment is not a factor: the platform stays closed.
        await db_session.refresh(user)
        assert user.must_enrol_mfa is True
        assert (await client.get(GATED_ROUTE, headers=headers)).status_code == 403

        enabled = await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": PASSWORD, "code": _code_for(secret)},
            headers=headers,
        )
        assert enabled.status_code == 200, enabled.text

        await db_session.refresh(user)
        assert user.must_enrol_mfa is False
        assert (await client.get(GATED_ROUTE, headers=headers)).status_code == 200

        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "auth.mfa.enrolled")
            )
        ).scalars().all()
        assert rows[-1].details["was_required"] is True

    @pytest.mark.anyio
    async def test_a_voluntary_enrolment_reports_that_nothing_was_required(
        self, client, db_session
    ):
        user = await _user_with_flags(db_session, "voluntary@example.com")
        headers = _headers(user)

        setup = await client.post(
            "/api/v1/auth/mfa/setup", json={"password": PASSWORD}, headers=headers
        )
        assert setup.status_code == 200, setup.text
        enabled = await client.post(
            "/api/v1/auth/mfa/enable",
            json={"password": PASSWORD, "code": _code_for(setup.json()["secret"])},
            headers=headers,
        )
        assert enabled.status_code == 200, enabled.text

        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "auth.mfa.enrolled")
            )
        ).scalars().all()
        # The two enrolments look identical in the trail except for this, which is
        # what tells a reader whether a recovery was completed or hardening began.
        assert rows[-1].details["was_required"] is False
