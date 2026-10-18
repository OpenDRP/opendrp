"""The admin CLI: what it refuses to do, and what it leaves in the trail.

Three findings meet here (``docs/internal/audit-2026-10-15_users-rbac_03``):

* USR-03 — ``reset`` used to set ``role = "admin"`` and ``is_active = True``
  unconditionally, so a support reset promoted a viewer and a lockout clear
  revived an account an administrator had deliberately deactivated. The tests
  below pin that no command changes role or activity without its own flag.
* USR-14 — the CLI required 8 characters while the API required 12, so the
  installation could be bootstrapped with a password its own API refused.
* USR-02 — none of the commands wrote an audit row. Each mutating subcommand now
  has exactly one, with ``details.source == "cli"`` and the target account, and
  the tests read it back from ``drp_audit_logs``.
"""

from __future__ import annotations

import io
import sys

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog

STRONG_PASSWORD = "StrongPass123!"
RESET_PASSWORD = "FreshPass456!"


def _silence(monkeypatch):
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    monkeypatch.setattr(sys, "stderr", io.StringIO())


def _raising_exit(monkeypatch):
    """A ``sys.exit`` that actually stops, so a refusal cannot fall through."""

    def _exit(code=0):
        raise SystemExit(code)

    monkeypatch.setattr(sys, "exit", _exit)


class TestValidators:
    def test_email_is_lowercased_and_trimmed(self):
        from scripts.manage_admin import _validate_email

        assert _validate_email("Admin@Example.COM") == "admin@example.com"
        assert _validate_email("a.b+tag@sub.domain.co.uk") == "a.b+tag@sub.domain.co.uk"

    @pytest.mark.parametrize(
        "bad",
        [
            "no-at-sign.com",
            "user@localhost",
            "a b@example.com",
            "",
            # Whitespace is refused rather than silently trimmed: an operator who
            # pastes a padded address should re-read it, not wonder which account
            # the command changed.
            " user@example.com ",
        ],
    )
    def test_email_refuses_malformed(self, bad, monkeypatch):
        from scripts.manage_admin import _validate_email

        _raising_exit(monkeypatch)
        _silence(monkeypatch)
        with pytest.raises(SystemExit) as exc_info:
            _validate_email(bad)
        assert exc_info.value.code == 2

    def test_password_uses_the_api_policy_not_a_weaker_copy(self, monkeypatch):
        """The API's 12-character rule is the CLI's rule (USR-14)."""
        from scripts.manage_admin import _validate_password

        _raising_exit(monkeypatch)
        _silence(monkeypatch)
        # 8 characters with an uppercase letter and a digit used to pass here.
        with pytest.raises(SystemExit) as exc_info:
            _validate_password("Abcdefg1")
        assert exc_info.value.code == 2
        # 11 characters still fail; the message states the API's minimum.
        with pytest.raises(SystemExit) as short:
            _validate_password("Abcdefgh12!")
        assert short.value.code == 2

    def test_password_accepts_what_the_api_accepts(self):
        from scripts.manage_admin import _validate_password

        assert _validate_password(STRONG_PASSWORD) == STRONG_PASSWORD
        assert _validate_password("Admin2024Extra!") == "Admin2024Extra!"

    def test_password_refuses_lowercase_only_and_no_digit(self, monkeypatch):
        from scripts.manage_admin import _validate_password

        _raising_exit(monkeypatch)
        _silence(monkeypatch)
        for weak in ("lowercaseonly1", "NoDigitsHereAtAll"):
            with pytest.raises(SystemExit) as exc_info:
                _validate_password(weak)
            assert exc_info.value.code == 2


class TestArgparseParser:
    """The real parser, so a documented flag cannot stop existing silently."""

    def _parser(self):
        from scripts.manage_admin import build_parser

        return build_parser()

    def test_parse_create(self):
        args = self._parser().parse_args(
            ["create", "-e", "a@b.com", "-p", STRONG_PASSWORD, "--force"]
        )
        assert args.command == "create"
        assert args.email == "a@b.com"
        assert args.force is True

    def test_parse_reset_defaults_change_nothing_else(self):
        args = self._parser().parse_args(["reset", "-e", "a@b.com", "-p", RESET_PASSWORD])
        assert args.role is None
        assert args.ensure_admin is False
        assert args.activate is False

    def test_parse_reset_explicit_role_and_activation(self):
        args = self._parser().parse_args(
            ["reset", "-e", "a@b.com", "-p", RESET_PASSWORD, "--role", "analyst", "--activate"]
        )
        assert args.role == "analyst"
        assert args.activate is True
        args = self._parser().parse_args(
            ["reset", "-e", "a@b.com", "-p", RESET_PASSWORD, "--ensure-admin"]
        )
        assert args.ensure_admin is True

    def test_parse_unlock_activation_flag(self):
        args = self._parser().parse_args(["unlock", "-e", "a@b.com", "--activate"])
        assert args.command == "unlock"
        assert args.activate is True

    def test_parse_list(self):
        args = self._parser().parse_args(["list"])
        assert args.command == "list"

    def test_create_missing_password_raises(self):
        with pytest.raises(SystemExit):
            self._parser().parse_args(["create", "-e", "a@b.com"])

    def test_bad_command_raises(self):
        with pytest.raises(SystemExit):
            self._parser().parse_args(["nope"])


@pytest.mark.anyio
class TestCreateAndResetLogic:
    async def test_find_user_returns_none_when_empty(self, db_session):
        from scripts.manage_admin import _find_user

        assert await _find_user(db_session, "ghost@local") is None

    async def test_create_new_admin_success(self, db_session, monkeypatch, capsys):
        from app.core.security import verify_password
        from app.models.user import User
        from scripts.manage_admin import cmd_create

        _raising_exit(monkeypatch)
        await cmd_create("newadmin@example.com", STRONG_PASSWORD)
        u = (
            await db_session.execute(
                select(User).where(User.email == "newadmin@example.com")
            )
        ).scalar_one()
        assert u.role == "admin"
        assert u.is_active is True
        assert verify_password(STRONG_PASSWORD, u.password_hash) is True


@pytest.mark.anyio
class TestRoleAndActivityAreExplicit:
    """USR-03: a password reset is not a promotion and not a revival."""

    async def _user(self, db_session, email: str, role: str = "viewer", active: bool = True):
        import uuid

        from app.core.security import hash_password
        from app.models.user import User

        user = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hash_password(STRONG_PASSWORD),
            role=role,
            is_active=active,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    async def test_reset_keeps_the_role_of_a_viewer(self, db_session, monkeypatch, capsys):
        from scripts.manage_admin import cmd_reset

        user = await self._user(db_session, "viewer-reset@example.com", role="viewer")
        _raising_exit(monkeypatch)
        await cmd_reset("viewer-reset@example.com", RESET_PASSWORD)

        await db_session.refresh(user)
        assert user.role == "viewer"
        assert user.is_active is True
        out = capsys.readouterr().out
        assert "viewer (unchanged)" in out

    async def test_reset_keeps_a_deactivated_account_deactivated(
        self, db_session, monkeypatch, capsys
    ):
        from scripts.manage_admin import cmd_reset

        user = await self._user(db_session, "offboarded@example.com", active=False)
        _raising_exit(monkeypatch)
        await cmd_reset("offboarded@example.com", RESET_PASSWORD)

        await db_session.refresh(user)
        assert user.is_active is False
        assert "(unchanged)" in capsys.readouterr().out

    async def test_activate_flag_is_what_revives_an_account(
        self, db_session, monkeypatch
    ):
        from scripts.manage_admin import cmd_reset

        user = await self._user(db_session, "revived@example.com", active=False)
        _raising_exit(monkeypatch)
        await cmd_reset("revived@example.com", RESET_PASSWORD, activate=True)

        await db_session.refresh(user)
        assert user.is_active is True

    async def test_ensure_admin_promotes_and_prints_the_change(
        self, db_session, monkeypatch, capsys
    ):
        from scripts.manage_admin import cmd_reset

        user = await self._user(db_session, "promoted@example.com", role="analyst")
        _raising_exit(monkeypatch)
        await cmd_reset("promoted@example.com", RESET_PASSWORD, ensure_admin=True)

        await db_session.refresh(user)
        assert user.role == "admin"
        assert "analyst -> admin" in capsys.readouterr().out

    async def test_explicit_role_flag_is_the_only_demotion_path(
        self, db_session, monkeypatch
    ):
        from scripts.manage_admin import cmd_reset

        # Two admins, so demoting one does not hit the last-admin invariant.
        await self._user(db_session, "other-admin@example.com", role="admin")
        user = await self._user(db_session, "demoted@example.com", role="admin")
        _raising_exit(monkeypatch)
        await cmd_reset("demoted@example.com", RESET_PASSWORD, role="viewer")

        await db_session.refresh(user)
        assert user.role == "viewer"

    async def test_refuses_to_demote_the_last_active_administrator(
        self, db_session, monkeypatch, capsys
    ):
        from scripts.manage_admin import cmd_reset

        user = await self._user(db_session, "only-admin@example.com", role="admin")
        _raising_exit(monkeypatch)
        with pytest.raises(SystemExit) as exc_info:
            await cmd_reset("only-admin@example.com", RESET_PASSWORD, role="viewer")
        assert exc_info.value.code == 5

        await db_session.refresh(user)
        assert user.role == "admin"
        assert "only active administrator" in capsys.readouterr().out

    async def test_unlock_does_not_reactivate_unless_asked(
        self, db_session, monkeypatch, capsys
    ):
        from scripts.manage_admin import cmd_unlock

        user = await self._user(db_session, "locked-off@example.com", active=False)
        _raising_exit(monkeypatch)
        await cmd_unlock("locked-off@example.com")

        await db_session.refresh(user)
        assert user.is_active is False
        assert "is_active:               False (unchanged)" in capsys.readouterr().out

        await cmd_unlock("locked-off@example.com", activate=True)
        await db_session.refresh(user)
        assert user.is_active is True

    async def test_create_force_keeps_a_deactivated_admin_deactivated(
        self, db_session, monkeypatch, capsys
    ):
        from scripts.manage_admin import cmd_create

        user = await self._user(
            db_session, "deactivated-admin@example.com", role="admin", active=False
        )
        _raising_exit(monkeypatch)
        await cmd_create("deactivated-admin@example.com", STRONG_PASSWORD, force=True)

        await db_session.refresh(user)
        assert user.is_active is False
        out = capsys.readouterr().out
        assert "active:   False (unchanged)" in out


@pytest.mark.anyio
class TestCliAudit:
    """USR-02: every command that changes an account leaves exactly one row."""

    async def _user(self, db_session, email: str, role: str = "viewer", active: bool = True):
        import uuid

        from app.core.security import hash_password
        from app.models.user import User

        user = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hash_password(STRONG_PASSWORD),
            role=role,
            is_active=active,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    async def _rows(self, db_session, action: str) -> list[AuditLog]:
        await db_session.rollback()
        return list(
            (
                await db_session.execute(
                    select(AuditLog)
                    .where(AuditLog.action == action)
                    .order_by(AuditLog.seq)
                )
            ).scalars()
        )

    async def test_create_writes_user_created(self, db_session, monkeypatch):
        from scripts.manage_admin import cmd_create

        _raising_exit(monkeypatch)
        await cmd_create("first-admin@example.com", STRONG_PASSWORD)

        rows = await self._rows(db_session, "user.created")
        assert len(rows) == 1
        row = rows[0]
        assert row.user_id is None
        assert row.details["source"] == "cli"
        assert row.details["actor"]
        assert row.details["target_email"] == "first-admin@example.com"
        assert row.details["role"] == "admin"
        assert row.entry_hash and row.seq > 0

    async def test_reset_writes_role_change_state(self, db_session, monkeypatch):
        from scripts.manage_admin import cmd_reset

        await self._user(db_session, "reset-audit@example.com", role="analyst")
        _raising_exit(monkeypatch)
        await cmd_reset("reset-audit@example.com", RESET_PASSWORD)

        rows = await self._rows(db_session, "user.password_reset")
        assert len(rows) == 1
        assert rows[0].details["method"] == "cli_reset"
        assert rows[0].details["role_changed"] is False

    async def test_unlock_writes_its_own_method(self, db_session, monkeypatch):
        from scripts.manage_admin import cmd_unlock

        await self._user(db_session, "unlock-audit@example.com")
        _raising_exit(monkeypatch)
        await cmd_unlock("unlock-audit@example.com")

        rows = await self._rows(db_session, "user.unlocked")
        assert len(rows) == 1
        assert rows[0].details["method"] == "cli_unlock"
        assert rows[0].details["source"] == "cli"

    async def test_onboarding_off_has_its_own_action(self, db_session, monkeypatch):
        from scripts.manage_admin import cmd_onboarding_off

        await self._user(db_session, "released@example.com")
        _raising_exit(monkeypatch)
        await cmd_onboarding_off("released@example.com")

        rows = await self._rows(db_session, "user.onboarding.cleared")
        assert len(rows) == 1
        assert rows[0].details["method"] == "cli_onboarding_off"

    async def test_mfa_off_records_the_factor_and_revokes_sessions(
        self, db_session, monkeypatch
    ):
        import uuid
        from datetime import datetime, timezone

        from app.models.token import RefreshTokenFamily
        from scripts.manage_admin import cmd_mfa_off

        user = await self._user(db_session, "lost-phone@example.com")
        db_session.add(
            RefreshTokenFamily(family_id=uuid.uuid4(), user_id=user.id, revoked=False)
        )
        await db_session.refresh(user)
        user.totp_secret = "encrypted"
        user.totp_enabled_at = datetime.now(timezone.utc)
        await db_session.commit()

        _raising_exit(monkeypatch)
        await cmd_mfa_off("lost-phone@example.com")

        rows = await self._rows(db_session, "user.mfa.reset")
        assert len(rows) == 1
        assert rows[0].details["method"] == "cli_mfa_off"
        assert rows[0].details["was_enabled"] is True
        assert rows[0].details["refresh_families_revoked"] == 1

    async def test_list_records_the_read_it_performed(self, db_session, monkeypatch):
        from scripts.manage_admin import cmd_list

        await self._user(db_session, "listed@example.com")
        _raising_exit(monkeypatch)
        await cmd_list()

        rows = await self._rows(db_session, "users.list")
        assert len(rows) == 1
        assert rows[0].details["method"] == "cli_list"


@pytest.mark.anyio
class TestOnboardingFlags:
    """Every credential this CLI sets on somebody's behalf is temporary.

    The operator who runs these commands types a password, so the CLI is the
    place where a shared secret is most likely to be created: it ends up in shell
    history, in a runbook, in a chat message. The account replaces it at the next
    sign-in, and the platform refuses it everywhere except the page that performs
    the change until then.
    """

    async def _user(self, db_session, email: str, role=None, **flags):
        import uuid

        from app.core.security import hash_password
        from app.models.user import User, UserRole

        user = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hash_password(STRONG_PASSWORD),
            role=role or UserRole.viewer,
            is_active=True,
            **flags,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    async def test_create_marks_the_password_temporary(
        self, db_session, monkeypatch, capsys
    ):
        from app.models.user import User
        from scripts.manage_admin import cmd_create

        _raising_exit(monkeypatch)
        await cmd_create("first@example.com", STRONG_PASSWORD)

        user = (
            await db_session.execute(
                select(User).where(User.email == "first@example.com")
            )
        ).scalar_one()
        assert user.must_change_password is True
        assert user.must_enrol_mfa is False
        # The operator is told what happens next, at the moment they need to know
        # it: the alternative is a support call about a password that "does not
        # get you into the platform".
        out = capsys.readouterr().out
        assert "temporary" in out
        assert "new password" in out

    async def test_reset_marks_the_password_temporary(
        self, db_session, monkeypatch, capsys
    ):
        from scripts.manage_admin import cmd_reset

        user = await self._user(db_session, "reset@example.com")
        assert user.must_change_password is False

        _raising_exit(monkeypatch)
        await cmd_reset("reset@example.com", RESET_PASSWORD)

        await db_session.refresh(user)
        assert user.must_change_password is True
        assert "temporary" in capsys.readouterr().out

    async def test_mfa_off_requires_a_new_factor(
        self, db_session, monkeypatch, capsys
    ):
        from datetime import datetime, timezone

        from scripts.manage_admin import cmd_mfa_off

        user = await self._user(
            db_session,
            "lostdevice@example.com",
            totp_secret="encrypted-placeholder",
            totp_enabled_at=datetime.now(timezone.utc),
        )
        _raising_exit(monkeypatch)
        await cmd_mfa_off("lostdevice@example.com")

        await db_session.refresh(user)
        assert user.totp_enabled_at is None
        # Recovery is not a downgrade: the cleared factor is owed again.
        assert user.must_enrol_mfa is True
        assert "required" in capsys.readouterr().out

    async def test_onboarding_off_releases_an_account_that_cannot_complete_it(
        self, db_session, monkeypatch, capsys
    ):
        from scripts.manage_admin import cmd_onboarding_off

        user = await self._user(
            db_session,
            "stuck@example.com",
            must_change_password=True,
            must_enrol_mfa=True,
        )
        _raising_exit(monkeypatch)
        await cmd_onboarding_off("stuck@example.com")

        await db_session.refresh(user)
        assert user.must_change_password is False
        assert user.must_enrol_mfa is False
        out = capsys.readouterr().out
        # The escape hatch says what it gave up, because the cost is real: the
        # password in force stays the one somebody else chose.
        assert "was_change_pw:    True" in out
        assert "nothing forces a" in out

    async def test_onboarding_off_fails_loudly_for_an_unknown_account(
        self, monkeypatch
    ):
        from scripts.manage_admin import cmd_onboarding_off

        # Raise rather than record: the real command stops at `sys.exit`, and a
        # stub that returns would let the code run on with a `None` user.
        _raising_exit(monkeypatch)
        with pytest.raises(SystemExit) as exc_info:
            await cmd_onboarding_off("ghost@example.com")
        assert exc_info.value.code == 4

    async def test_list_reports_what_each_account_owes(
        self, db_session, monkeypatch, capsys
    ):
        from datetime import datetime, timezone

        from scripts.manage_admin import cmd_list

        await self._user(
            db_session,
            "pending@example.com",
            must_change_password=True,
            must_enrol_mfa=True,
        )
        await self._user(
            db_session,
            "enrolled@example.com",
            totp_enabled_at=datetime.now(timezone.utc),
        )

        _raising_exit(monkeypatch)
        await cmd_list()
        out = capsys.readouterr().out
        assert "ONBOARDING" in out
        assert "password, mfa" in out
        # An operator answering a support call can see the factor state here: the
        # command used to report locks and failed attempts, and nothing about MFA.
        assert "enrolled@example.com" in out
        assert "yes" in out
        assert "manage_admin onboarding-off" in out

    async def test_list_explains_an_account_the_deployment_policy_is_holding(
        self, db_session, monkeypatch, capsys
    ):
        """The policy is not a flag on the account, so it has to be computed here.

        Without this the table would show an administrator with nothing owed and no
        explanation for being refused everywhere — and `onboarding-off`, which is
        the escape hatch for the account's own steps, does not release this one.
        """
        from app.core.config import settings
        from app.models.user import UserRole
        from scripts.manage_admin import cmd_list

        monkeypatch.setattr(settings, "REQUIRE_MFA_FOR_ADMINS", True)
        _raising_exit(monkeypatch)
        await self._user(db_session, "policyadmin@example.com", role=UserRole.admin)

        await cmd_list()
        out = capsys.readouterr().out

        assert "mfa (policy)" in out
        assert "REQUIRE_MFA_FOR_ADMINS" in out
