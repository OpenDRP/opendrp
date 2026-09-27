import argparse
import re

import pytest

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_email_inline(email: str) -> bool:
    return bool(EMAIL_RE.match(email))


class TestValidators:
    @pytest.mark.parametrize(
        "email,ok",
        [
            ("admin@example.com", True),
            ("A.B+tag@sub.domain.co.uk", True),
            ("no-at-sign.com", False),
            ("user@localhost", False),
            (" user@example.com ", False),
            ("", False),
            ("@example.com", False),
            ("user@", False),
            ("user@.com", False),
        ],
    )
    def test_email_regex(self, email, ok):
        assert _validate_email_inline(email) is ok

    def test_password_short_less_than_8(self):
        from scripts.manage_admin import _validate_password
        with pytest.raises(SystemExit) as exc_info:
            import sys
            import io
            old = sys.stdout, sys.stderr
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()
            try:
                _validate_password("1234567")
            finally:
                sys.stdout, sys.stderr = old
        assert exc_info.value.code == 2

    def test_password_8_plus_accepted(self):
        from scripts.manage_admin import _validate_password
        assert _validate_password("Abcdefg1") == "Abcdefg1"
        assert _validate_password("Admin2024!") == "Admin2024!"


class TestArgparseParser:
    def _parser(self):
        from scripts.manage_admin import main as _unused  # noqa: F401
        parser = argparse.ArgumentParser(prog="manage_admin")
        sub = parser.add_subparsers(dest="command", required=True)
        pc = sub.add_parser("create")
        pc.add_argument("-e", "--email", required=True)
        pc.add_argument("-p", "--password", required=True)
        pc.add_argument("-f", "--force", action="store_true")
        pr = sub.add_parser("reset")
        pr.add_argument("-e", "--email", required=True)
        pr.add_argument("-p", "--password", required=True)
        sub.add_parser("list")
        return parser

    def test_parse_create(self):
        args = self._parser().parse_args(
            ["create", "-e", "a@b.com", "-p", "passw0rd!", "--force"]
        )
        assert args.command == "create"
        assert args.email == "a@b.com"
        assert args.force is True

    def test_parse_reset(self):
        args = self._parser().parse_args(["reset", "-e", "a@b.com", "-p", "p1234567"])
        assert args.command == "reset"
        assert args.password == "p1234567"

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
        import sys
        from app.core.security import verify_password
        from scripts.manage_admin import cmd_create
        from app.models.user import User
        from sqlalchemy import select

        exit_codes = []

        def _fake_exit(code=0):
            exit_codes.append(code)

        monkeypatch.setattr(sys, "exit", _fake_exit)
        await cmd_create("newadmin@example.com", "Passw0rd!")
        if exit_codes and exit_codes[-1] != 0:
            pytest.fail("create exited with code " + str(exit_codes[-1]))
        u = (await db_session.execute(
            select(User).where(User.email == "newadmin@example.com")
        )).scalar_one()
        assert u.role == "admin"
        assert u.is_active is True
        assert verify_password("Passw0rd!", u.password_hash) is True


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
            password_hash=hash_password("Passw0rd!"),
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
        import sys

        from app.models.user import User
        from scripts.manage_admin import cmd_create
        from sqlalchemy import select

        monkeypatch.setattr(sys, "exit", lambda code=0: None)
        await cmd_create("first@example.com", "Passw0rd!")

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
        import sys

        from scripts.manage_admin import cmd_reset

        user = await self._user(db_session, "reset@example.com")
        assert user.must_change_password is False

        monkeypatch.setattr(sys, "exit", lambda code=0: None)
        await cmd_reset("reset@example.com", "FreshPass456!")

        await db_session.refresh(user)
        assert user.must_change_password is True
        assert "temporary" in capsys.readouterr().out

    async def test_mfa_off_requires_a_new_factor(
        self, db_session, monkeypatch, capsys
    ):
        import sys
        from datetime import datetime, timezone

        from scripts.manage_admin import cmd_mfa_off

        user = await self._user(
            db_session,
            "lostdevice@example.com",
            totp_secret="encrypted-placeholder",
            totp_enabled_at=datetime.now(timezone.utc),
        )
        monkeypatch.setattr(sys, "exit", lambda code=0: None)
        await cmd_mfa_off("lostdevice@example.com")

        await db_session.refresh(user)
        assert user.totp_enabled_at is None
        # Recovery is not a downgrade: the cleared factor is owed again.
        assert user.must_enrol_mfa is True
        assert "required" in capsys.readouterr().out

    async def test_onboarding_off_releases_an_account_that_cannot_complete_it(
        self, db_session, monkeypatch, capsys
    ):
        import sys

        from scripts.manage_admin import cmd_onboarding_off

        user = await self._user(
            db_session,
            "stuck@example.com",
            must_change_password=True,
            must_enrol_mfa=True,
        )
        monkeypatch.setattr(sys, "exit", lambda code=0: None)
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
        import sys

        from scripts.manage_admin import cmd_onboarding_off

        # Raise rather than record: the real command stops at `sys.exit`, and a
        # stub that returns would let the code run on with a `None` user.
        def _exit(code=0):
            raise SystemExit(code)

        monkeypatch.setattr(sys, "exit", _exit)
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
        await self._user(db_session, "policyadmin@example.com", role=UserRole.admin)

        await cmd_list()
        out = capsys.readouterr().out

        assert "mfa (policy)" in out
        assert "REQUIRE_MFA_FOR_ADMINS" in out
