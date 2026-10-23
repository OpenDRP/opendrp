"""OpenDRP Admin Account Management CLI.

Use this tool to:
  1. Create the FIRST admin account after initial deployment (no auto-create
     happens on app startup anymore).
  2. Reset a lost/forgotten password at any time.

Every password this tool sets is treated as temporary: the account holder is
asked to choose their own at the next sign-in, and until they do, the platform
refuses the account everywhere except the page that performs the change. The same
applies to a second factor cleared with ``mfa-off``: it must be enrolled again
before the account can be used, so a recovery never leaves a downgrade behind.

**No command changes an account's role or activity unless it is asked to.** A
support-driven password reset used to make the account an administrator and
reactivate it — so ``reset`` on a viewer granted administration of users, audit
and settings as a side effect, and ``unlock`` undid a deliberate deactivation.
Roles and activity are now changed only by an explicit flag (``--role``,
``--ensure-admin``, ``--activate``), and the command prints every field it
changed. ``--force`` on ``create`` overwrites the password and leaves the
account's activity alone for the same reason.

Every command that changes an account writes one row into the audit chain
(``user.created``, ``user.password_reset``, ``user.unlocked``, ``user.mfa.reset``,
``user.onboarding.cleared``) with ``details.source = "cli"``, the operating-system
user that ran it and the target account — because "who created the first
administrator, and when" is exactly the question the trail exists to answer. A
command whose audit row cannot be written fails instead of applying silently.
``list`` records ``users.list``, the same action the API writes for the same read.

Run INSIDE the backend container (so DB env and venv are wired correctly):

    docker compose exec backend python -m scripts.manage_admin create --email admin@example.com --password "ChangeMeAdminPass123!"

    docker compose exec backend python -m scripts.manage_admin reset --email admin@example.com --password "NewStrongPass456!"

    docker compose exec backend python -m scripts.manage_admin reset --email admin@example.com --password "NewStrongPass456!" --ensure-admin

    docker compose exec backend python -m scripts.manage_admin unlock --email user@example.com

    docker compose exec backend python -m scripts.manage_admin list

    docker compose exec backend python -m scripts.manage_admin onboarding-off --email admin@example.com
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import re
import sys
from typing import Optional

from datetime import datetime, timezone

from sqlalchemy import select

from app.core.audit import AuditLogger
from app.core.database import AsyncSessionLocal
from app.core.mfa_policy import mfa_required_by_policy
from app.core.security import hash_password
from app.models.user import User, role_name
from app.schemas.user import PASSWORD_MIN_LENGTH, validate_password_strength
from app.services.admin_invariants import (
    LastActiveAdminError,
    ensure_active_admin_remains,
    lock_active_admin_set,
)
from app.services.refresh_sessions import revoke_refresh_families


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

#: The audit trail's ``ip_address`` is a field an Elastic index may map as an IP
#: address, so a CLI row carries the loopback address rather than a word like
#: "cli" that the mapping would refuse. The origin is named where it belongs, in
#: ``details.source``, which is what a SIEM rule reads for host-side actions.
_CLI_IP_ADDRESS = "127.0.0.1"


def _validate_email(email: str) -> str:
    if not EMAIL_RE.match(email):
        print(f"[ERROR] Invalid email format: {email}")
        sys.exit(2)
    return email.lower().strip()


def _validate_password(pw: str) -> str:
    """The API's own policy, not a second copy of it.

    The CLI used to require 8 characters while the API required 12, so the
    installation could be bootstrapped with a password its own API would have
    rejected. One validator means the next rule (a breach-list check, say) is
    written once.
    """
    try:
        validate_password_strength(pw)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(2)
    return pw


def _cli_actor() -> str:
    """The operating-system user that ran the command, for the audit row."""
    try:
        return getpass.getuser() or "unknown"
    except Exception:
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


async def _audit_cli(db, action: str, details: dict, *, commit: bool = False) -> None:
    """Write the command's audit row, in the command's own transaction.

    ``user_id`` is ``None`` on purpose: the actor is a host operator, not a
    platform account, and inventing an account id would attribute the action to
    somebody who did not take it. The chain still includes the row, so the
    sequence has no gap.

    ``require_persistence`` is set for the mutating commands: a password reset
    that leaves no trail is the finding this exists to close, so a command that
    cannot write its row must fail rather than apply.
    """
    await AuditLogger.emit(
        db,
        action=action,
        ip_address=_CLI_IP_ADDRESS,
        user_id=None,
        details={"source": "cli", "actor": _cli_actor(), **details},
        require_persistence=True,
        commit=commit,
    )


async def _find_user(db, email: str) -> Optional[User]:
    r = await db.execute(select(User).where(User.email == email))
    return r.scalar_one_or_none()


async def cmd_create(email: str, password: str, force: bool = False) -> None:
    email = _validate_email(email)
    password = _validate_password(password)

    async with AsyncSessionLocal() as db:
        existing = await _find_user(db, email)
        if existing is not None:
            if existing.role == "admin":
                if not force:
                    print(
                        f"[SKIP] Admin user {email} already exists "
                        f"(id={existing.id}, is_active={existing.is_active}). "
                        f"Use 'reset' to change the password or pass --force to overwrite."
                    )
                    sys.exit(0)
                was_active = existing.is_active
                existing.password_hash = hash_password(password)
                # ``--force`` resets a password. It deliberately does not revive
                # an account an administrator deactivated: a support action must
                # not silently change who can sign in.
                existing.must_change_password = True
                revoked = await revoke_refresh_families(
                    db, existing.id, reason="password_reset_cli"
                )
                await _audit_cli(
                    db,
                    "user.password_reset",
                    {
                        "target_user_id": str(existing.id),
                        "target_email": existing.email,
                        "method": "cli_create_force",
                        "role": role_name(existing.role),
                        "is_active": was_active,
                        "refresh_families_revoked": revoked,
                        "onboarding_required": ["password"],
                    },
                )
                await db.commit()
                print(
                    f"[OK] Admin {email} password UPDATED (--force). id={existing.id}. "
                    f"Sessions revoked: {revoked}\n"
                    f"     role:     {role_name(existing.role)} (unchanged)\n"
                    f"     active:   {existing.is_active} (unchanged)\n"
                    f"     This password is temporary: the next sign-in requires "
                    f"choosing a new one."
                )
                return
            else:
                print(
                    f"[ERROR] User {email} already exists but has role '{existing.role}'. "
                    f"Choose a different email or remove that user first."
                )
                sys.exit(3)

        # Entering the active-admin set takes the same lock as leaving it, so an
        # insertion and a demotion cannot interleave: the service states that
        # every writer of the set holds it, and this is a writer that has no
        # authenticated caller to serialise against.
        await lock_active_admin_set(db)
        admin = User(
            email=email,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
            # The password above is in a shell history, a chat message or this
            # documentation. The account is expected to replace it at first
            # sign-in, and app/api/deps.py is what makes that expectation real.
            must_change_password=True,
        )
        db.add(admin)
        await db.flush()
        await _audit_cli(
            db,
            "user.created",
            {
                "target_user_id": str(admin.id),
                "target_email": admin.email,
                "method": "cli_create",
                "role": "admin",
                "is_active": True,
                "onboarding_required": ["password"],
            },
        )
        await db.commit()
        await db.refresh(admin)
        print(
            f"[OK] Created admin user:\n"
            f"     email:    {admin.email}\n"
            f"     id:       {admin.id}\n"
            f"     role:     {role_name(admin.role)}\n"
            f"     active:   {admin.is_active}\n"
            f"     password: {'*' * len(password)} ({len(password)} chars) — temporary\n"
            f"     next:     the first sign-in asks for a new password of your own"
        )


async def cmd_reset(
    email: str,
    password: str,
    role: Optional[str] = None,
    ensure_admin: bool = False,
    activate: bool = False,
) -> None:
    """Reset a password; change role or activity only when explicitly asked.

    The password, the lockout counters and the sessions are the recovery. The
    role and the active flag are *decisions*, and they are made by a named flag
    (``--role``/``--ensure-admin``/``--activate``) that the command prints back —
    which is the difference between an operator choosing to promote an account
    and a password reset promoting it by accident.
    """
    email = _validate_email(email)
    password = _validate_password(password)

    async with AsyncSessionLocal() as db:
        user = await _find_user(db, email)
        if user is None:
            print(f"[ERROR] No user found with email: {email}")
            sys.exit(4)

        role_before = role_name(user.role)
        active_before = user.is_active

        target_role = role
        if ensure_admin and target_role is None and role_before != "admin":
            target_role = "admin"

        role_changed = False
        if target_role is not None and target_role != role_before:
            # Demoting the last administrator from the host would leave the
            # platform with nobody able to create an account, so the CLI applies
            # the same invariant the API does.
            try:
                await ensure_active_admin_remains(
                    db, user, final_role=target_role, final_active=active_before
                )
            except LastActiveAdminError as exc:
                print(
                    f"[ERROR] {exc}: {email} is the only active administrator. "
                    f"Create or promote another administrator first."
                )
                sys.exit(5)
            user.role = target_role
            role_changed = True

        activated = False
        if activate and not user.is_active:
            user.is_active = True
            activated = True

        user.password_hash = hash_password(password)
        user.failed_login_attempts = 0
        user.locked_until = None
        # A reset hands the operator a password they chose, so the account must
        # replace it before using the platform. Without this the new password
        # lives on in whoever ran the command.
        user.must_change_password = True
        revoked = await revoke_refresh_families(
            db, user.id, reason="password_reset_cli"
        )
        await _audit_cli(
            db,
            "user.password_reset",
            {
                "target_user_id": str(user.id),
                "target_email": user.email,
                "method": "cli_reset",
                "role_changed": role_changed,
                "role": role_name(user.role),
                "previous_role": role_before,
                "activated": activated,
                "is_active": user.is_active,
                "refresh_families_revoked": revoked,
                "onboarding_required": ["password"],
            },
        )
        await db.commit()
        print(
            f"[OK] Password RESET for user:\n"
            f"     email:    {user.email}\n"
            f"     id:       {user.id}\n"
            f"     role:     {role_before}"
            + (f" -> {role_name(user.role)}" if role_changed else " (unchanged)")
            + "\n"
            f"     active:   {user.is_active}"
            + (" (activated by --activate)" if activated else " (unchanged)")
            + "\n"
            f"     locked:   unlocked (failed_attempts reset to 0)\n"
            f"     sessions: revoked ({revoked} refresh family/-ies)\n"
            f"     password: {'*' * len(password)} ({len(password)} chars) — temporary\n"
            f"     next:     the next sign-in asks for a new password of your own"
        )


async def cmd_unlock(email: str, activate: bool = False) -> None:
    """Clear a brute-force lockout; reactivate only with ``--activate``.

    Unlocking an account that was deliberately deactivated used to switch it
    back on as a side effect. Those are two different decisions and now take two
    different flags; the output always names the resulting state.
    """
    email = _validate_email(email)
    async with AsyncSessionLocal() as db:
        user = await _find_user(db, email)
        if user is None:
            print(f"[ERROR] No user found with email: {email}")
            sys.exit(4)
        activated = False
        if activate and not user.is_active:
            user.is_active = True
            activated = True
        user.failed_login_attempts = 0
        user.locked_until = None
        await _audit_cli(
            db,
            "user.unlocked",
            {
                "target_user_id": str(user.id),
                "target_email": user.email,
                "method": "cli_unlock",
                "activated": activated,
                "is_active": user.is_active,
            },
        )
        await db.commit()
        print(
            f"[OK] User {email} UNLOCKED.\n"
            f"     id:                      {user.id}\n"
            f"     role:                    {role_name(user.role)} (unchanged)\n"
            f"     failed_login_attempts:   0 (reset)\n"
            f"     locked_until:            None\n"
            f"     is_active:               {user.is_active}"
            + (" (activated by --activate)" if activated else " (unchanged)")
        )


async def cmd_mfa_off(email: str) -> None:
    """Clear a user's second factor — the account-recovery path for a lost device.

    Deliberately CLI-only and deliberately not available over the API for your
    own account: a session that can remove its own second factor is not a second
    factor. Requiring access to the running deployment (or the database) is a
    higher bar than a password plus a stolen session, which is the whole point of
    the comparison.

    Every other account can be recovered by an administrator through
    ``POST /api/v1/users/{id}/mfa/reset`` (audited as ``user.mfa.reset``); this
    command is what an administrator uses for their *own* account, and for the
    case where the last administrator is the one locked out. It revokes the
    account's refresh families for the same reason the API path does: a factor
    that was cleared may be in the hands of whoever took the device, and a live
    session would outlive the recovery.
    """
    email = _validate_email(email)
    async with AsyncSessionLocal() as db:
        user = await _find_user(db, email)
        if user is None:
            print(f"[ERROR] No user found with email: {email}")
            sys.exit(4)
        was_enabled = user.totp_enabled_at is not None
        # The lockout that five wrong guesses produce outlives the factor, and
        # both enrolment routes refuse while it is in force: a recovery that
        # left it behind handed back an account that still could not enrol, for
        # another fifteen minutes and with nothing saying why. The API reset
        # clears both counters, and this path is the same recovery.
        locked_until = user.mfa_locked_until
        if locked_until is not None and locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        was_locked = locked_until is not None and locked_until > datetime.now(timezone.utc)
        user.totp_secret = None
        user.totp_enabled_at = None
        user.totp_last_used_step = None
        user.mfa_failed_attempts = 0
        user.mfa_locked_until = None
        # Recovery is not a downgrade: the account owes a factor, and the platform
        # refuses it everywhere except the page that enrols one until it does.
        user.must_enrol_mfa = True
        revoked = await revoke_refresh_families(db, user.id, reason="mfa_reset_cli")
        await _audit_cli(
            db,
            "user.mfa.reset",
            {
                "target_user_id": str(user.id),
                "target_email": user.email,
                "method": "cli_mfa_off",
                "was_enabled": was_enabled,
                "mfa_lockout_cleared": was_locked,
                "refresh_families_revoked": revoked,
                "onboarding_required": ["mfa"],
            },
        )
        await db.commit()
        print(
            f"[OK] Second factor cleared for {email}.\n"
            f"     id:          {user.id}\n"
            f"     was_enabled: {was_enabled}\n"
            f"     sessions:    revoked ({revoked} refresh family/-ies)\n"
            f"     next login:  password, then a new authenticator — enrolment is "
            f"required before the rest of the platform opens"
        )


async def cmd_onboarding_off(email: str) -> None:
    """Clear the credential-onboarding requirements for an account.

    The escape hatch for the case the gate would otherwise trap: an operator whose
    temporary password was applied faster than it could be changed, a deployment
    whose mail relay or authenticator app is not available yet, or an account that
    has to reach the platform before its owner does. It requires access to the
    running deployment, which is a deliberately higher bar than a browser session.

    It does not weaken anything by itself: the flags carry no privilege. What it
    does is stop insisting that a credential be replaced — so the password in force
    stays the one somebody else chose, which is exactly the state the flags exist
    to make visible. Printing that is the point of the warning below, and the
    audit row (``user.onboarding.cleared``) is what makes the release findable
    later: ``onboarding-off`` leaves an account working with a shared secret, and
    "who released it" has to be answerable from the trail rather than from host
    history.
    """
    email = _validate_email(email)
    async with AsyncSessionLocal() as db:
        user = await _find_user(db, email)
        if user is None:
            print(f"[ERROR] No user found with email: {email}")
            sys.exit(4)
        was_password = user.must_change_password
        was_mfa = user.must_enrol_mfa
        user.must_change_password = False
        user.must_enrol_mfa = False
        await _audit_cli(
            db,
            "user.onboarding.cleared",
            {
                "target_user_id": str(user.id),
                "target_email": user.email,
                "method": "cli_onboarding_off",
                "was_change_pw": was_password,
                "was_enrol_mfa": was_mfa,
            },
        )
        await db.commit()
        print(
            f"[OK] Onboarding requirements cleared for {email}.\n"
            f"     id:               {user.id}\n"
            f"     was_change_pw:    {was_password}\n"
            f"     was_enrol_mfa:    {was_mfa}\n"
            f"     second factor:    "
            f"{'enrolled' if user.totp_enabled_at is not None else 'NOT enrolled'}\n"
            f"     note: the current password keeps working as-is; nothing forces a "
            f"change until the next administrator reset"
        )


async def cmd_list() -> None:
    async with AsyncSessionLocal() as db:
        r = await db.execute(select(User).order_by(User.role, User.email))
        rows = r.scalars().all()
        # A host operator reading every account's security state is the same read
        # the API records as `users.list`; the origin is named in the details.
        await _audit_cli(
            db,
            "users.list",
            {"method": "cli_list", "results": len(rows)},
            commit=True,
        )
        if not rows:
            print("[INFO] No users in the database yet. Use 'create' to add an admin.")
            return
        now = datetime.now(timezone.utc)
        print(f"[INFO] Users in database: {len(rows)}\n")
        print(
            f"{'EMAIL':<30} {'ROLE':<10} {'ACTIVE':<8} {'FAILS':<6} "
            f"{'LOCKED':<7} {'MFA':<4} {'ONBOARDING':<20} {'ID'}"
        )
        print("-" * 150)
        for u in rows:
            locked = "LOCKED" if (
                u.locked_until and u.locked_until > now
            ) else "-"
            fails = str(u.failed_login_attempts or 0)
            mfa = "yes" if u.totp_enabled_at is not None else "-"
            # What is still owed at the next sign-in, so a support call can be
            # answered from this table instead of from a browser session.
            pending = [
                label
                for label, flag in (
                    ("password", u.must_change_password),
                    ("mfa", u.must_enrol_mfa),
                )
                if flag
            ]
            # The deployment's own policy is not stored on the account, so it has to
            # be computed here. Without it this table would show an administrator
            # with nothing owed and no explanation for being refused everywhere —
            # which is exactly the support call the table exists to answer.
            if not pending and mfa_required_by_policy(u.role, u.totp_enabled_at):
                pending.append("mfa (policy)")
            onboarding = ", ".join(pending) if pending else "-"
            print(
                f"{u.email:<30} {str(u.role):<10} {str(u.is_active):<8} "
                f"{fails:<6} {locked:<7} {mfa:<4} {onboarding:<20} {u.id}"
            )
        if any(u.must_change_password or u.must_enrol_mfa for u in rows) or any(
            mfa_required_by_policy(u.role, u.totp_enabled_at) for u in rows
        ):
            print(
                "\n[INFO] 'ONBOARDING' lists what an account must complete at its "
                "next sign-in.\n"
                "       The platform refuses everything except the onboarding page "
                "until then.\n"
                "       'mfa (policy)' is not a flag on the account: it comes from "
                "REQUIRE_MFA_FOR_ADMINS, so it is answered by that setting or by "
                "enrolling a factor.\n"
                "       To release an account that cannot complete its own steps: "
                "manage_admin onboarding-off -e <email>"
            )


def build_parser() -> argparse.ArgumentParser:
    """The command line this script accepts, as an object a caller can inspect.

    Separate from `main` so the documentation gate can read the subcommands and
    flags an operator is told to type and compare them with what the script
    actually parses: help text drifts silently otherwise.
    """
    parser = argparse.ArgumentParser(
        prog="manage_admin",
        description="OpenDRP admin account bootstrap / password reset CLI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m scripts.manage_admin create -e admin@example.com -p 'StrongPass123!'\n"
            "  python -m scripts.manage_admin reset  -e admin@example.com -p 'NewPass456!'\n"
            "  python -m scripts.manage_admin reset  -e admin@example.com -p 'NewPass456!' --ensure-admin\n"
            "  python -m scripts.manage_admin unlock -e admin@example.com\n"
            "  python -m scripts.manage_admin mfa-off -e admin@example.com\n"
            "  python -m scripts.manage_admin onboarding-off -e admin@example.com\n"
            "  python -m scripts.manage_admin list\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Create a new admin user (idempotent)")
    p_create.add_argument("-e", "--email", required=True, help="Admin email address")
    p_create.add_argument(
        "-p",
        "--password",
        required=True,
        help=f"Admin password (>= {PASSWORD_MIN_LENGTH} chars, one uppercase, one digit)",
    )
    p_create.add_argument(
        "-f", "--force", action="store_true",
        help="Overwrite the password if an admin already exists with this email",
    )

    p_reset = sub.add_parser(
        "reset",
        help="Reset a password (role and activity are changed only by an explicit flag)",
    )
    p_reset.add_argument("-e", "--email", required=True, help="Target user email")
    p_reset.add_argument(
        "-p",
        "--password",
        required=True,
        help=f"New password (>= {PASSWORD_MIN_LENGTH} chars, one uppercase, one digit)",
    )
    p_reset.add_argument(
        "--role",
        choices=["admin", "analyst", "viewer"],
        default=None,
        help="Explicitly set the account role (default: keep the current one)",
    )
    p_reset.add_argument(
        "--ensure-admin",
        action="store_true",
        help="Promote the account to admin if it is not one (prints the change)",
    )
    p_reset.add_argument(
        "--activate",
        action="store_true",
        help="Reactivate a deactivated account (default: keep the current state)",
    )

    p_unlock = sub.add_parser("unlock", help="Unlock a locked user (clear failed attempts + locked_until)")
    p_unlock.add_argument("-e", "--email", required=True, help="User email to unlock")
    p_unlock.add_argument(
        "--activate",
        action="store_true",
        help="Also reactivate a deactivated account (default: keep it deactivated)",
    )

    p_mfa_off = sub.add_parser(
        "mfa-off",
        aliases=["mfa-reset"],
        help="Clear a user's TOTP second factor (lost authenticator / locked-out administrator)",
    )
    p_mfa_off.add_argument("-e", "--email", required=True, help="User email whose second factor to clear")

    p_onboarding_off = sub.add_parser(
        "onboarding-off",
        help="Clear the forced password change / factor enrolment for a user",
    )
    p_onboarding_off.add_argument("--email", "-e", required=True, help="User email")

    sub.add_parser(
        "list", help="List all users with lock status, second factor and onboarding"
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "create":
        asyncio.run(cmd_create(args.email, args.password, args.force))
    elif args.command == "reset":
        asyncio.run(
            cmd_reset(
                args.email,
                args.password,
                role=args.role,
                ensure_admin=args.ensure_admin,
                activate=args.activate,
            )
        )
    elif args.command == "unlock":
        asyncio.run(cmd_unlock(args.email, activate=args.activate))
    elif args.command in ("mfa-off", "mfa-reset"):
        asyncio.run(cmd_mfa_off(args.email))
    elif args.command == "onboarding-off":
        asyncio.run(cmd_onboarding_off(args.email))
    elif args.command == "list":
        asyncio.run(cmd_list())
    else:  # pragma: no cover
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
