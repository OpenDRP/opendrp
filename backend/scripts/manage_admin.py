"""OpenDRP Admin Account Management CLI.

Use this tool to:
  1. Create the FIRST admin account after initial deployment (no auto-create
     happens on app startup anymore).
  2. Reset a lost/forgotten admin password at any time.

Every password this tool sets is treated as temporary: the account holder is
asked to choose their own at the next sign-in, and until they do, the platform
refuses the account everywhere except the page that performs the change. The same
applies to a second factor cleared with ``mfa-off``: it must be enrolled again
before the account can be used, so a recovery never leaves a downgrade behind.

Run INSIDE the backend container (so DB env and venv are wired correctly):

    docker compose exec backend python -m scripts.manage_admin create --email admin@example.com --password "ChangeMeAdminPass123!"

    docker compose exec backend python -m scripts.manage_admin reset --email admin@example.com --password "NewStrongPass456!"

    docker compose exec backend python -m scripts.manage_admin list

    docker compose exec backend python -m scripts.manage_admin onboarding-off --email admin@example.com
"""
from __future__ import annotations

import argparse
import asyncio
import re
import sys
from typing import Optional

from datetime import datetime, timezone

from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.core.mfa_policy import mfa_required_by_policy
from app.core.security import hash_password
from app.models.user import User
from app.services.refresh_sessions import revoke_refresh_families


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_email(email: str) -> str:
    if not EMAIL_RE.match(email):
        print(f"[ERROR] Invalid email format: {email}")
        sys.exit(2)
    return email.lower().strip()


def _validate_password(pw: str) -> str:
    if len(pw) < 8:
        print("[ERROR] Password must be at least 8 characters long")
        sys.exit(2)
    if not re.search(r"[A-Z]", pw):
        print("[ERROR] Password must contain at least one uppercase letter (A-Z)")
        sys.exit(2)
    if not re.search(r"[0-9]", pw):
        print("[ERROR] Password must contain at least one digit (0-9)")
        sys.exit(2)
    return pw


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
                existing.password_hash = hash_password(password)
                existing.is_active = True
                existing.must_change_password = True
                revoked = await revoke_refresh_families(
                    db, existing.id, reason="password_reset_cli"
                )
                await db.commit()
                print(
                    f"[OK] Admin {email} password UPDATED (--force). id={existing.id}. "
                    f"Sessions revoked: {revoked}\n"
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
        await db.commit()
        await db.refresh(admin)
        print(
            f"[OK] Created admin user:\n"
            f"     email:    {admin.email}\n"
            f"     id:       {admin.id}\n"
            f"     role:     {admin.role}\n"
            f"     active:   {admin.is_active}\n"
            f"     password: {'*' * len(password)} ({len(password)} chars) — temporary\n"
            f"     next:     the first sign-in asks for a new password of your own"
        )


async def cmd_reset(email: str, password: str) -> None:
    email = _validate_email(email)
    password = _validate_password(password)

    async with AsyncSessionLocal() as db:
        user = await _find_user(db, email)
        if user is None:
            print(f"[ERROR] No user found with email: {email}")
            sys.exit(4)

        user.password_hash = hash_password(password)
        user.is_active = True
        user.role = "admin"
        user.failed_login_attempts = 0
        user.locked_until = None
        # A reset hands the operator a password they chose, so the account must
        # replace it before using the platform. Without this the new password
        # lives on in whoever ran the command.
        user.must_change_password = True
        revoked = await revoke_refresh_families(
            db, user.id, reason="password_reset_cli"
        )
        await db.commit()
        print(
            f"[OK] Password RESET for user:\n"
            f"     email:    {user.email}\n"
            f"     id:       {user.id}\n"
            f"     role:     {user.role} (forced admin)\n"
            f"     active:   True\n"
            f"     locked:   unlocked (failed_attempts reset to 0)\n"
            f"     sessions: revoked ({revoked} refresh family/-ies)\n"
            f"     password: {'*' * len(password)} ({len(password)} chars) — temporary\n"
            f"     next:     the next sign-in asks for a new password of your own"
        )


async def cmd_unlock(email: str) -> None:
    email = _validate_email(email)
    async with AsyncSessionLocal() as db:
        user = await _find_user(db, email)
        if user is None:
            print(f"[ERROR] No user found with email: {email}")
            sys.exit(4)
        user.failed_login_attempts = 0
        user.locked_until = None
        user.is_active = True
        await db.commit()
        print(
            f"[OK] User {email} UNLOCKED.\n"
            f"     id:                      {user.id}\n"
            f"     role:                    {user.role}\n"
            f"     failed_login_attempts:   0 (reset)\n"
            f"     locked_until:            None\n"
            f"     is_active:               True (forced)"
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
    case where the last administrator is the one locked out.
    """
    email = _validate_email(email)
    async with AsyncSessionLocal() as db:
        user = await _find_user(db, email)
        if user is None:
            print(f"[ERROR] No user found with email: {email}")
            sys.exit(4)
        was_enabled = user.totp_enabled_at is not None
        user.totp_secret = None
        user.totp_enabled_at = None
        user.totp_last_used_step = None
        # Recovery is not a downgrade: the account owes a factor, and the platform
        # refuses it everywhere except the page that enrols one until it does.
        user.must_enrol_mfa = True
        await db.commit()
        print(
            f"[OK] Second factor cleared for {email}.\n"
            f"     id:          {user.id}\n"
            f"     was_enabled: {was_enabled}\n"
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
    to make visible. Printing that is the point of the warning below.
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


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="manage_admin",
        description="OpenDRP admin account bootstrap / password reset CLI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m scripts.manage_admin create -e admin@example.com -p 'StrongPass123!'\n"
            "  python -m scripts.manage_admin reset  -e admin@example.com -p 'NewPass456!'\n"
            "  python -m scripts.manage_admin unlock -e admin@example.com\n"
            "  python -m scripts.manage_admin mfa-off -e admin@example.com\n"
            "  python -m scripts.manage_admin onboarding-off -e admin@example.com\n"
            "  python -m scripts.manage_admin list\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Create a new admin user (idempotent)")
    p_create.add_argument("-e", "--email", required=True, help="Admin email address")
    p_create.add_argument("-p", "--password", required=True, help="Admin password (>= 8 chars)")
    p_create.add_argument(
        "-f", "--force", action="store_true",
        help="Overwrite password if admin already exists with this email",
    )

    p_reset = sub.add_parser("reset", help="Reset password (and ensure role=admin, active=True, unlocked)")
    p_reset.add_argument("-e", "--email", required=True, help="Target user email")
    p_reset.add_argument("-p", "--password", required=True, help="New password (>= 8 chars)")

    p_unlock = sub.add_parser("unlock", help="Unlock a locked user (clear failed attempts + locked_until)")
    p_unlock.add_argument("-e", "--email", required=True, help="User email to unlock")

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

    args = parser.parse_args()

    if args.command == "create":
        asyncio.run(cmd_create(args.email, args.password, args.force))
    elif args.command == "reset":
        asyncio.run(cmd_reset(args.email, args.password))
    elif args.command == "unlock":
        asyncio.run(cmd_unlock(args.email))
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
