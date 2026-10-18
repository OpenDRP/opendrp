"""Rotate the encryption key and the JWT signing secret, verifiably.

Rotating a key is the operation that reveals whether a system was built for it:
if replacing `ENCRYPTION_KEY` means every stored secret becomes unreadable, the
rotation happens during an incident, if at all. `app/core/crypto.py` supports two
keys at once (newest encrypts, all decrypt) and `app/core/security.py` verifies a
token against any configured secret, so the work here is only the part that needs
the database: re-encrypting what the old key wrote.

Usage:

    python -m scripts.rotate_keys generate            # new Fernet key + .env lines
    python -m scripts.rotate_keys generate --jwt      # new JWT secret + .env lines
    python -m scripts.rotate_keys generate --audit-chain  # new audit chain key + .env lines
    python -m scripts.rotate_keys status              # what each key currently reads
    python -m scripts.rotate_keys rewrap              # re-encrypt with the newest key

The sequence is in docs/upgrading.md, "Rotating secrets". Short form: put the new
key first and the old one in `ENCRYPTION_PREVIOUS_KEYS`, restart the backend,
`rewrap`, confirm with `status`, then drop the previous key.

`rewrap` never silently skips a value: a stored secret that no configured key can
read aborts the run before anything is written, because the next step of the
procedure is to delete a key, and deleting a key that is still needed destroys data.

Everything the key protects is covered, second factors included: a user's
`totp_secret` is Fernet ciphertext like the settings secrets, so dropping the
previous key without re-encrypting it would make every enrolled authenticator
unreadable and lock those accounts out of their own second factor.
"""

from __future__ import annotations

import argparse
import secrets
import sys
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.crypto import configured_keys, key_index_for, rewrap_value
from app.core.logging_config import configure_logging, get_logger
from app.models.settings import SystemSettings
from app.models.source_account import SourceAccount
from app.models.user import User

configure_logging()
log = get_logger("opendrp.rotate_keys")

#: Columns whose plaintext is Fernet-encrypted by the hybrid properties on
#: `SystemSettings`. Kept as a list of names rather than reaching for the model's
#: hybrid attributes because the setters encrypt: reading a decrypted value here
#: and writing it back through the property would be a no-op for the wrong reason.
ENCRYPTED_COLUMNS = (
    "smtp_password",
    "smtp_from_email",
    "alert_recipient_email",
    "telegram_bot_token",
)


@dataclass
class StoredSecret:
    """One stored ciphertext, with the object and attribute that hold it."""

    label: str
    owner: Any
    attribute: str
    value: str


def _generate(*, jwt: bool, audit_chain: bool = False) -> int:
    if audit_chain:
        new_value = secrets.token_urlsafe(48)
        # `settings.audit_chain_keys` is the *merged* list the chain uses, so the
        # raw fields are read here instead: what goes into the previous field is
        # every key that was in force before, in the order it was in.
        current = settings.AUDIT_CHAIN_KEYS
        previous = settings.AUDIT_CHAIN_PREVIOUS_KEYS
        field, previous_field = "AUDIT_CHAIN_KEYS", "AUDIT_CHAIN_PREVIOUS_KEYS"

        merged = ", ".join(part for part in (current, previous) if part)
        print("# Add both lines to .env, replacing AUDIT_CHAIN_KEYS:")
        print(f"{field}={new_value}")
        print(f"{previous_field}={merged}")
        print()
        print(
            "# New entries are signed with the first key in AUDIT_CHAIN_KEYS; the\n"
            "# rest only verify. There is nothing to re-encrypt: each entry records\n"
            "# which key signed it. Run `make verify-audit-chain` with both keys in\n"
            "# place before removing the old one — an entry whose key is gone cannot\n"
            "# be distinguished from one somebody rewrote."
        )
        return 0

    if jwt:
        new_value = secrets.token_urlsafe(48)
        current = settings.JWT_SECRET_KEY
        previous = ", ".join(settings.jwt_verification_keys()[1:])
        field, previous_field = "JWT_SECRET_KEY", "JWT_PREVIOUS_SECRET_KEYS"
    else:
        new_value = Fernet.generate_key().decode("ascii")
        current = settings.ENCRYPTION_KEY
        previous = ", ".join(settings.encryption_previous_keys())
        field, previous_field = "ENCRYPTION_KEY", "ENCRYPTION_PREVIOUS_KEYS"

    merged = ", ".join(part for part in (current, previous) if part)
    print(f"# Add both lines to .env, replacing {field}:")
    print(f"{field}={new_value}")
    print(f"{previous_field}={merged}")
    print()
    print(
        "# Restart the backend so the new key is loaded, then re-encrypt what the\n"
        "# old key wrote:  docker compose exec backend python -m scripts.rotate_keys rewrap"
        if not jwt
        else "# Access and refresh tokens signed with the old secret keep working until\n"
        "# the previous key is removed, so the rotation does not sign anyone out."
    )
    return 0


async def _load_row(db: AsyncSession) -> SystemSettings | None:
    return (await db.execute(select(SystemSettings).limit(1))).scalar_one_or_none()


async def stored_secrets(db: AsyncSession) -> list[StoredSecret]:
    """Every stored ciphertext this script re-encrypts.

    Three places hold one: the settings singleton, each provider key on a source
    account, and each enrolled user's second factor. They are collected in one
    list so `status`, `rewrap` and its verification all see the same set — a
    column covered by re-encryption but not by the count would let `status`
    report a rotation as finished while a value is still on the previous key.
    """
    found: list[StoredSecret] = []
    row = await _load_row(db)
    if row is not None:
        for column in ENCRYPTED_COLUMNS:
            value = getattr(row, column)
            if value:
                found.append(StoredSecret(f"system_settings.{column}", row, column, value))
    accounts = (
        await db.execute(
            select(SourceAccount).where(SourceAccount.api_key_encrypted.is_not(None))
        )
    ).scalars().all()
    for account in accounts:
        found.append(
            StoredSecret(
                f"source_accounts.api_key_encrypted ({account.source_id}/{account.name})",
                account,
                "api_key_encrypted",
                account.api_key_encrypted,
            )
        )
    users = (
        await db.execute(select(User).where(User.totp_secret.is_not(None)))
    ).scalars().all()
    for user in users:
        if not user.totp_secret:
            # An empty value is "no second factor" (`totp_enabled_at` is what
            # makes the factor real), not a ciphertext to move to another key.
            continue
        found.append(
            StoredSecret(
                f"users.totp_secret ({user.email})",
                user,
                "totp_secret",
                user.totp_secret,
            )
        )
    return found


def summarize_secrets(found: list[StoredSecret]) -> tuple[dict[int, int], list[str]]:
    """Count stored values per configured key index, and list the unreadable ones."""
    per_key: dict[int, int] = {index: 0 for index in range(len(configured_keys()))}
    unreadable: list[str] = []
    for item in found:
        index = key_index_for(item.value)
        if index is None:
            unreadable.append(item.label)
        else:
            per_key[index] += 1
    return per_key, unreadable


async def rewrap_stored(db: AsyncSession) -> tuple[int, list[str]]:
    """Re-encrypt every stored secret not yet on the newest key.

    Returns ``(changed, failures)``. If any value is unreadable, nothing is written
    and the unreadable labels are returned, so a partial rotation can never be
    mistaken for a finished one.
    """
    found = await stored_secrets(db)
    _, unreadable = summarize_secrets(found)
    if unreadable:
        return 0, unreadable

    changed = 0
    for item in found:
        if key_index_for(item.value) == 0:
            continue
        setattr(item.owner, item.attribute, rewrap_value(item.value))
        changed += 1
    if changed:
        await db.commit()

    # Verified in memory after the write: the next documented step deletes a key,
    # which is only safe if every value now reads with the newest one.
    still_old = [
        item.label
        for item in found
        if key_index_for(getattr(item.owner, item.attribute)) != 0
    ]
    return changed, still_old


async def _status() -> int:
    keys = configured_keys()
    if not keys:
        print("No ENCRYPTION_KEY is configured.")
        return 2

    engine = create_async_engine(settings.DATABASE_URL_ASYNCPG, pool_pre_ping=True)
    try:
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as db:
            found = await stored_secrets(db)
    finally:
        await engine.dispose()

    if not found:
        print("No encrypted values are stored yet; nothing is encrypted.")
        return 0

    per_key, unreadable = summarize_secrets(found)
    print(f"{len(keys)} encryption key(s) configured, newest first.")
    for index in range(len(keys)):
        role = "encrypts and decrypts" if index == 0 else "decrypts only"
        print(f"  [{index}] {role}: {per_key[index]} stored value(s)")

    if unreadable:
        print("")
        print(f"FAIL: no configured key can read: {', '.join(unreadable)}")
        print("Restore the key that wrote these values before rotating further.")
        return 1

    if per_key.get(0, 0) == sum(per_key.values()):
        print("")
        print("OK: every stored value is readable with the newest key. Any previous key can be removed.")
    else:
        print("")
        print("Run `python -m scripts.rotate_keys rewrap` to move the remaining values to key [0].")
    return 0


async def _rewrap() -> int:
    engine = create_async_engine(settings.DATABASE_URL_ASYNCPG, pool_pre_ping=True)
    try:
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as db:
            changed, failures = await rewrap_stored(db)
    finally:
        await engine.dispose()

    if failures:
        for label in failures:
            print(
                f"FAIL: {label} cannot be decrypted with any configured key, "
                "or was not moved to the newest key. Restore the key that wrote it — "
                "re-encrypting would destroy the value."
            )
        return 1

    print(f"Re-encrypted {changed} value(s) with the newest key.")
    print("Confirm with `status`, then remove ENCRYPTION_PREVIOUS_KEYS from .env.")
    log.info("encryption_rewrapped", values=changed, keys=len(configured_keys()))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """The command line this script accepts, as an object a caller can inspect.

    Separate from `main` so the documentation gate can compare the commands
    `docs/upgrading.md` tells an operator to run with the parser that exists.
    """
    parser = argparse.ArgumentParser(
        description="Rotate the OpenDRP encryption key or JWT signing secret."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="print fresh key material and the .env lines")
    target = generate.add_mutually_exclusive_group()
    target.add_argument(
        "--jwt",
        action="store_true",
        help="generate a JWT signing secret instead of a Fernet encryption key",
    )
    target.add_argument(
        "--audit-chain",
        action="store_true",
        dest="audit_chain",
        help="generate an audit chain signing key instead of a Fernet encryption key",
    )
    subparsers.add_parser("status", help="report which configured key reads what")
    subparsers.add_parser("rewrap", help="re-encrypt stored secrets with the newest key")

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "generate":
        return _generate(jwt=args.jwt, audit_chain=args.audit_chain)
    if args.command == "status":
        import asyncio

        return asyncio.run(_status())
    if args.command == "rewrap":
        import asyncio

        return asyncio.run(_rewrap())
    parser.error(f"unknown command {args.command!r}")
    return 2  # pragma: no cover - argparse exits first


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
