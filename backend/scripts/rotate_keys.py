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
read aborts the run, because the next step of the procedure is to delete a key,
and deleting a key that is still needed destroys data.
"""

from __future__ import annotations

import argparse
import secrets
import sys

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.crypto import configured_keys, key_index_for, rewrap_value
from app.core.logging_config import configure_logging, get_logger
from app.models.settings import SystemSettings

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


async def _status() -> int:
    keys = configured_keys()
    if not keys:
        print("No ENCRYPTION_KEY is configured.")
        return 2

    engine = create_async_engine(settings.DATABASE_URL_ASYNCPG, pool_pre_ping=True)
    try:
        factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as db:
            row = await _load_row(db)
            if row is None:
                print("No system_settings row exists yet; nothing is encrypted.")
                return 0

            per_key: dict[int, int] = {index: 0 for index in range(len(keys))}
            unreadable: list[str] = []
            for column in ENCRYPTED_COLUMNS:
                value = getattr(row, column)
                if not value:
                    continue
                index = key_index_for(value)
                if index is None:
                    unreadable.append(column)
                else:
                    per_key[index] += 1
    finally:
        await engine.dispose()

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
            row = await _load_row(db)
            if row is None:
                print("No system_settings row exists yet; nothing to re-encrypt.")
                return 0

            changed = 0
            for column in ENCRYPTED_COLUMNS:
                value = getattr(row, column)
                if not value:
                    continue
                index = key_index_for(value)
                if index is None:
                    print(
                        f"FAIL: {column} cannot be decrypted with any configured key. "
                        "Restore the key that wrote it — re-encrypting would destroy the value."
                    )
                    return 1
                if index == 0:
                    continue
                setattr(row, column, rewrap_value(value))
                changed += 1

            if changed:
                await db.commit()

            # Verified after the write, in the same session: the next step of the
            # documented procedure is to delete a key, which is only safe if this
            # is true.
            for column in ENCRYPTED_COLUMNS:
                value = getattr(row, column)
                if value and key_index_for(value) != 0:
                    print(f"FAIL: {column} is still not readable with the newest key after rewrap.")
                    return 1
    finally:
        await engine.dispose()

    print(f"Re-encrypted {changed} value(s) with the newest key.")
    print("Confirm with `status`, then remove ENCRYPTION_PREVIOUS_KEYS from .env.")
    log.info("encryption_rewrapped", values=changed, keys=len(configured_keys()))
    return 0


def main(argv: list[str]) -> int:
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
