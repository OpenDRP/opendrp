"""The user/RBAC properties that only PostgreSQL can host.

Two findings from ``docs/internal/audit-2026-10-15_users-rbac_03`` cannot be
asserted on SQLite, and pretending otherwise is how they stayed open:

* **USR-12 / RWI-10.** A refresh family whose account is gone is a session nobody
  can revoke. The guarantee is a foreign key with ``ON DELETE CASCADE``, which
  SQLite only enforces when every connection asks for it — and a raw
  ``DELETE FROM users`` (an operator's SQL, a restore into a half-populated
  database) is exactly the case the router's hand-written DELETE never covered.
* **USR-03's neighbour / RWI-11.** Creating an administrator takes
  ``pg_advisory_xact_lock(0x4F445250)`` so two writers cannot both believe they
  are leaving one admin behind. The question the audit raised is what happens when
  another session holds that lock: the request must fail on the server's
  ``lock_timeout`` (five seconds), not on the client's command timeout, because a
  client-side timeout reads as a network fault and leaves the waiter invisible.

``REQUIRE_INTEGRATION=1`` — what CI's ``production-integration`` job sets — turns a
missing database into a failure rather than a skip, so a job that lost its
database cannot report this file as green without having run it.
"""

from __future__ import annotations

import os
import time
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.database import postgres_connect_args
from app.models.token import RefreshTokenFamily
from app.models.user import User
from app.services.admin_invariants import ACTIVE_ADMIN_LOCK_KEY

_DATABASE_URL = os.environ.get("INTEGRATION_MIGRATION_DATABASE_URL")
if not _DATABASE_URL:
    _message = "set INTEGRATION_MIGRATION_DATABASE_URL to run the user/RBAC PostgreSQL tests"
    if os.environ.get("REQUIRE_INTEGRATION") == "1":
        raise RuntimeError(f"{_message} — REQUIRE_INTEGRATION=1 forbids skipping")
    pytest.skip(_message, allow_module_level=True)

# Selected by CI's `-m integration` run and deselected by the SQLite job.
pytestmark = pytest.mark.integration


def _engine():
    """The application's own connection settings, against the migrated database.

    ``postgres_connect_args`` is what a request's connection carries, so a
    property asserted here is a property the API has rather than one this file
    arranged for itself.
    """
    return create_async_engine(_DATABASE_URL, connect_args=postgres_connect_args())


async def _create_user(factory, email: str) -> uuid.UUID:
    async with factory() as db:
        user = User(email=email, password_hash="not-used-in-this-test", role="viewer")
        db.add(user)
        await db.commit()
        return user.id


async def _drop_user(factory, user_id: uuid.UUID) -> None:
    async with factory() as db:
        await db.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
        await db.commit()


async def test_deleting_a_user_cascades_to_its_refresh_families():
    """A raw ``DELETE FROM users`` is enough; no application code has to run."""
    engine = _engine()
    factory = async_sessionmaker(engine, expire_on_commit=False)
    user_id = await _create_user(factory, "cascade-postgres@example.com")
    try:
        async with factory() as db:
            db.add(
                RefreshTokenFamily(
                    family_id=uuid.uuid4(),
                    user_id=user_id,
                    last_jti=str(uuid.uuid4()),
                )
            )
            await db.commit()

        await _drop_user(factory, user_id)

        async with factory() as db:
            remaining = (
                await db.execute(
                    text(
                        "SELECT count(*) FROM drp_refresh_families WHERE user_id = :id"
                    ),
                    {"id": user_id},
                )
            ).scalar_one()
        assert remaining == 0, "the account is gone but its sessions are still revocable state"
    finally:
        await _drop_user(factory, user_id)
        await engine.dispose()


async def test_no_orphaned_refresh_families_remain():
    """The adoption cleanup in ``docs/upgrading.md`` leaves nothing behind.

    An orphan is not merely untidy: the retention sweep deletes by ``revoked_at``,
    so a row that never had a revocation recorded is never selected, and it holds
    a family id that could still be presented.
    """
    engine = _engine()
    try:
        async with engine.connect() as connection:
            orphans = (
                await connection.execute(
                    text(
                        "SELECT count(*) FROM drp_refresh_families f "
                        "LEFT JOIN users u ON u.id = f.user_id WHERE u.id IS NULL"
                    )
                )
            ).scalar_one()
        assert orphans == 0, f"{orphans} refresh families have no user row"
    finally:
        await engine.dispose()


async def test_the_constraint_is_cascade_and_names_the_delete_rule():
    """The rule is in the schema, so it survives a writer that knows no ORM."""
    engine = _engine()
    try:
        async with engine.connect() as connection:
            rule = (
                await connection.execute(
                    text(
                        "SELECT confdeltype FROM pg_constraint "
                        "WHERE conname = 'fk_drp_refresh_families_user_id_users'"
                    )
                )
            ).scalar_one_or_none()
        # PostgreSQL's ``"char"`` maps to ``str`` on some asyncpg versions and to
        # ``bytes`` on others; the rule is the same either way.
        rule_text = rule.decode() if isinstance(rule, (bytes, bytearray)) else rule
        assert rule_text == "c", (
            "the refresh-family foreign key is missing or does not cascade: "
            f"{rule!r} — 'c' is cascade, 'n' is set null, 'a' is no action"
        )
    finally:
        await engine.dispose()


async def test_a_held_advisory_lock_fails_on_lock_timeout_not_on_the_client():
    """RWI-11: the waiter gives up in seconds, and says it was the lock.

    A second session holds the administrator-set lock inside its transaction; the
    first request-shaped connection asks for it. The server's ``lock_timeout``
    ends the wait, which is an error the API can report, instead of the client's
    ``command_timeout`` closing the socket — the difference between "busy, retry"
    and "the database went away".
    """
    engine = _engine()
    try:
        async with engine.connect() as holder:
            await holder.execute(
                text("SELECT pg_advisory_xact_lock(:key)"), {"key": ACTIVE_ADMIN_LOCK_KEY}
            )
            async with engine.connect() as waiter:
                started = time.monotonic()
                with pytest.raises(Exception) as failure:
                    await waiter.execute(
                        text("SELECT pg_advisory_xact_lock(:key)"),
                        {"key": ACTIVE_ADMIN_LOCK_KEY},
                    )
                elapsed = time.monotonic() - started
            await holder.rollback()

        assert elapsed < 10, (
            "the waiter did not stop on the server's lock_timeout: "
            f"{elapsed:.1f}s against a {settings.DB_LOCK_TIMEOUT_MS} ms bound"
        )
        message = str(failure.value).lower()
        assert "lock timeout" in message or "locknotavailable" in type(failure.value).__name__.lower(), (
            f"the refusal does not name the lock: {failure.value!r}"
        )
        # The property the numbers are chosen for: the server stops the wait
        # before the client-side ceiling, so the API sees an error to report.
        assert settings.DB_LOCK_TIMEOUT_MS < settings.DB_COMMAND_TIMEOUT_SECONDS * 1000, (
            "lock_timeout must sit below the client command timeout, or the wait end "
            "arrives as a disconnect"
        )
    finally:
        await engine.dispose()
