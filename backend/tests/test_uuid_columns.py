"""Every UUID column has to survive the SQLite database the suite runs on.

The failure these tests guard appeared as an order-dependent red test in an
unrelated module: ``tests/test_dns_security.py`` read its own observations back,
and ``select(DNSObservation)`` raised
``AttributeError: 'float' object has no attribute 'replace'`` from inside
SQLAlchemy's UUID result processor — while the same test passed on its own, and
in every smaller selection that was run to reproduce it.

The cause was the column type, not the test. ``sqlalchemy.UUID`` renders the
literal type name ``UUID`` on *every* backend. PostgreSQL has that type; SQLite
does not, and its fallback is affinity — the name matches none of SQLite's rules,
so the column is given NUMERIC affinity. SQLite applies that affinity to the
value on insert, and a 32-character hex string made only of decimal digits is a
number to it: too large for its 64-bit integer, so it is stored as a REAL. The
row is then unreadable through the ORM for as long as it exists, in whichever
test happens to read it. ``uuid4`` draws such a hex about once in three million
times, and a full suite writes enough UUIDs for that to arrive eventually.

``sqlalchemy.Uuid`` is the type meant for the gap: ``CHAR(32)`` where the backend
has no native UUID (TEXT affinity — the hex is stored verbatim) and the native
``UUID`` column on PostgreSQL. Both halves are pinned here, because a column that
reaches for ``UUID`` again reintroduces the silent corruption, while "fixing" it
the other way — a text type everywhere — would silently change what production
stores.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import Uuid, select, text
from sqlalchemy.dialects import postgresql, sqlite

from app.models.dns_observation import DNSObservation

#: The UUID whose hex is a number to SQLite: 32 nines. Rewriting this to a random
#: ``uuid4`` would make the round-trip test below pass for the wrong reason.
DIGITS_ONLY_UUID = uuid.UUID("9" * 32)


def _uuid_columns() -> list[tuple[str, object]]:
    import app.models  # noqa: F401  (populates Base.metadata)

    from app.core.database import Base

    return [
        (table.name, column)
        for table in Base.metadata.sorted_tables
        for column in table.columns
        if isinstance(column.type, Uuid)
    ]


def test_the_scan_sees_the_platforms_uuid_columns():
    """A scan that found nothing would make both dialect tests below vacuous."""
    found = {f"{table_name}.{column.name}" for table_name, column in _uuid_columns()}

    assert "dns_security_observations.id" in found
    assert len(found) > 40


def test_no_uuid_column_asks_sqlite_for_numeric_affinity():
    dialect = sqlite.dialect()

    offenders = [
        f"{table_name}.{column.name} ({column.type.compile(dialect=dialect)})"
        for table_name, column in _uuid_columns()
        if str(column.type.compile(dialect=dialect)) != "CHAR(32)"
    ]

    assert offenders == [], (
        "a UUID column whose SQLite type is not CHAR(32) gets NUMERIC affinity, and "
        "SQLite then stores an all-digit UUID as a number — see this module's "
        "docstring:\n  " + "\n  ".join(offenders)
    )


def test_postgresql_still_stores_uuids_in_its_own_type():
    dialect = postgresql.dialect()

    offenders = [
        f"{table_name}.{column.name} ({column.type.compile(dialect=dialect)})"
        for table_name, column in _uuid_columns()
        if str(column.type.compile(dialect=dialect)) != "UUID"
    ]

    assert offenders == [], (
        "production runs on PostgreSQL, where these columns are the native UUID "
        "type; a column that renders anything else changes the storage a "
        "deployment already has:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.asyncio
async def test_an_all_digit_uuid_round_trips_through_the_test_database(db_session):
    """The exact shape that failed: stored, then read back through the ORM."""
    now = datetime.now(timezone.utc)
    db_session.add(
        DNSObservation(
            id=DIGITS_ONLY_UUID,
            observation_key="digits-only",
            observation_type="dns_record",
            subject="example.com",
            record_type="A",
            value="203.0.113.10",
            source="resolver",
            first_seen_at=now,
            last_seen_at=now,
        )
    )
    await db_session.commit()
    db_session.expire_all()

    stored_type, stored_value = (
        await db_session.execute(
            text("SELECT typeof(id), id FROM dns_security_observations")
        )
    ).one()
    row = (await db_session.execute(select(DNSObservation))).scalar_one()

    # Read from SQLite itself first: the column kept the hex as text, which is
    # what the ORM's result processor needs to turn it back into a UUID.
    assert (stored_type, stored_value) == ("text", DIGITS_ONLY_UUID.hex)
    assert row.id == DIGITS_ONLY_UUID
