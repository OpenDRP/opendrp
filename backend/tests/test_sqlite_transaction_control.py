"""What the SQLite engine's transaction control buys, and what it must not cost.

AUD-042 was the first half: with pysqlite in its default mode SQLAlchemy issues no
``BEGIN``, so a ``SAVEPOINT`` opened as a session's first statement becomes the
outermost transaction and its ``RELEASE`` **commits** — the mutation-and-audit
atomicity the asset and ingestion paths promise was false on the backend every
test runs on.

The naive fix — ``BEGIN`` at the start of every transaction, the recipe the
SQLAlchemy documentation shows — was tried and does not survive this suite: every
read transaction then holds a SHARED lock for as long as its session lives, and a
second connection's commit waits out the busy timeout (``database is locked``,
reported against a statement that is not at fault). So the control is pinned here
in both directions:

* a savepoint has a real outer transaction to nest in, and a rollback undoes it;
* a DML statement without a savepoint is still rolled back, as pysqlite's own
  implicit transaction made it;
* a read-only session holds no lock, so a writer on another connection proceeds.

Each test builds its own file database, because the property under test is about
connections contending with each other — the suite's shared engine is the wrong
place to observe it.
"""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.database import install_sqlite_transaction_control


def _engine(tmp_path: Path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'txn.db'}"
    return create_async_engine(
        url,
        poolclass=NullPool,
        connect_args={"check_same_thread": False, "timeout": 0.2},
    )


async def _make_table(engine) -> None:
    async with engine.begin() as conn:
        await conn.exec_driver_sql("CREATE TABLE rows (id TEXT PRIMARY KEY)")


def _session_factory(engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)


@pytest.mark.asyncio
async def test_a_savepoint_is_no_longer_the_outermost_transaction(tmp_path):
    """The defect: a first-statement savepoint used to commit on ``RELEASE``.

    A session that inserts inside ``begin_nested()`` and then rolls back must leave
    no row — which is the guarantee ``require_persistence=True, commit=False``
    relies on. Without the control the same code stores the row (that is the probe
    in AUD-042), so this test is the fix's regression test.
    """
    engine = _engine(tmp_path)
    install_sqlite_transaction_control(engine)
    await _make_table(engine)
    factory = _session_factory(engine)
    row_id = str(uuid.uuid4())

    async with factory() as session:
        async with session.begin_nested():
            await session.execute(text("INSERT INTO rows (id) VALUES (:id)"), {"id": row_id})
        await session.rollback()

    async with factory() as session:
        count = (await session.execute(text("SELECT COUNT(*) FROM rows"))).scalar_one()
    assert count == 0, "a savepoint released as the outermost transaction committed the row"

    await engine.dispose()


@pytest.mark.asyncio
async def test_a_write_without_a_savepoint_is_still_rolled_back(tmp_path):
    """The behaviour pysqlite's implicit transaction gave, kept deliberately.

    ``DELETE /assets`` writes and then fails its audit row; the refusal is only
    honest if the session's rollback undoes the delete. Autocommit mode would have
    lost that, which is why ``BEGIN`` is sent before DML as well as before a
    savepoint.
    """
    engine = _engine(tmp_path)
    install_sqlite_transaction_control(engine)
    await _make_table(engine)
    factory = _session_factory(engine)
    row_id = str(uuid.uuid4())

    async with factory() as session:
        await session.execute(text("INSERT INTO rows (id) VALUES (:id)"), {"id": row_id})
        await session.commit()

    async with factory() as session:
        await session.execute(text("DELETE FROM rows WHERE id = :id"), {"id": row_id})
        await session.rollback()

    async with factory() as session:
        count = (await session.execute(text("SELECT COUNT(*) FROM rows"))).scalar_one()
    assert count == 1, "a write outside a savepoint survived the session's rollback"

    await engine.dispose()


@pytest.mark.asyncio
async def test_a_read_only_session_holds_no_lock_against_a_writer(tmp_path):
    """The cost the first attempt paid, pinned so it cannot come back.

    The reader's session stays open across the writer's commit, exactly as a test
    fixture or an idle request session does. If reads began a transaction, the
    writer would block for its busy timeout (0.2s here, 30s in a deployment) and the
    suite would fail with ``database is locked`` from an unrelated statement.
    """
    engine = _engine(tmp_path)
    install_sqlite_transaction_control(engine)
    await _make_table(engine)
    factory = _session_factory(engine)

    reader = factory()
    async with reader:
        await reader.execute(text("SELECT COUNT(*) FROM rows"))

        async def _write() -> None:
            async with factory() as writer:
                await writer.execute(
                    text("INSERT INTO rows (id) VALUES (:id)"), {"id": str(uuid.uuid4())}
                )
                await writer.commit()

        # A blocked writer would raise OperationalError after the busy timeout.
        await asyncio.wait_for(_write(), timeout=5)

    await engine.dispose()
