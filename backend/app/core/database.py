from datetime import datetime, timezone
from typing import AsyncGenerator
import uuid
from uuid import uuid4

from sqlalchemy import DateTime, Uuid, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.core.config import settings


def postgres_connect_args(settings_=settings) -> dict:
    """asyncpg connect arguments, including the server-side statement limits.

    The pool is bounded, so an unbounded statement does not merely make one
    request slow: it holds a connection that every other request then has to
    wait for. PostgreSQL enforces these limits per connection, which is the
    property that matters — the guarantee survives a replica that forgets to
    configure it, and it applies to statements the application did not write
    (the ORM's own, a migration's backfill, a `SELECT` that stopped matching an
    index).

    ``statement_timeout=0`` disables the bound and is what a very large
    inventory may need; it is a setting rather than a hard-coded value so that
    the choice is the operator's, and a visible one.
    """
    server_settings = {
        # Shows up in `pg_stat_activity.application_name`, which is how an
        # operator identifies which container is holding the pool.
        "application_name": str(settings_.DB_APPLICATION_NAME),
        # Strings, not ints: asyncpg forwards these through the startup packet
        # as `SET` parameter values, and PostgreSQL parses them as strings.
        "statement_timeout": str(int(settings_.DB_STATEMENT_TIMEOUT_MS)),
        "lock_timeout": str(int(settings_.DB_LOCK_TIMEOUT_MS)),
        "idle_in_transaction_session_timeout": str(
            int(settings_.DB_IDLE_IN_TRANSACTION_TIMEOUT_MS)
        ),
    }
    connect_args: dict = {"server_settings": server_settings}
    if settings_.DB_COMMAND_TIMEOUT_SECONDS > 0:
        # Client-side ceiling, deliberately above `statement_timeout`: the
        # server should be the one to stop a slow statement, because its
        # cancellation is an error the API can report as a busy database, while
        # a client-side timeout arrives as an abrupt disconnect that reads like
        # a network fault.
        connect_args["command_timeout"] = float(settings_.DB_COMMAND_TIMEOUT_SECONDS)
    return connect_args


def migration_server_settings(settings_=settings) -> dict:
    """Server-side bounds for the connection a schema migration runs on.

    The values live in one place because the two migration entry points have to
    agree: `alembic/env.py` (where the revision graph runs) passes them as
    `server_settings`, and `scripts/migrate.py` renders the statement half into
    its psycopg `options` and deliberately omits the lock half — that connection
    waits for the migration slot by design. A bound only one of them carried
    would be a bound the other path does not have, and the failure it prevents is
    indistinguishable from a hung container: the API is started by the same
    entrypoint that migrates, so a migration blocked on a lock reads as
    "backend unhealthy" and nothing in the log names the wait.

    ``statement_timeout`` is disabled (``0``) unless the operator set
    ``MIGRATION_STATEMENT_TIMEOUT_MS``: the baseline builds its index families in
    one transaction and on a populated database that build is legitimately long, so
    inheriting the application's 30s bound would fail the documented maintenance
    window instead of protecting it.
    """
    return {
        "lock_timeout": str(int(settings_.MIGRATION_LOCK_TIMEOUT_MS)),
        "statement_timeout": str(int(settings_.MIGRATION_STATEMENT_TIMEOUT_MS)),
    }


def engine_kwargs(url: str, settings_=settings) -> dict:
    """SQLAlchemy engine options for a database URL.

    Split out of the module-level engine so that the options can be asserted
    without building an engine against a real database — the SQLite test suite
    never exercises this function with a PostgreSQL URL, which is exactly the
    configuration that must not silently lose its limits.
    """
    kwargs: dict = {
        "future": True,
        "pool_pre_ping": True,
    }
    if url.startswith(("postgresql+asyncpg://", "postgres+asyncpg://")):
        kwargs["pool_size"] = settings_.DB_POOL_SIZE
        kwargs["max_overflow"] = settings_.DB_MAX_OVERFLOW
        kwargs["pool_recycle"] = settings_.DB_POOL_RECYCLE_SECONDS
        kwargs["pool_timeout"] = settings_.DB_POOL_TIMEOUT_SECONDS
        kwargs["pool_use_lifo"] = settings_.DB_POOL_USE_LIFO
        kwargs["connect_args"] = postgres_connect_args(settings_)
    elif url.startswith(("sqlite+aiosqlite://",)):
        connect_args: dict = {"check_same_thread": False}
        if "?mode=memory&cache=shared" in url or "file:" in url.split(":///", 1)[-1]:
            connect_args["uri"] = True
        kwargs["connect_args"] = connect_args
    return kwargs


_async_url = settings.DATABASE_URL_ASYNCPG
engine = create_async_engine(_async_url, **engine_kwargs(_async_url, settings))

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    #: Every ``Mapped[uuid.UUID]`` column resolves to the platform's UUID type, so a
    #: column declared by annotation alone cannot pick a different one than the
    #: columns declared explicitly. See the note on :class:`UUIDMixin`.
    type_annotation_map = {uuid.UUID: Uuid(as_uuid=True)}


class UUIDMixin:
    """Primary key shared by every table, declared as ``Uuid`` and never ``UUID``.

    The two names render the same type on PostgreSQL — ``UUID``, the native one — and
    that is what the platform ships on. They differ where there is no native UUID:
    ``sqlalchemy.UUID`` writes the literal type name ``UUID`` into every backend's
    DDL, and SQLite has no such type, so it falls back to its affinity rules and
    matches none of them: the column gets **NUMERIC** affinity. SQLite applies that
    affinity to the value on insert, and a 32-character hex string made only of
    decimal digits *is* a number to it — one too large for its 64-bit integer, so it
    is stored as a REAL. Reading that row runs ``uuid.UUID(1e+32)`` inside the type's
    own result processor and raises "'float' object has no attribute 'replace'", in
    whichever test reads the row: `uuid4` produces such a hex about once in three
    million draws, and the suite writes enough UUIDs that the failure arrives
    eventually, in an unrelated module, with no failing code in the failing test.

    ``sqlalchemy.Uuid`` is the type meant for that gap: on SQLite it renders
    ``CHAR(32)`` — TEXT affinity, so the hex is stored verbatim — while on
    PostgreSQL it still creates the native ``UUID`` column with no conversion in
    either direction. The same value is stored either way (the type's SQLite bind
    processor writes the same 32-character hex), so existing test databases stay
    readable.
    """

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
