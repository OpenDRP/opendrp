from datetime import datetime, timezone
from typing import AsyncGenerator
import uuid
from uuid import uuid4

from sqlalchemy import DateTime, UUID, func
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
    pass


class UUIDMixin:
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
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
