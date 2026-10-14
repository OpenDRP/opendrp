import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import settings
from app.core.database import Base, migration_server_settings
from app.models import *  # noqa: F401, F403

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_sync_url() -> str:
    url = settings.DATABASE_URL
    url = url.replace("+asyncpg", "")
    if "+psycopg2" not in url:
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+psycopg2://", 1)
        elif url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url


def _get_async_url() -> str:
    return settings.DATABASE_URL_ASYNCPG


def run_migrations_offline() -> None:
    url = _get_sync_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _get_async_url()

    # The revision itself runs on this connection, so it is the one that must not
    # wait forever behind another session's lock: `lock_timeout` turns that wait
    # into an error that names it, and the statement bound is deliberately off
    # (see `migration_server_settings`). Only PostgreSQL gets them — a SQLite URL
    # has no `server_settings`, and this engine is built for whichever database
    # the caller configured.
    connect_args = (
        {"server_settings": migration_server_settings()}
        if _get_async_url().startswith(("postgresql+asyncpg://", "postgres+asyncpg://"))
        else {}
    )

    connectable = AsyncEngine(
        engine_from_config(
            configuration,
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
            future=True,
            connect_args=connect_args,
        )
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
