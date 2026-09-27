"""Startup seeder — runs after `alembic upgrade head` in the backend entrypoint.

NOTE: This script does NOT create admin accounts anymore. Admin bootstrap /
password recovery is handled exclusively by the local `manage_admin.py` CLI
which an operator runs manually. See backend/scripts/manage_admin.py.

This script only:
  1. Ensures the `system_settings` singleton row exists (so Settings UI works).
"""
from __future__ import annotations

import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.models import SystemSettings


async def _seed() -> None:
    engine = create_async_engine(
        settings.DATABASE_URL_ASYNCPG,
        pool_pre_ping=True,
        future=True,
    )
    session_factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    async with session_factory() as db:
        result = await db.execute(select(SystemSettings).limit(1))
        existing = result.scalar_one_or_none()
        if existing is None:
            db.add(SystemSettings())
            await db.commit()
            print("[seed] Created system_settings singleton")
        else:
            print("[seed] system_settings singleton already exists")

    await engine.dispose()
    print("[seed] Done.")


def main() -> None:
    asyncio.run(_seed())


if __name__ == "__main__":
    main()
