"""Startup seeder — runs after `alembic upgrade head` in the backend entrypoint.

NOTE: This script does NOT create admin accounts anymore. Admin bootstrap /
password recovery is handled exclusively by the local `manage_admin.py` CLI
which an operator runs manually. See backend/scripts/manage_admin.py.

This script:
  1. Ensures the `system_settings` singleton row exists (so Settings UI works).
  2. Brings a database an earlier build created up to the connector seed's
     declaration: the HIBP worker is a provider-backed connector, and its account
     row has to exist and the connector has to point at it. A fresh installation
     gets both from the baseline revision; this step is what makes an adopted
     database say the same thing, and it is idempotent because it runs on every
     container start.
"""
from __future__ import annotations

import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.models import Connector, SourceAccount, SystemSettings

#: The connector whose provider binding predates its account row. Named rather
#: than inferred: a future provider-backed connector gets its binding from the
#: baseline seed, and this map is only for the rows an earlier installation holds.
_LEGACY_PROVIDER_BINDINGS = {"breaches-hibp": "hibp"}


async def _bind_legacy_provider_rows(db: AsyncSession) -> None:
    """Give an adopted database the provider binding its seed did not declare.

    The baseline now declares `breaches-hibp` with `source: hibp`, but a database
    created before that change keeps the row it was seeded with: a connector with
    no provider is not gated on readiness and spends requests no account records.
    Binding it here is the same statement the baseline makes, applied to the row
    that already exists — and only while it is still unbound, so an operator's
    reassignment is never overwritten.
    """
    for connector_name, source_id in _LEGACY_PROVIDER_BINDINGS.items():
        connector = (
            await db.execute(select(Connector).where(Connector.name == connector_name))
        ).scalar_one_or_none()
        if connector is None:
            continue

        account = (
            await db.execute(
                select(SourceAccount).where(
                    SourceAccount.source_id == source_id,
                    SourceAccount.name == "default",
                )
            )
        ).scalar_one_or_none()
        if account is None:
            # Unapproved, exactly like every other seeded account: the row makes
            # the provider visible and its budget addressable, and an operator
            # decides whether scans may spend it.
            account = SourceAccount(
                source_id=source_id,
                name="default",
                policy={"approved": False},
                access_state="unknown",
            )
            db.add(account)
            await db.flush()
            print(f"[seed] Created source account {source_id}/default")

        if not connector.provider:
            connector.provider = source_id
            connector.quota_group = connector.quota_group or "default"
            connector.source_account_id = account.id
            print(f"[seed] Bound {connector_name} to {source_id}/default")


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
            print("[seed] Created system_settings singleton")
        else:
            print("[seed] system_settings singleton already exists")

        await _bind_legacy_provider_rows(db)
        await db.commit()

    await engine.dispose()
    print("[seed] Done.")


def main() -> None:
    asyncio.run(_seed())


if __name__ == "__main__":
    main()
