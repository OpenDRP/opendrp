"""Alembic migration tests against a real PostgreSQL database.

Verifies the consolidated v0.1.0 initial schema (0001_initial_schema):
table creation, extension, indexes, defaults, seeds, and downgrade round-trip.

Required environment variable:
    INTEGRATION_MIGRATION_DATABASE_URL=postgresql+asyncpg://...
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import settings
from scripts.check_migrations import REVISION_ID_MAX_LENGTH

_DATABASE_URL = os.environ.get("INTEGRATION_MIGRATION_DATABASE_URL")
if not _DATABASE_URL:
    _message = "set INTEGRATION_MIGRATION_DATABASE_URL to run Alembic PostgreSQL tests"
    if os.environ.get("REQUIRE_INTEGRATION") == "1":
        raise RuntimeError(f"{_message} — REQUIRE_INTEGRATION=1 forbids skipping")
    pytest.skip(_message, allow_module_level=True)

pytestmark = pytest.mark.integration

_ROOT = Path(__file__).resolve().parents[1]


def _alembic_config() -> Config:
    config = Config(str(_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(_ROOT / "alembic"))
    return config


def _head_revision() -> str:
    from alembic.script import ScriptDirectory
    return ScriptDirectory.from_config(_alembic_config()).get_current_head()


def _run_migration(action: str, revision: str) -> None:
    config = _alembic_config()
    if action == "upgrade":
        command.upgrade(config, revision)
    elif action == "downgrade":
        command.downgrade(config, revision)
    else:
        raise ValueError(f"unsupported migration action: {action}")


async def _table_names(engine) -> set[str]:
    async with engine.connect() as connection:
        return set(await connection.run_sync(lambda sync: inspect(sync).get_table_names()))


#: The module-definition keys stored in ``json`` columns. A ``text()`` query
#: carries no type information, so whether one of these arrives as a decoded
#: object or as its text depends on the driver's codecs, while the rest of the row
#: is plain text in every case.
_JSON_MODULE_KEYS = frozenset({"asset_types", "fields", "dedup_fields", "storage"})


def _as_stored(value, key: str):
    """A stored module value as Python, whichever layer decoded it."""
    import json

    if key in _JSON_MODULE_KEYS and isinstance(value, str):
        return json.loads(value)
    return value


async def _column_names(engine, table_name: str) -> set[str]:
    async with engine.connect() as connection:
        return set(
            await connection.run_sync(
                lambda sync: {
                    column["name"]
                    for column in inspect(sync).get_columns(table_name)
                }
            )
        )


@pytest.mark.asyncio
async def test_clean_database_upgrades_to_head_and_seeds_required_registry(monkeypatch):
    """A fresh PostgreSQL database reaches 0001_initial_schema head."""
    monkeypatch.setattr(settings, "DATABASE_URL", _DATABASE_URL)
    engine = create_async_engine(_DATABASE_URL, poolclass=NullPool)
    try:
        await asyncio.to_thread(_run_migration, "downgrade", "base")
        await asyncio.to_thread(_run_migration, "upgrade", "head")

        tables = await _table_names(engine)
        assert {
            "alembic_version",
            "users",
            "assets",
            "drp_phishing_domains",
            "drp_breaches",
            "reports",
            "jobs",
            "drp_connectors",
            "drp_modules",
            "drp_findings",
            "system_settings",
            "drp_audit_logs",
            "drp_audit_chain",
            "drp_refresh_families",
            "alert_deliveries",
        } <= tables

        async with engine.connect() as connection:
            revision = (
                await connection.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one()
            assert revision == "0001_initial_schema"

            connectors = (
                await connection.execute(
                    text(
                        "SELECT name, connector_type, default_job_type "
                        "FROM drp_connectors ORDER BY name"
                    )
                )
            ).all()
            assert [(row.name, row.connector_type, row.default_job_type) for row in connectors] == [
                ("dnstwist", "phishing", "phishing.dnstwist"),
                ("hibp", "breaches", "breaches.hibp"),
                ("shodan", "phishing", "phishing.shodan"),
            ]

            modules = (
                await connection.execute(
                    text(
                        "SELECT id, label, description, finding_kind, asset_types, "
                        "fields, dedup_fields, title_field, storage, enabled, builtin "
                        "FROM drp_modules ORDER BY id"
                    )
                )
            ).mappings().all()
            assert [(row["id"], row["finding_kind"]) for row in modules] == [
                ("breaches", "breach"),
                ("phishing", "phishing"),
            ]
            # Every seeded value, not just the ids: a module row is data the core
            # dispatches on (``storage.adapter`` selects the write path, and
            # ``dedup_fields`` decides what counts as a duplicate), so a seed that
            # differs from the application's own definition is a functional
            # difference — invisible until a connector submits through that
            # module, and invisible to the SQLite suite, which seeds no rows at
            # all because it builds its schema from the models.
            from app.services.module_registry import BUILTIN_MODULE_DEFINITIONS

            stored = {row["id"]: dict(row) for row in modules}
            for definition in BUILTIN_MODULE_DEFINITIONS:
                row = stored[definition["id"]]
                for key, value in definition.items():
                    assert _as_stored(row[key], key) == value, (
                        f"{definition['id']}.{key} drifted"
                    )
                assert row["enabled"] is True
                assert row["builtin"] is True

            schedule = (
                await connection.execute(
                    text("SELECT schedule_phishing, schedule_breaches FROM system_settings")
                )
            ).one()
            assert schedule.schedule_phishing is not None
            assert schedule.schedule_breaches is not None

        user_columns = await _column_names(engine, "users")
        assert {"rate_limit_minutes", "must_change_password", "must_enrol_mfa", "mfa_failed_attempts", "mfa_locked_until"} <= user_columns
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_full_migration_round_trip_to_base_and_back(monkeypatch):
    """0001_initial_schema must downgrade cleanly to base and re-apply cleanly."""
    monkeypatch.setattr(settings, "DATABASE_URL", _DATABASE_URL)
    engine = create_async_engine(_DATABASE_URL, poolclass=NullPool)
    try:
        await asyncio.to_thread(_run_migration, "upgrade", "head")
        await asyncio.to_thread(_run_migration, "downgrade", "base")

        tables_at_base = await _table_names(engine)
        assert tables_at_base <= {"alembic_version"}
        async with engine.connect() as connection:
            revision = (
                await connection.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one_or_none()
            assert revision is None

        await asyncio.to_thread(_run_migration, "upgrade", "head")
        tables_at_head = await _table_names(engine)
        assert {
            "users",
            "assets",
            "drp_phishing_domains",
            "drp_breaches",
            "reports",
            "jobs",
            "drp_connectors",
            "system_settings",
            "drp_audit_logs",
            "drp_refresh_families",
            "drp_modules",
            "drp_findings",
            "alert_deliveries",
        } <= tables_at_head
        async with engine.connect() as connection:
            revision = (
                await connection.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one()
            assert revision == "0001_initial_schema"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_migrated_schema_matches_orm_metadata(monkeypatch):
    """The check that would have caught the unhealthy backend on 2026-09-24.

    ``SystemSettings`` mapped a ``telegram_chat_id`` column that no revision
    created. The unit suite cannot see that, because it builds its schema with
    ``Base.metadata.create_all`` — from the very metadata under test. This test
    compares the metadata against a database built by the migrations, and a
    disagreement between those two is a startup failure: the lifespan in
    ``app/main.py`` selects every mapped column before the API serves anything.
    """
    from app.core.database import Base

    import app.models  # noqa: F401  (populates Base.metadata)

    monkeypatch.setattr(settings, "DATABASE_URL", _DATABASE_URL)
    engine = create_async_engine(_DATABASE_URL, poolclass=NullPool)
    try:
        await asyncio.to_thread(_run_migration, "downgrade", "base")
        await asyncio.to_thread(_run_migration, "upgrade", "head")
        database_tables = await _table_names(engine)

        problems: list[str] = []
        for table_name, table in sorted(Base.metadata.tables.items()):
            if table_name not in database_tables:
                problems.append(
                    f"{table_name}: mapped by the models but no revision creates it"
                )
                continue
            in_database = await _column_names(engine, table_name)
            mapped = {column.name for column in table.columns}
            for column in sorted(mapped - in_database):
                problems.append(
                    f"{table_name}.{column}: mapped by the models but not created by "
                    f"the migrations"
                )
            for column in sorted(in_database - mapped):
                problems.append(
                    f"{table_name}.{column}: created by the migrations but not mapped "
                    f"by any model"
                )

        assert problems == [], (
            "the migrated schema and Base.metadata disagree — a fresh deployment "
            "reads the models, so every difference here is a failed startup:\n  "
            + "\n  ".join(problems)
        )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_the_startup_seeder_runs_against_a_freshly_migrated_database(monkeypatch):
    """``scripts.seed_defaults``, exactly as the container entrypoint runs it.

    This is the step that actually failed on a fresh deployment: the seeder is
    the first ORM read in the entrypoint, the entrypoint runs with ``set -e``, so
    the container exited before Uvicorn started and Docker reported only
    "unhealthy". Reproducing it here means the next mismatch of this kind fails a
    test rather than a `docker compose up`.
    """
    from app.models import SystemSettings
    from scripts import seed_defaults

    monkeypatch.setattr(settings, "DATABASE_URL", _DATABASE_URL)
    engine = create_async_engine(_DATABASE_URL, poolclass=NullPool)
    try:
        await asyncio.to_thread(_run_migration, "downgrade", "base")
        await asyncio.to_thread(_run_migration, "upgrade", "head")

        await seed_defaults._seed()

        session_factory = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        async with session_factory() as session:
            row = (
                await session.execute(select(SystemSettings).limit(1))
            ).scalar_one_or_none()
        assert row is not None

        async with engine.connect() as connection:
            count = (
                await connection.execute(
                    text("SELECT count(*) FROM system_settings")
                )
            ).scalar_one()
        assert count == 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_version_column_width_matches_the_revision_id_limit(monkeypatch):
    """The migration gate enforces a revision-id length; pin the real width."""
    monkeypatch.setattr(settings, "DATABASE_URL", _DATABASE_URL)
    engine = create_async_engine(_DATABASE_URL, poolclass=NullPool)
    try:
        await asyncio.to_thread(_run_migration, "upgrade", "head")
        async with engine.connect() as connection:
            width = (
                await connection.execute(
                    text(
                        "SELECT character_maximum_length FROM "
                        "information_schema.columns WHERE table_name = "
                        "'alembic_version' AND column_name = 'version_num'"
                    )
                )
            ).scalar_one()
        assert width == REVISION_ID_MAX_LENGTH
    finally:
        await engine.dispose()
