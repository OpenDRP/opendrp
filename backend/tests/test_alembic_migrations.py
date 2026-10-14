"""Alembic migration tests against a real PostgreSQL database.

Verifies the single baseline revision: table creation, extensions, indexes,
defaults, the declarations it seeds, and the downgrade round trip.

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
from scripts import migrate as services_migrate
from scripts.check_migrations import REVISION_ID_MAX_LENGTH

_DATABASE_URL = os.environ.get("INTEGRATION_MIGRATION_DATABASE_URL")


def _key_expression(column: str) -> str:
    """``sql_key`` as PostgreSQL stores it: ``lower(rtrim(trim(x), '.'))``."""
    return f"lower(rtrim(trim(bothfrom{column}),'.'::text))"
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
        return set(
            await connection.run_sync(lambda sync: inspect(sync).get_table_names())
        )


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


def _json_value(value):
    """A JSON column as Python, whichever layer decoded it."""
    import json

    return json.loads(value) if isinstance(value, str) else value


async def _column_names(engine, table_name: str) -> set[str]:
    async with engine.connect() as connection:
        return set(
            await connection.run_sync(
                lambda sync: {
                    column["name"] for column in inspect(sync).get_columns(table_name)
                }
            )
        )


@pytest.mark.asyncio
async def test_clean_database_upgrades_to_head_and_seeds_required_registry(monkeypatch):
    """A fresh PostgreSQL database reaches the head and holds the declarations.

    The baseline is the whole history, so this is what a new installation is:
    the schema plus the platform's own registry rows, and nothing else.
    """
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
            "dns_security_observations",
            "source_observations",
            "dns_expiry_monitors",
            "ingestion_events",
            "source_accounts",
        } <= tables

        async with engine.connect() as connection:
            revision = (
                await connection.execute(
                    text("SELECT version_num FROM alembic_version")
                )
            ).scalar_one()
            assert revision == _head_revision()

            connectors = (
                await connection.execute(
                    text(
                        "SELECT id,name,connector_type,default_job_type,aliases,status,config,token_hash,last_seen_at,last_error,api_version "
                        "FROM drp_connectors ORDER BY name"
                    )
                )
            ).all()
            #: The registry the baseline seeds: every standard label follows
            #: `<module>-<provider>[-<task>]`, and the module a connector feeds is
            #: the module id itself.
            expected_connectors = sorted(
                [
                    ("breaches-hibp", "breaches", "breaches.hibp"),
                    ("dns-ctlogs", "dns", "dns.ctlogs"),
                    ("dns-netlas", "dns", "dns.netlas"),
                    ("dns-rdap", "dns", "dns.rdap"),
                    ("dns-resolver", "dns", "dns.resolver"),
                    ("dns-virustotal", "dns", "dns.virustotal"),
                    ("exposure-netlas", "exposure", "exposure.netlas"),
                    ("phishing-dnstwist", "phishing", "phishing.dnstwist"),
                    ("phishing-netlas", "phishing", "phishing.netlas"),
                    ("phishing-shodan", "phishing", "phishing.shodan"),
                ]
            )
            assert [
                (row.name, row.connector_type, row.default_job_type)
                for row in connectors
            ] == expected_connectors
            aliases = {row.name: row.aliases for row in connectors}
            #: A connector answers to every spelling it has ever had, and the
            #: *first* alias is the value a source identity is derived from. That
            #: order is the whole point: it is what keeps an already-issued token
            #: authenticating and an existing observation attached to the provider
            #: that reported it.
            assert aliases["phishing-shodan"] == ["shodan", "shodan-phishing-default"]
            shipped = {row.name: row for row in connectors}
            #: Where a row's settings live: the keyed provider an operator switches
            #: on by hand carries an empty config for them to fill in, while the
            #: rows a Compose profile enables are declared with none. The account
            #: the quota is drawn from holds the credential either way, and the
            #: application reads both spellings as "no settings yet".
            assert _json_value(shipped["dns-netlas"].config) == {}
            assert shipped["phishing-shodan"].config is None
            assert shipped["dns-virustotal"].config is None
            assert shipped["phishing-dnstwist"].config is None
            assert shipped["phishing-dnstwist"].token_hash is None
            assert shipped["phishing-dnstwist"].status == "enabled"

            assert aliases["breaches-hibp"] == ["hibp", "hibp-breaches-default"]
            assert aliases["dns-rdap"] == ["dns-rdap", "rdap-dns-security-default"]
            assert aliases["dns-resolver"] == [
                "dns-resolver",
                "resolver-dns-security-default",
            ]
            assert aliases["dns-ctlogs"] == ["dns-ctlogs", "ctlogs-dns-security-default"]
            assert aliases["dns-virustotal"] == [
                "dns-virustotal",
                "virustotal-dns-security-default",
            ]
            #: Every connector carries at least one alias. Together with the name
            #: they are the spellings a worker may authenticate under, so a label
            #: that stops being accepted breaks tokens and source identity without
            #: failing a single scan.
            assert all(row.aliases for row in connectors)
            #: One account per *provider*, and only for the providers this release
            #: ships. A withdrawn provider has no account here, because a seeded
            #: row that cannot run is a row an operator has to clean up.
            accounts = (
                await connection.execute(
                    text(
                        "SELECT source_id, name, policy, access_state FROM "
                        "source_accounts ORDER BY source_id"
                    )
                )
            ).all()
            assert [(row.source_id, row.name) for row in accounts] == [
                ("netlas", "default"),
                ("shodan", "default"),
                ("virustotal", "default"),
            ]
            #: A seeded account declares that the provider exists; it does not
            #: decide that using it is allowed, so none of them is approved.
            assert all(
                _json_value(row.policy) == {"approved": False} for row in accounts
            )
            assert {row.access_state for row in accounts} == {"unknown"}
            assert (
                await connection.execute(
                    text("SELECT count(*) FROM drp_connectors WHERE aliases IS NULL")
                )
            ).scalar_one() == 0
            opt_in = (
                await connection.execute(
                    text(
                        "SELECT status, provider, quota_group FROM drp_connectors WHERE provider IS NOT NULL"
                    )
                )
            ).all()
            #: Netlas is the optional passive provider that ships switched off, so
            #: its three workers are the whole opt-in set: seeded disabled, waiting
            #: for an operator's key, an approved quota and explicit enablement.
            #: Shodan and VirusTotal are provider-backed too, and are enabled by
            #: the profile that starts them rather than by a seeded registry row.
            assert len(opt_in) == 5
            assert all(row.quota_group == "default" for row in opt_in)
            assert sorted(row.provider for row in opt_in) == [
                "netlas",
                "netlas",
                "netlas",
                "shodan",
                "virustotal",
            ]
            assert sorted(
                row.provider for row in opt_in if row.status == "disabled"
            ) == ["netlas", "netlas", "netlas"]
            #: A fresh installation seeds the platform's own declarations and
            #: nothing else. Everything that carries an observation, a finding or
            #: a queue position starts empty, so the operator's first scan is the
            #: first row in each of these tables.
            for table in (
                "source_observations",
                "dns_security_observations",
                "dns_expiry_monitors",
                "drp_findings",
                "drp_phishing_domains",
                "drp_breaches",
                "assets",
                "jobs",
                "schedule_occurrences",
                "audit_archives",
                "report_artifact_cleanup",
                "report_audit_outbox",
            ):
                assert (
                    await connection.execute(text(f"SELECT count(*) FROM {table}"))
                ).scalar_one() == 0, f"{table} is not empty on a fresh install"

            modules = (
                (
                    await connection.execute(
                        text(
                            "SELECT id, label, description, finding_kind, asset_types, "
                            "fields, dedup_fields, title_field, storage, enabled, builtin "
                            "FROM drp_modules ORDER BY id"
                        )
                    )
                )
                .mappings()
                .all()
            )
            assert [(row["id"], row["finding_kind"]) for row in modules] == [
                ("breaches", "breach"),
                ("dns", "dns_observation"),
                ("exposure", "exposure"),
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
                    assert (
                        _as_stored(row[key], key) == value
                    ), f"{definition['id']}.{key} drifted"
                assert row["enabled"] is True
                assert row["builtin"] is True

            schedule = (
                await connection.execute(
                    text(
                        "SELECT schedule_phishing, schedule_breaches, "
                        "schedule_dns_security, schedule_exposure, schedules FROM system_settings"
                    )
                )
            ).one()
            assert schedule.schedule_phishing is not None
            assert schedule.schedule_breaches is not None
            assert schedule.schedule_dns_security is not None
            assert schedule.schedule_exposure is None
            assert schedule.schedules is None

        user_columns = await _column_names(engine, "users")
        assert {
            "rate_limit_minutes",
            "must_change_password",
            "must_enrol_mfa",
            "mfa_failed_attempts",
            "mfa_locked_until",
        } <= user_columns
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_full_migration_round_trip_to_base_and_back(monkeypatch):
    """The baseline must downgrade cleanly and re-apply."""
    monkeypatch.setattr(settings, "DATABASE_URL", _DATABASE_URL)
    engine = create_async_engine(_DATABASE_URL, poolclass=NullPool)
    try:
        await asyncio.to_thread(_run_migration, "upgrade", "head")
        await asyncio.to_thread(_run_migration, "downgrade", "base")

        tables_at_base = await _table_names(engine)
        assert tables_at_base <= {"alembic_version"}
        async with engine.connect() as connection:
            revision = (
                await connection.execute(
                    text("SELECT version_num FROM alembic_version")
                )
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
            "dns_security_observations",
            "source_observations",
            "dns_expiry_monitors",
            "ingestion_events",
            "source_accounts",
        } <= tables_at_head
        async with engine.connect() as connection:
            revision = (
                await connection.execute(
                    text("SELECT version_num FROM alembic_version")
                )
            ).scalar_one()
            assert revision == _head_revision()
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
                await connection.execute(text("SELECT count(*) FROM system_settings"))
            ).scalar_one()
        assert count == 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_asset_matching_order_and_search_indexes_exist(monkeypatch):
    """WI-15: the predicates that read by asset, the list order and substring search.

    Every asset-scoped read filters on the module's denormalized ``matched_*``
    column, and every page of the asset list orders by ``created_at, id`` — both
    were sequential scans (AST-17/18). Substring search (``ILIKE '%term%'``) keeps
    its own access path, a trigram GIN index (AST-19), which is why the
    ``pg_trgm`` extension has to be installable by the migrating role.
    """
    monkeypatch.setattr(settings, "DATABASE_URL", _DATABASE_URL)
    engine = create_async_engine(_DATABASE_URL, poolclass=NullPool)
    btree_indexes = {
        "drp_phishing_domains": "ix_drp_phishing_domains_matched_asset",
        "drp_findings": "ix_drp_findings_matched_asset",
        "source_observations": "ix_source_observations_matched_asset",
        "assets": "ix_assets_created_at_id",
    }
    trigram_indexes = (
        "ix_assets_normalized_value_trgm",
        "ix_assets_asset_value_trgm",
    )
    try:
        await asyncio.to_thread(_run_migration, "downgrade", "base")
        await asyncio.to_thread(_run_migration, "upgrade", "head")

        async with engine.connect() as connection:
            for table, index in btree_indexes.items():
                names = await connection.run_sync(
                    lambda sync, table=table: {
                        item["name"] for item in inspect(sync).get_indexes(table)
                    }
                )
                assert index in names, f"{table} is missing {index}"
            definitions = {
                name: definition
                for name, definition in (
                    await connection.execute(
                        text(
                            "SELECT indexname, indexdef FROM pg_indexes "
                            "WHERE indexname = ANY(:names)"
                        ),
                        {"names": list(trigram_indexes)},
                    )
                ).all()
            }
        assert set(definitions) == set(trigram_indexes), definitions
        for name, definition in definitions.items():
            assert "USING gin" in definition, definition
            assert "gin_trgm_ops" in definition, definition

        # Dropping the only revision removes both index families and leaves the
        # extension alone: it is database-wide, and an operator's own query may be
        # using it.
        await asyncio.to_thread(_run_migration, "downgrade", "base")
        async with engine.connect() as connection:
            remaining = (
                await connection.execute(
                    text(
                        "SELECT count(*) FROM pg_indexes WHERE indexname = ANY(:names)"
                    ),
                    {"names": [*btree_indexes.values(), *trigram_indexes]},
                )
            ).scalar_one()
            assert remaining == 0, "downgrade left the new indexes behind"
            installed = (
                await connection.execute(
                    text("SELECT count(*) FROM pg_extension WHERE extname = 'pg_trgm'")
                )
            ).scalar_one()
            assert installed == 1, "downgrade removed the shared pg_trgm extension"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_the_timed_reads_are_backed_by_their_own_indexes(monkeypatch):
    """A-20: the two reads that happen on a timer, each with an access path.

    ``ConnectorService.claim_work`` filters on ``status='pending'`` and orders by
    ``created_at``; it is the read every connector makes on every poll, which
    makes it the most frequent one this table has. ``dispatch_notification_events``
    and ``enrich_one_event`` filter on ``kind``, ``processed_at IS NULL`` and a due
    ``next_attempt_at`` every fifteen seconds, over the rows the retention window
    keeps — the whole table the dispatcher exists to drain. A single-column index
    serves neither predicate, and the DDL lives in one place, so this asserts the
    composites are there after a real migration and gone after the downgrade.
    """
    monkeypatch.setattr(settings, "DATABASE_URL", _DATABASE_URL)
    engine = create_async_engine(_DATABASE_URL, poolclass=NullPool)
    expected = {
        "jobs": "ix_jobs_status_created",
        "ingestion_events": "ix_ingestion_events_due",
    }
    try:
        await asyncio.to_thread(_run_migration, "downgrade", "base")
        await asyncio.to_thread(_run_migration, "upgrade", "head")

        async with engine.connect() as connection:
            for table, index in expected.items():
                names = await connection.run_sync(
                    lambda sync, table=table: {
                        item["name"] for item in inspect(sync).get_indexes(table)
                    }
                )
                assert index in names, f"{table} is missing {index}: {sorted(names)}"

        await asyncio.to_thread(_run_migration, "downgrade", "base")
        async with engine.connect() as connection:
            remaining = (
                await connection.execute(
                    text(
                        "SELECT count(*) FROM pg_indexes WHERE indexname = ANY(:names)"
                    ),
                    {"names": list(expected.values())},
                )
            ).scalar_one()
        assert remaining == 0, "downgrade left the claim/outbox indexes behind"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_the_matching_rule_is_backed_by_expression_indexes(monkeypatch):
    """WI-20: the indexes the matched predicates can actually use.

    The ``matched_*`` columns are also indexed as stored, but the matching rule
    compares ``lower(rtrim(trim(x), '.'))`` — an index on the bare column is not
    usable by that expression, so every asset-scoped lookup scanned the table.
    These expression indexes match the predicate character for character, which is
    what turns the involvement counters and the ``has_findings`` filter into index
    lookups. The email domain index is the email-to-domain branch of the rule.
    """
    monkeypatch.setattr(settings, "DATABASE_URL", _DATABASE_URL)
    engine = create_async_engine(_DATABASE_URL, poolclass=NullPool)
    #: ``index name -> the expression PostgreSQL stores``. ``sql_key`` renders
    #: ``lower(rtrim(trim(x), '.'))``, which the server normalizes to the text
    #: below; the email domain branch is ``EmailDomain``'s PostgreSQL rendering.
    expression_indexes = {
        "ix_drp_phishing_domains_matched_asset_key": _key_expression("matched_asset"),
        "ix_drp_findings_matched_asset_key": _key_expression("matched_asset"),
        "ix_source_observations_matched_asset_key": _key_expression("matched_asset"),
        "ix_dns_security_observations_subject_key": _key_expression("subject"),
        "ix_dns_security_observations_value_key": _key_expression("value"),
        "ix_drp_breaches_matched_domain_key": _key_expression("matched_domain"),
        "ix_drp_breaches_matched_email_key": _key_expression("matched_email"),
        "ix_drp_breaches_matched_email_domain": (
            "lower(split_part((matched_email)::text,'@'::text,2))"
        ),
        "ix_assets_normalized_value_key": (
            "lower(rtrim(trim(bothfromcoalesce(normalized_value,asset_value)),'.'::text))"
        ),
    }
    try:
        await asyncio.to_thread(_run_migration, "downgrade", "base")
        await asyncio.to_thread(_run_migration, "upgrade", "head")

        async with engine.connect() as connection:
            definitions = {
                name: definition
                for name, definition in (
                    await connection.execute(
                        text(
                            "SELECT indexname, indexdef FROM pg_indexes "
                            "WHERE indexname = ANY(:names)"
                        ),
                        {"names": list(expression_indexes)},
                    )
                ).all()
            }
        assert set(definitions) == set(expression_indexes), definitions
        for name, fragment in expression_indexes.items():
            # The planner only uses an expression index whose expression it finds
            # verbatim, so the index text is the contract, not a detail.
            normalized = definitions[name].lower().replace(" ", "").replace('"', "")
            assert fragment.replace(" ", "") in normalized, definitions[name]

        # The only revision there is owns these indexes, so dropping it removes
        # them: nothing in the schema outlives the baseline.
        await asyncio.to_thread(_run_migration, "downgrade", "base")
        async with engine.connect() as connection:
            remaining = (
                await connection.execute(
                    text("SELECT count(*) FROM pg_indexes WHERE indexname = ANY(:names)"),
                    {"names": list(expression_indexes)},
                )
            ).scalar_one()
            assert remaining == 0, "downgrade left the expression indexes behind"
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


@pytest.mark.asyncio
async def test_a_database_whose_recorded_revision_vanished_is_adopted(monkeypatch):
    """The upgrade path for an installation created before the history collapsed.

    Such a database holds the schema the baseline creates while recording an id
    whose file is gone, which is the one state Alembic refuses to move. The
    wrapper records the baseline, and the upgrade that follows must then be a
    no-op — not a second creation of tables that already exist. `alembic stamp`
    is not a candidate here: it reads the recorded revision before writing and
    fails on this database, which is why the wrapper writes the row itself.
    """
    monkeypatch.setattr(settings, "DATABASE_URL", _DATABASE_URL)
    engine = create_async_engine(_DATABASE_URL, poolclass=NullPool)
    vanished = "0016_vanished_revision"
    try:
        await asyncio.to_thread(_run_migration, "upgrade", "head")
        head = _head_revision()
        async with engine.begin() as connection:
            await connection.execute(
                text("UPDATE alembic_version SET version_num = :vanished"),
                {"vanished": vanished},
            )

        async with engine.connect() as connection:
            # The state the wrapper must recognise as "not one of ours any more".
            assert services_migrate._unresolvable(
                services_migrate._alembic_config(), vanished
            )
            await connection.run_sync(services_migrate._adopt)

        async with engine.connect() as connection:
            recorded = (
                await connection.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one()
        assert recorded == head

        # The recorded revision makes the next start a no-op, not an error.
        await asyncio.to_thread(_run_migration, "upgrade", "head")
        async with engine.connect() as connection:
            assert (
                await connection.execute(
                    text("SELECT count(*) FROM drp_modules WHERE builtin IS TRUE")
                )
            ).scalar_one() == 4
    finally:
        await engine.dispose()
