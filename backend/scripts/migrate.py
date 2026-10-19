"""Apply Alembic migrations once, even when several containers start together.

The API container migrates its own schema at startup, which is convenient — an
operator who raises `OPENDRP_VERSION` and restarts gets a consistent deployment
without remembering a second step — and is a race the moment there is more than
one replica: `alembic upgrade head` has no lock of its own, so two containers
starting at the same moment both inspect the current revision, both decide the
same migration is pending, and both apply it. Depending on the migration that is
either an error (a duplicate object) or a silent double-apply of data
transformation, and it is the failure mode that appears exactly when someone
scales the API out.

PostgreSQL's advisory lock is the fix that does not add a coordinator: it is
taken on the *database*, so it serialises every process that can reach the schema
regardless of which host, container or orchestrator it runs in. The second
replica blocks until the first has finished, then runs `upgrade head` and finds
nothing to do — a no-op rather than a failure.

This is strictly a *deployment* convenience. Alembic itself remains the
supported way to move the schema (`docker compose exec backend alembic upgrade
head`, `alembic downgrade`), and both paths end in the same revision graph; the
wrapper only serialises the automatic path.

It also *adopts* a database that records a revision this checkout does not
contain. That is the state of every installation created before the migration
history was collapsed into the single baseline: its schema is the schema the
baseline creates, but the revision id it recorded belonged to a file that no
longer exists, and Alembic cannot resolve such an id — it aborts with "Can't
locate revision" rather than moving the database forward. Recording the baseline
is the correct move for exactly that database, and doing it here means an
operator who pulls a new image and restarts does not have to know that the
record was rewritten. The adoption is deliberately narrow: it requires the
recorded id to be one this checkout cannot resolve *and* the database to carry
this platform's own tables, so the record is never replaced on an unrelated
schema. `alembic stamp` cannot make this edit — it resolves the recorded heads
before it writes, so it fails with the same "Can't locate revision" on the one
database being repaired — which is why the row is written directly, under the
migration lock (`tests/test_alembic_migrations.py` runs that end to end against
PostgreSQL).
"""

from __future__ import annotations

import sys
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.util import CommandError

from app.core.config import settings
from app.core.logging_config import configure_logging, get_logger

# Called at import for the same reason `app.core.audit` does it: without it this
# script's records have no handler, and a startup step whose output is silently
# discarded is a step nobody can debug from `docker compose logs`.
configure_logging()

#: Any constant works as long as every process agrees on it. Spelled as ASCII
#: ("OpenDRP1") so that a lock accidentally left behind in a bug report is
#: recognisable in `pg_locks` rather than an unexplained number.
MIGRATION_LOCK_KEY = 0x4F70656E44525031

BACKEND_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
ALEMBIC_DIR = BACKEND_DIR / "alembic"

log = get_logger("opendrp.migrate")

_LOCK_SQL = "SELECT pg_advisory_lock(:key)"
_UNLOCK_SQL = "SELECT pg_advisory_unlock(:key)"

#: Tables a database must already have before its recorded revision is replaced
#: with the baseline. Adoption asserts "this schema is the one the baseline
#: creates", so the assertion is worth checking: these three are the tables every
#: installation of this platform has written to since the first release, and a
#: schema without them is not this platform's.
_ADOPTION_SENTINELS = ("drp_audit_logs", "drp_modules", "jobs")


def _sync_url() -> str:
    """The database URL with a *synchronous* driver.

    The advisory lock is taken on a plain connection, and Alembic's `env.py`
    already rebuilds the URL itself — this only exists so the lock does not need
    an async engine for the sake of one statement.
    """
    url = settings.DATABASE_URL
    if "+asyncpg" in url:
        return url.replace("+asyncpg", "+psycopg2")
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg2://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url


def _alembic_config() -> Config:
    """An Alembic config that does not depend on the current directory.

    `script_location` in `alembic.ini` is relative, and a relative location is
    resolved against the working directory — which is `/app` in the image but
    `backend/` in a test run. Setting it to the absolute path makes the wrapper
    behave identically in both.
    """
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_DIR))
    return config


def upgrade() -> None:
    """Run `alembic upgrade head`."""
    command.upgrade(_alembic_config(), "head")


def _recorded_revision(connection: sa.Connection) -> str | None:
    """The revision Alembic recorded, or ``None`` for a database with no record.

    A database nobody has migrated has no version table at all, which is not a
    state to adopt — the upgrade that follows creates it.
    """
    if connection.execute(
        sa.text("SELECT to_regclass('public.alembic_version')")
    ).scalar() is None:
        return None
    recorded = connection.execute(
        sa.text("SELECT version_num FROM alembic_version")
    ).scalars().all()
    if len(recorded) > 1:
        raise RuntimeError(
            "alembic_version holds more than one revision "
            f"({', '.join(sorted(recorded))}); reconcile the schema by hand "
            "before starting the API again"
        )
    return recorded[0] if recorded else None


def _unresolvable(config: Config, revision: str) -> bool:
    """Whether this checkout cannot resolve a recorded revision id."""
    try:
        ScriptDirectory.from_config(config).get_revision(revision)
    except (CommandError, KeyError):
        return True
    return False


def _adopt(connection: sa.Connection) -> None:
    """Record the baseline on a database whose recorded revision is gone.

    Called with the migration lock already held, so two replicas starting
    together cannot both decide to adopt.
    """
    recorded = _recorded_revision(connection)
    if recorded is None:
        return
    config = _alembic_config()
    if not _unresolvable(config, recorded):
        # A revision this checkout knows about: `upgrade head` moves it, and
        # replacing the record would be a comment on a schema nobody checked.
        return

    present = set(
        connection.execute(
            sa.text("SELECT table_name FROM information_schema.tables " "WHERE table_schema = 'public'")
        ).scalars().all()
    )
    missing = [table for table in _ADOPTION_SENTINELS if table not in present]
    if missing:
        raise RuntimeError(
            f"this database records revision {recorded!r}, which this checkout "
            f"cannot resolve, and it lacks {', '.join(missing)} — it is not an "
            "OpenDRP schema, so its recorded revision is not going to be "
            "replaced. Point DATABASE_URL at the installation's database."
        )

    head = ScriptDirectory.from_config(config).get_current_head()
    # Written as an UPDATE rather than through `alembic stamp`: stamp reads the
    # recorded heads from the database before it writes, so it raises "Can't
    # locate revision" on exactly the database this function was written for.
    # `alembic_version` is Alembic's own one-row table, so the edit is the one
    # stamp would have made, and it is committed before the upgrade that follows
    # opens its own connection.
    connection.execute(
        sa.text("UPDATE alembic_version SET version_num = :head"), {"head": head}
    )
    connection.commit()
    log.info(
        "migration_adopted", recorded_revision=recorded, revision=head
    )


def main() -> int:
    url = _sync_url()

    if not url.startswith("postgresql"):
        # SQLite (the test suite, and nothing else) has no advisory locks and is
        # never opened by two processes at once, so the lock would only be
        # ceremony. Anything non-PostgreSQL reaching production is already a
        # configuration error that config.py rejects.
        upgrade()
        return 0

    # The statement bound the revision runs under is set here too, and the lock
    # bound deliberately is not: this connection exists to *wait* for the migration
    # slot (`tests/test_migrate_lock.py` pins that a second replica queues and then
    # finds nothing to do), and `lock_timeout` is exactly what would abandon that
    # wait. The bound that matters — a DDL statement behind somebody else's open
    # transaction — belongs to the connection `alembic/env.py` opens, which carries
    # `migration_server_settings()`.
    engine = sa.create_engine(
        url,
        poolclass=sa.pool.NullPool,
        connect_args={
            "options": "-c statement_timeout="
            + str(int(settings.MIGRATION_STATEMENT_TIMEOUT_MS))
        },
    )
    try:
        with engine.connect() as lock_connection:
            lock_connection.execute(sa.text(_LOCK_SQL), {"key": MIGRATION_LOCK_KEY})
            log.info("migration_lock_acquired", key=MIGRATION_LOCK_KEY)
            try:
                _adopt(lock_connection)
                upgrade()
            finally:
                # Released explicitly rather than left to session teardown: a
                # pooled connection returned to the pool with the lock still held
                # would block every later migration.
                lock_connection.execute(
                    sa.text(_UNLOCK_SQL), {"key": MIGRATION_LOCK_KEY}
                )
                log.info("migration_lock_released", key=MIGRATION_LOCK_KEY)
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
