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
"""

from __future__ import annotations

import sys
from pathlib import Path

import sqlalchemy as sa
from alembic import command
from alembic.config import Config

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


def main() -> int:
    url = _sync_url()

    if not url.startswith("postgresql"):
        # SQLite (the test suite, and nothing else) has no advisory locks and is
        # never opened by two processes at once, so the lock would only be
        # ceremony. Anything non-PostgreSQL reaching production is already a
        # configuration error that config.py rejects.
        upgrade()
        return 0

    engine = sa.create_engine(url, poolclass=sa.pool.NullPool)
    try:
        with engine.connect() as lock_connection:
            lock_connection.execute(sa.text(_LOCK_SQL), {"key": MIGRATION_LOCK_KEY})
            log.info("migration_lock_acquired", key=MIGRATION_LOCK_KEY)
            try:
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
