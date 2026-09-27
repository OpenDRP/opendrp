"""The startup migration wrapper must serialise, not merely run.

The property under test is the one that fails silently under two API replicas:
that `upgrade()` never runs on a PostgreSQL database without the advisory lock
held around it. A test that only asserted "upgrade was called" would pass for the
broken implementation, which is what makes these worth writing.
"""

from __future__ import annotations

import pytest

from scripts import migrate

POSTGRES_URL = "postgresql+asyncpg://opendrp:secret@postgres:5432/opendrp"
SQLITE_URL = "sqlite+aiosqlite:///./test.sqlite3"


class _RecordingConnection:
    def __init__(self, events: list[tuple[str, str]]) -> None:
        self._events = events

    def execute(self, statement, parameters=None):  # noqa: ANN001 - SQLAlchemy API
        self._events.append(("execute", str(statement).strip()))
        return None

    def __enter__(self) -> "_RecordingConnection":
        return self

    def __exit__(self, *exc_info) -> bool:
        return False


class _RecordingEngine:
    def __init__(self, events: list[tuple[str, str]]) -> None:
        self._events = events
        self.disposed = False

    def connect(self) -> _RecordingConnection:
        return _RecordingConnection(self._events)

    def dispose(self) -> None:
        self.disposed = True
        self._events.append(("dispose", ""))


@pytest.fixture
def events() -> list[tuple[str, str]]:
    return []


def test_postgres_takes_the_lock_around_the_upgrade(monkeypatch, events):
    engine = _RecordingEngine(events)
    monkeypatch.setattr(migrate, "_sync_url", lambda: POSTGRES_URL)
    monkeypatch.setattr(migrate.sa, "create_engine", lambda *a, **k: engine)
    monkeypatch.setattr(migrate, "upgrade", lambda: events.append(("upgrade", "")))

    assert migrate.main() == 0

    call_order = [name for name, _ in events]
    assert call_order == ["execute", "upgrade", "execute", "dispose"]
    assert events[0][1] == "SELECT pg_advisory_lock(:key)"
    assert events[2][1] == "SELECT pg_advisory_unlock(:key)"
    assert engine.disposed is True


def test_postgres_releases_the_lock_when_the_upgrade_fails(monkeypatch, events):
    """A failed migration must not hold the lock: the next replica would hang."""

    engine = _RecordingEngine(events)
    monkeypatch.setattr(migrate, "_sync_url", lambda: POSTGRES_URL)
    monkeypatch.setattr(migrate.sa, "create_engine", lambda *a, **k: engine)

    def _boom() -> None:
        events.append(("upgrade", ""))
        raise RuntimeError("migration failed")

    monkeypatch.setattr(migrate, "upgrade", _boom)

    with pytest.raises(RuntimeError):
        migrate.main()

    statements = [value for name, value in events if name == "execute"]
    assert statements == [
        "SELECT pg_advisory_lock(:key)",
        "SELECT pg_advisory_unlock(:key)",
    ]
    assert engine.disposed is True


def test_non_postgres_skips_the_lock(monkeypatch, events):
    """SQLite has no advisory locks; the wrapper must not pretend otherwise."""

    def _fail_create_engine(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("no engine should be created for a non-PostgreSQL URL")

    monkeypatch.setattr(migrate, "_sync_url", lambda: SQLITE_URL)
    monkeypatch.setattr(migrate.sa, "create_engine", _fail_create_engine)
    monkeypatch.setattr(migrate, "upgrade", lambda: events.append(("upgrade", "")))

    assert migrate.main() == 0
    assert events == [("upgrade", "")]


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        (POSTGRES_URL, "postgresql+psycopg2://opendrp:secret@postgres:5432/opendrp"),
        ("postgresql://user:pw@db:5432/x", "postgresql+psycopg2://user:pw@db:5432/x"),
        ("postgres://user:pw@db:5432/x", "postgresql+psycopg2://user:pw@db:5432/x"),
        # Not PostgreSQL: left alone, because the lock path is skipped for it.
        (SQLITE_URL, SQLITE_URL),
    ],
)
def test_sync_url_selects_a_synchronous_driver(monkeypatch, configured, expected):
    """`env.py` rebuilds the URL for Alembic; the lock connection needs its own."""
    monkeypatch.setattr(migrate.settings, "DATABASE_URL", configured)
    assert migrate._sync_url() == expected
