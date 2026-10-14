"""Adopting a database whose recorded revision this checkout cannot resolve.

A database created before the migration history was collapsed records a revision
id whose file is gone. Alembic cannot resolve an id it does not have: it aborts
rather than moving the schema forward, so the API container would enter a restart
loop on the one deployment that most needs to come up. `scripts.migrate` records
the baseline for exactly that database, and these tests pin the three decisions
that make the adoption safe:

* a database with no record at all is left to the upgrade that follows;
* a revision this checkout *does* know about is moved by the upgrade, never
  rewritten — replacing the record of a schema nobody checked is how a real
  migration gets silently skipped;
* a database without this platform's own tables is refused, because adoption
  asserts something about a schema and the assertion is checkable.

The write itself goes through the connection the wrapper already holds rather
than through `alembic stamp`, which resolves the recorded heads before it writes
and therefore fails on the one database this function exists for. The end-to-end
half — a real PostgreSQL database whose record is replaced and then adopted —
lives in ``test_alembic_migrations.py``, next to the other tests that need a
server.
"""

from __future__ import annotations

import pytest

from scripts import migrate

_VANISHED = "0016_vanished_revision"


class _ScalarResult:
    """The two shapes `_adopt` reads: a scalar and a list of scalars."""

    def __init__(self, values) -> None:
        self._values = list(values)

    def scalar(self):
        return self._values[0] if self._values else None

    def scalars(self):
        return self

    def all(self):
        return list(self._values)


class _ScriptedConnection:
    """Answers the queries the adoption step makes, in any order.

    The write to `alembic_version` is recorded rather than executed: the upgrade
    that follows reads it on a connection of its own, so an uncommitted write is
    an invisible one, and both facts are asserted on here.
    """

    def __init__(self, *, revision=None, tables=(), rows=None) -> None:
        self._revision_present = revision is not None or rows is not None
        self._rows = list(rows) if rows is not None else ([revision] if revision else [])
        self._tables = list(tables)
        self.adopted: list[str] = []
        self.commits = 0

    def execute(self, statement, parameters=None):  # noqa: ANN001 - SQLAlchemy API
        sql = str(statement)
        if "to_regclass" in sql:
            return _ScalarResult([1 if self._revision_present else None])
        if "information_schema.tables" in sql:
            return _ScalarResult(self._tables)
        if sql.startswith("UPDATE alembic_version"):
            assert parameters is not None
            self.adopted.append(parameters["head"])
            return None
        if "version_num" in sql:
            return _ScalarResult(self._rows)
        raise AssertionError(f"unexpected statement: {sql}")

    def commit(self) -> None:
        self.commits += 1


def test_no_version_table_is_not_an_adoption() -> None:
    connection = _ScriptedConnection(tables=("drp_modules", "jobs"))

    migrate._adopt(connection)

    assert connection.adopted == []


def test_a_revision_this_checkout_knows_is_left_to_the_upgrade() -> None:
    connection = _ScriptedConnection(
        revision="0001_initial_schema", tables=("drp_modules", "drp_audit_logs", "jobs")
    )

    migrate._adopt(connection)

    assert connection.adopted == []


def test_a_vanished_revision_is_adopted_as_the_baseline() -> None:
    connection = _ScriptedConnection(
        revision=_VANISHED, tables=("drp_modules", "drp_audit_logs", "jobs")
    )

    migrate._adopt(connection)

    assert connection.adopted == ["0001_initial_schema"]
    assert connection.commits == 1, "the upgrade that follows reads it on its own connection"


def test_a_schema_without_this_platforms_tables_is_refused() -> None:
    connection = _ScriptedConnection(revision=_VANISHED, tables=("orders", "customers"))

    with pytest.raises(RuntimeError, match="not an OpenDRP schema"):
        migrate._adopt(connection)

    assert connection.adopted == []


def test_more_than_one_recorded_revision_is_refused() -> None:
    connection = _ScriptedConnection(
        rows=[_VANISHED, "0001_initial_schema"],
        tables=("drp_modules", "drp_audit_logs", "jobs"),
    )

    with pytest.raises(RuntimeError, match="more than one revision"):
        migrate._adopt(connection)

    assert connection.adopted == []


def test_the_adoption_runs_before_the_upgrade(monkeypatch) -> None:
    """The rewritten record is what makes the upgrade a no-op; the order is it."""
    order: list[str] = []
    monkeypatch.setattr(migrate, "_sync_url", lambda: "postgresql+asyncpg://u:p@h:5432/d")
    monkeypatch.setattr(migrate.sa, "create_engine", lambda *a, **k: _Engine(order))
    monkeypatch.setattr(
        migrate,
        "_adopt",
        lambda connection: order.append("adopt"),
    )
    monkeypatch.setattr(migrate, "upgrade", lambda: order.append("upgrade"))

    assert migrate.main() == 0
    assert order == ["lock", "adopt", "upgrade", "unlock", "dispose"]


class _EngineConnection:
    def __init__(self, order: list[str]) -> None:
        self._order = order

    def execute(self, statement, parameters=None):  # noqa: ANN001 - SQLAlchemy API
        sql = str(statement)
        self._order.append("unlock" if "unlock" in sql else "lock")
        return None

    def __enter__(self) -> "_EngineConnection":
        return self

    def __exit__(self, *exc_info) -> bool:
        return False


class _Engine:
    def __init__(self, order: list[str]) -> None:
        self._order = order

    def connect(self) -> _EngineConnection:
        return _EngineConnection(self._order)

    def dispose(self) -> None:
        self._order.append("dispose")
