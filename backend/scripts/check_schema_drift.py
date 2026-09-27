"""Gate that compares the ORM models with the schema the revisions build.

The failure this exists for: ``SystemSettings`` mapped a ``telegram_chat_id``
column that the consolidated baseline revision never created. Nothing caught it,
and nothing *could* have:

* the unit suite builds its schema with ``Base.metadata.create_all`` — from the
  very metadata under test — so a column no migration creates still exists in the
  test database, and every query against it passes;
* the PostgreSQL migration test asserted a hand-written subset of tables and
  columns, which did not include this one;
* ``check_migrations.py`` reads the *graph* of revisions (single head, ancestry,
  table names that must exist by then) and never looks at a model at all.

The first place the mismatch became visible was a fresh deployment:
``scripts.seed_defaults`` — and, on any deployment where the seeder had already
run, the lifespan in ``app/main.py`` — issued ``SELECT ... telegram_chat_id
...``, PostgreSQL answered ``UndefinedColumnError``, the ``set -e`` entrypoint
exited, the container entered a restart loop, and ``docker compose up`` reported
only ``dependency failed to start: container opendrp-backend is unhealthy``. A
green test suite and a container that cannot boot.

This gate asks the one question none of those asked: **does the schema the
revisions build contain exactly the tables and columns the models map?** Both
directions are checked, because a column only one side knows about is a defect
either way:

* *mapped, not created* — the ORM's statements name a column that does not
  exist, so the process cannot start against a database built from these
  revisions, and the failure surfaces as an unhealthy container rather than a
  failing test;
* *created, not mapped* — schema nobody reads: what a half-finished cleanup
  leaves behind, and a column the platform would keep around forever.

The schema is reconstructed from revision sources with the same AST reading
``check_migrations.py`` uses for its own table walk — ``op.create_table`` and
``op.add_column`` add, ``op.drop_column`` and ``op.drop_table`` remove,
``op.rename_table`` moves — applied in ancestry order from ``base`` to head. No
database, no Alembic runtime, no Docker: it runs in milliseconds on every push,
before anyone builds an image.

Two limits, stated rather than hidden:

* DDL written as raw SQL through ``op.execute`` is invisible to an AST read, so
  a revision that adds a column that way must be reflected here explicitly. The
  shipped baseline expresses every column through ``op.*`` (its ``op.execute``
  calls only create the two enum types, the audit sequence and the extension);
* a column name the gate cannot read is reported as a failure rather than
  skipped. Guessing would make the gate able to invent a finding, and a gate
  that cries wolf gets switched off.

Usage:

    python -m scripts.check_schema_drift [VERSIONS_DIR]
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    # Makes `python scripts/check_schema_drift.py` work as well as
    # `python -m scripts.check_schema_drift`. The file form puts the *scripts*
    # directory at ``sys.path[0]``, while both ``app`` and ``scripts`` are
    # imported below and live one level up.
    sys.path.insert(0, str(_BACKEND_ROOT))

from sqlalchemy import MetaData  # noqa: E402

from scripts.check_migrations import (  # noqa: E402
    _TABLES_OUTSIDE_MIGRATIONS,
    Revision,
    _ancestry_order,
    _literal_string,
    _load_revisions,
)

#: ``sa.Column``, spelled with or without its module prefix.
_COLUMN_CALL = "Column"

#: Tables a revision may create that no model maps. Empty, and meant to stay
#: that way: in a migration-driven platform every table exists because a model
#: reads it. An entry here is a decision to keep dead schema, so it belongs in a
#: commit message rather than in this file's history.
_DB_ONLY_TABLES: set[str] = set()

#: ``(table, column)`` pairs a revision may create that no model maps. The
#: escape hatch for a genuinely database-only column — a generated or identity
#: column the ORM deliberately does not map. Empty today.
_DB_ONLY_COLUMNS: set[tuple[str, str]] = set()

_DEFAULT_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"

#: The module alias every revision in this repository imports as
#: ``from alembic import op``. Requiring it keeps ``sa.Column`` calls from being
#: mistaken for operations while walking a function that contains both.
_OPERATIONS_MODULE = "op"


class _Effect:
    """One column-level effect of a migration function, in source order."""

    __slots__ = ("kind", "table", "column")

    def __init__(self, kind: str, table: str, column: str = "") -> None:
        self.kind = kind
        self.table = table
        self.column = column


def _call_name(node: ast.Call) -> str | None:
    """The name a call is written as: ``sa.Column(...)`` -> ``"Column"``."""
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _operation(node: ast.AST) -> str | None:
    """The ``op.<name>`` a call node is, or ``None`` for anything else."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if not isinstance(func, ast.Attribute):
        return None
    if getattr(func.value, "id", None) != _OPERATIONS_MODULE:
        return None
    return func.attr


def _column_name(call: ast.Call, filename: str, failures: list[str]) -> str | None:
    """The name a ``sa.Column(...)`` call declares.

    A name the gate cannot read is a failure, not a skip: returning ``None`` here
    would later look like "the models declare a column the revisions do not
    create", which is a wrong finding, and a wrong finding is how a gate loses
    its audience.
    """
    if not call.args:
        failures.append(
            f"{filename}: a Column(...) at line {call.lineno} declares no name — the "
            f"schema gate reads column names from the source and cannot verify it"
        )
        return None
    name = _literal_string(call.args[0])
    if name is None:
        failures.append(
            f"{filename}: the column name at line {call.lineno} is not a literal "
            f'string — write `sa.Column("name", ...)` so the schema gate can read it'
        )
    return name


def _keywords(node: ast.Call) -> dict[str, ast.AST]:
    return {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}


def _column_effects(
    function: ast.FunctionDef, filename: str
) -> tuple[list[_Effect], list[str]]:
    """Column-level effects of one migration function, in source order.

    Order matters within a revision — a table created and then dropped is not a
    table — so effects are sorted by line number. ``ast.walk`` is breadth-first
    and would visit a nested ``sa.Column(...)`` before the ``op.add_column``
    holding it.
    """
    positioned: list[tuple[int, _Effect]] = []
    failures: list[str] = []

    for node in ast.walk(function):
        method = _operation(node)
        if method is None or not isinstance(node, ast.Call):
            continue
        keywords = _keywords(node)
        table = _literal_string(node.args[0]) if node.args else None
        if table is None:
            table = _literal_string(keywords.get("table_name"))
        if table is None:
            continue

        if method == "create_table":
            positioned.append((node.lineno, _Effect("table", table)))
            for argument in node.args[1:]:
                if isinstance(argument, ast.Call) and _call_name(argument) == _COLUMN_CALL:
                    name = _column_name(argument, filename, failures)
                    if name:
                        positioned.append((node.lineno, _Effect("add", table, name)))
        elif method == "add_column":
            candidates: list[ast.AST] = list(node.args[1:])
            if "column" in keywords:
                candidates.append(keywords["column"])
            for candidate in candidates:
                if isinstance(candidate, ast.Call) and _call_name(candidate) == _COLUMN_CALL:
                    name = _column_name(candidate, filename, failures)
                    if name:
                        positioned.append((node.lineno, _Effect("add", table, name)))
        elif method == "drop_column":
            column = _literal_string(node.args[1]) if len(node.args) > 1 else None
            if column is None:
                column = _literal_string(
                    keywords.get("column_name") or keywords.get("existing_column")
                )
            if column:
                positioned.append((node.lineno, _Effect("drop_column", table, column)))
        elif method == "alter_column":
            column = _literal_string(node.args[1]) if len(node.args) > 1 else None
            if column is None:
                column = _literal_string(
                    keywords.get("column_name") or keywords.get("existing_column")
                )
            new_name = _literal_string(keywords.get("new_column_name"))
            if column and new_name:
                positioned.append((node.lineno, _Effect("drop_column", table, column)))
                positioned.append((node.lineno, _Effect("add", table, new_name)))
        elif method == "drop_table":
            positioned.append((node.lineno, _Effect("drop_table", table)))
        elif method == "rename_table":
            new_name = _literal_string(node.args[1]) if len(node.args) > 1 else None
            if new_name is None:
                new_name = _literal_string(keywords.get("new_name"))
            if new_name:
                positioned.append((node.lineno, _Effect("rename_table", table, new_name)))

    positioned.sort(key=lambda item: item[0])
    return [effect for _, effect in positioned], failures


def _function_node(tree: ast.Module, name: str) -> ast.FunctionDef | None:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def build_schema(versions_dir: Path) -> tuple[dict[str, set[str]], list[str]]:
    """The tables and columns the revision chain creates, in ancestry order.

    Returns the schema and the reasons it could not be read. A non-empty second
    element means the first must not be trusted: reporting drift from a partially
    read chain would produce findings that are artefacts of the reading.
    """
    revisions = _load_revisions(versions_dir)
    if not revisions:
        return {}, [f"no revision files found in {versions_dir}"]

    by_id: dict[str, Revision] = {}
    for revision in revisions:
        if revision.revision is None:
            return {}, [f"{revision.path.name}: missing or non-literal 'revision'"]
        by_id[revision.revision] = revision

    referenced = {parent for revision in revisions for parent in revision.down_revisions}
    heads = [revision_id for revision_id in by_id if revision_id not in referenced]
    if len(heads) != 1:
        listed = ", ".join(sorted(heads)) or "none"
        return {}, [f"expected exactly one head revision, found {len(heads)}: {listed}"]

    order, cycle_at = _ancestry_order(by_id, heads[0])
    if cycle_at is not None:
        return {}, [f"cycle detected in revision chain at {cycle_at!r}"]

    schema: dict[str, set[str]] = {}
    failures: list[str] = []
    for revision in order:
        upgrade = _function_node(revision.tree, "upgrade")
        if upgrade is None:
            continue
        effects, effect_failures = _column_effects(upgrade, revision.path.name)
        failures.extend(effect_failures)
        for effect in effects:
            if effect.kind == "table":
                schema.setdefault(effect.table, set())
            elif effect.kind == "add":
                schema.setdefault(effect.table, set()).add(effect.column)
            elif effect.kind == "drop_column":
                schema.get(effect.table, set()).discard(effect.column)
            elif effect.kind == "drop_table":
                schema.pop(effect.table, None)
            elif effect.kind == "rename_table":
                schema[effect.column] = schema.pop(effect.table, set())

    return schema, failures


def check_schema_drift(metadata: MetaData, versions_dir: Path) -> list[str]:
    """Every difference between the models and the revision-built schema."""
    schema, failures = build_schema(versions_dir)
    if failures:
        return failures

    problems: list[str] = []

    for table_name in sorted(metadata.tables):
        mapped = {column.name for column in metadata.tables[table_name].columns}
        built = schema.get(table_name)
        if built is None:
            problems.append(
                f"{table_name}: mapped by the models but no revision creates it — a "
                f"fresh database has no such table, so the API fails on first use"
            )
            continue
        for column in sorted(mapped - built):
            problems.append(
                f"{table_name}.{column}: declared by the models but no revision creates "
                f"it — every ORM statement names this column, so the API cannot start "
                f"against a database built from these revisions "
                f"(asyncpg UndefinedColumnError), and no unit test can see it because "
                f"the test schema is built from the same models"
            )

    for table_name in sorted(schema):
        if table_name in _TABLES_OUTSIDE_MIGRATIONS or table_name in _DB_ONLY_TABLES:
            continue
        if table_name not in metadata.tables:
            problems.append(
                f"{table_name}: created by a revision but no model maps it — either a "
                f"model is missing or the table is dead schema"
            )
            continue
        mapped = {column.name for column in metadata.tables[table_name].columns}
        for column in sorted(schema[table_name] - mapped):
            if (table_name, column) in _DB_ONLY_COLUMNS:
                continue
            problems.append(
                f"{table_name}.{column}: created by a revision but no model maps it — "
                f"usually the leftover half of a removal that deleted the model field "
                f"and forgot the column, or the reverse"
            )

    return problems


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        print("usage: python -m scripts.check_schema_drift [VERSIONS_DIR]")
        return 2
    versions_dir = Path(argv[0]) if argv else _DEFAULT_VERSIONS_DIR

    try:
        from app.core.database import Base

        import app.models  # noqa: F401  (populates Base.metadata)
    except Exception as exc:  # pragma: no cover - environment problem, not drift
        print(f"schema drift gate: FAILED — cannot import the models: {exc}")
        return 2

    try:
        problems = check_schema_drift(Base.metadata, versions_dir)
    except (OSError, SyntaxError) as exc:
        print(f"schema drift gate: FAILED — cannot read revisions: {exc}")
        return 2

    if problems:
        print("schema drift gate: FAILED")
        for problem in problems:
            print(f"  {problem}")
        return 1

    print(
        "schema drift gate: OK — every table and column the models map is created by "
        f"the revision chain, and everything the chain creates is mapped "
        f"({len(Base.metadata.tables)} tables)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
