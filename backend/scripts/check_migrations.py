"""Structural gate for the Alembic revision graph.

Catches the failure classes a data-migration test cannot see, without touching
a database:

* two heads after an unrebase merge (``alembic upgrade head`` becomes
  ambiguous);
* a ``down_revision`` naming a revision that does not exist, or a chain that
  never reaches ``base`` — rollback becomes impossible;
* duplicate or missing revision identifiers;
* a revision without ``upgrade``/``downgrade``;
* a silently empty ``downgrade()``: the shape of a migration that upgrades
  fine and cannot be rolled back. Such a revision must state the intent with a
  ``migration-downgrade: intentional-noop`` comment;
* a revision id longer than Alembic's version column. Alembic records the
  applied revision as ``UPDATE alembic_version SET version_num = ...``, and that
  column is ``VARCHAR(32)``. A longer id makes ``upgrade`` fail at the final
  bookkeeping statement — after the DDL, inside the same transaction — so on
  PostgreSQL the DDL rolls back and the revision is never recorded, leaving the
  migration permanently unappliable;
* a revision that **names a table no earlier revision creates**. Reflection
  (``sa.inspect(bind).get_columns(...)``) and ``sa.table(...)`` take the table as
  a plain string, so a typo in it is invisible to every check that does not have
  a database — and it fails at the *end* of the chain, on a real PostgreSQL, as
  ``NoSuchTableError``. That is exactly how ``0022`` shipped a reference to
  ``drp_reports`` (the table is ``reports``) and turned the PostgreSQL round trip
  red while every local test stayed green.

Pure AST over ``alembic/versions``, so it is instant and can run on every push
before the PostgreSQL-backed round trip.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

INTENTIONAL_NOOP_MARKER = "migration-downgrade: intentional-noop"

#: Width of ``alembic_version.version_num``, which Alembic defines as
#: ``String(32)`` and has never widened. Not configurable from ``alembic.ini``,
#: so the limit is a hard constraint on revision ids. ``test_alembic_migrations``
#: asserts the real column is exactly this wide, so the constant cannot drift
#: away from the database it is protecting.
REVISION_ID_MAX_LENGTH = 32

#: Methods that take a table name and read the table's shape back from the
#: database. Unlike ``op.add_column``, the name here is the only positional
#: argument, so it can be read out of the source without guessing, and a name
#: that does not exist is a hard failure rather than a mistake the DDL absorbs.
_TABLE_REFLECTION_METHODS = {
    "get_columns",
    "get_indexes",
    "get_unique_constraints",
    "get_foreign_keys",
    "get_pk_constraint",
    "has_table",
}

#: Tables that exist without any revision creating them and that a revision may
#: legitimately name: Alembic's own bookkeeping table.
_TABLES_OUTSIDE_MIGRATIONS = {"alembic_version"}

_DEFAULT_VERSIONS_DIR = Path(__file__).resolve().parents[1] / "alembic" / "versions"


class Revision:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.source = path.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source, filename=str(path))
        self.revision: str | None = None
        self.down_revisions: list[str] = []
        self.has_upgrade = False
        self.has_downgrade = False
        self.downgrade_is_noop = False
        self.assignments: dict[str, ast.AST] = {}
        #: ``(kind, table)`` pairs in source order, where kind is "create",
        #: "drop" or "read" — the effects a function has on table *names*.
        self.upgrade_effects: list[tuple[str, str]] = []
        self.downgrade_effects: list[tuple[str, str]] = []
        self._scan()

    def _scan(self) -> None:
        for node in self.tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.assignments[target.id] = node.value
            elif isinstance(node, ast.AnnAssign):
                # Autogenerate emits ``revision: str = "..."`` (and
                # ``down_revision: Union[str, None] = None``), so annotated
                # assignments carry the same information as plain ones.
                if isinstance(node.target, ast.Name) and node.value is not None:
                    self.assignments[node.target.id] = node.value
            elif isinstance(node, ast.FunctionDef) and not node.decorator_list:
                if node.name == "upgrade":
                    self.has_upgrade = True
                    self.upgrade_effects = _table_effects(node)
                elif node.name == "downgrade":
                    self.has_downgrade = True
                    self.downgrade_is_noop = _is_noop(node)
                    self.downgrade_effects = _table_effects(node)

        revision_node = self.assignments.get("revision")
        if isinstance(revision_node, ast.Constant) and isinstance(revision_node.value, str):
            self.revision = revision_node.value

        down_node = self.assignments.get("down_revision")
        if isinstance(down_node, ast.Constant) and down_node.value is None:
            self.down_revisions = []
        elif isinstance(down_node, ast.Constant) and isinstance(down_node.value, str):
            self.down_revisions = [down_node.value]
        elif isinstance(down_node, ast.Tuple):
            self.down_revisions = [
                element.value
                for element in down_node.elts
                if isinstance(element, ast.Constant) and isinstance(element.value, str)
            ]

    @property
    def declares_down_revision(self) -> bool:
        return "down_revision" in self.assignments

    @property
    def documented_noop(self) -> bool:
        return INTENTIONAL_NOOP_MARKER in self.source


def _literal_string(node: ast.AST | None) -> str | None:
    """The string a node literally is, or ``None`` when it is computed."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _table_effects(function: ast.FunctionDef) -> list[tuple[str, str]]:
    """Table names this function creates, drops or reads, in source order.

    Only literal names are returned. A name held in a variable is skipped rather
    than guessed: the gate fails builds, so it must never invent a finding.
    """
    effects: list[tuple[int, str, str]] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        for kind, table in _call_table_effects(node):
            effects.append((node.lineno, kind, table))

    # ``ast.walk`` is breadth-first; order matters within a revision
    # (``create_table`` then ``sa.table`` on the new table is fine, the reverse is
    # the bug), so sort by line. ``sorted`` is stable and a line holds one call
    # per name in practice.
    effects.sort(key=lambda item: item[0])
    return [(kind, table) for _, kind, table in effects]


def _call_table_effects(call: ast.Call) -> list[tuple[str, str]]:
    func = call.func
    args = call.args
    first = _literal_string(args[0]) if args else None

    # ``sa.inspect(...).get_columns("t")`` and
    # ``inspector.get_columns("t")`` are the same call: every method in
    # ``_TABLE_REFLECTION_METHODS`` is only ever a table-read in a migration, and
    # its first positional argument is always the table name. Matching on the
    # name alone therefore covers both spellings without tracking what a local
    # variable holds — which matters, because the aliased spelling is one a
    # reader would not look twice at.
    if isinstance(func, ast.Attribute):
        method = func.attr
        if method in _TABLE_REFLECTION_METHODS:
            return [("read", first)] if first else []
        if method == "create_table":
            return [("create", first)] if first else []
        if method == "drop_table":
            return [("drop", first)] if first else []
        if method == "rename_table":
            new_name = _literal_string(args[1]) if len(args) > 1 else None
            for keyword in call.keywords:
                if keyword.arg == "new_name":
                    new_name = new_name or _literal_string(keyword.value)
            renamed = [("drop", first)] if first else []
            if new_name:
                renamed.append(("create", new_name))
            return renamed

    # ``sa.table("t", ...)`` builds a lightweight handle for a DML statement, so
    # the table must already exist.
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "table"
        and isinstance(func.value, ast.Name)
        and func.value.id in {"sa", "sqlalchemy"}
        and first
    ):
        return [("read", first)]

    return []


def _is_noop(function: ast.FunctionDef) -> bool:
    """True when the body does nothing but ``pass``/docstring."""
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    return bool(body) and all(isinstance(statement, ast.Pass) for statement in body)


def _load_revisions(versions_dir: Path) -> list[Revision]:
    return [
        Revision(path)
        for path in sorted(versions_dir.glob("*.py"))
        if path.name != "__init__.py"
    ]


def _ancestry_order(by_id: dict[str, Revision], head: str) -> tuple[list[Revision], str | None]:
    """The chain from base to head, or the id a cycle was detected at."""
    order: list[Revision] = []
    visited: set[str] = set()
    cursor: str | None = head
    while cursor is not None:
        if cursor in visited:
            return order, cursor
        visited.add(cursor)
        order.append(by_id[cursor])
        parents = by_id[cursor].down_revisions
        cursor = parents[0] if parents else None
    order.reverse()
    return order, None


def check_table_references(order: list[Revision]) -> list[str]:
    """Every table a revision reads or drops must exist by the time it runs.

    The check walks the chain from ``base`` forward, so "exists" means "some
    revision at or before this one creates it" — a name that a *later* revision
    creates is as wrong as a name nothing creates, and both only surface against
    a real database at the far end of ``upgrade head``.
    """
    failures: list[str] = []
    available: set[str] = set(_TABLES_OUTSIDE_MIGRATIONS)

    for revision in order:
        available |= {
            table for kind, table in revision.upgrade_effects if kind == "create"
        }
        # A revision may drop what it just created, in either direction, without
        # that being a reference to something that never existed.
        created_here = {
            table
            for kind, table in (*revision.upgrade_effects, *revision.downgrade_effects)
            if kind == "create"
        }
        for function_name, effects in (
            ("upgrade", revision.upgrade_effects),
            ("downgrade", revision.downgrade_effects),
        ):
            for kind, table in effects:
                if kind == "create" or table in available or table in created_here:
                    continue
                failures.append(
                    f"{revision.path.name}: {function_name}() names table {table!r}, "
                    f"but no revision at or before this one creates it — this "
                    f"fails only against a real database (NoSuchTableError), at "
                    f"the end of `alembic upgrade head`"
                )
    return failures


def check_versions_dir(versions_dir: Path) -> list[str]:
    failures: list[str] = []
    if not versions_dir.is_dir():
        return [f"versions directory not found: {versions_dir}"]

    revisions = _load_revisions(versions_dir)
    if not revisions:
        return [f"no revision files found in {versions_dir}"]

    by_id: dict[str, Revision] = {}
    for revision in revisions:
        name = revision.path.name
        if revision.revision is None:
            failures.append(f"{name}: missing or non-literal 'revision'")
            continue
        if revision.revision in by_id:
            failures.append(
                f"{name}: duplicate revision id {revision.revision!r} "
                f"(also in {by_id[revision.revision].path.name})"
            )
            continue
        if len(revision.revision) > REVISION_ID_MAX_LENGTH:
            failures.append(
                f"{name}: revision id is {len(revision.revision)} characters, "
                f"but alembic_version.version_num is VARCHAR({REVISION_ID_MAX_LENGTH}) "
                f"— the id would be too long to record, making the migration "
                f"unappliable. Shorten it (e.g. drop a word) and keep the file "
                f"name in step."
            )
            continue
        by_id[revision.revision] = revision

    referenced: set[str] = set()
    for revision in revisions:
        name = revision.path.name
        if not revision.declares_down_revision:
            failures.append(f"{name}: missing 'down_revision' assignment")
        if not revision.has_upgrade:
            failures.append(f"{name}: missing upgrade() function")
        if not revision.has_downgrade:
            failures.append(f"{name}: missing downgrade() function")
        elif revision.downgrade_is_noop and not revision.documented_noop:
            failures.append(
                f"{name}: downgrade() is empty and not marked — add "
                f"'{INTENTIONAL_NOOP_MARKER}' if the irreversibility is deliberate"
            )

        for parent in revision.down_revisions:
            referenced.add(parent)
            if parent not in by_id:
                failures.append(f"{name}: down_revision {parent!r} does not exist")

    if failures:
        return failures

    heads = [revision_id for revision_id in by_id if revision_id not in referenced]
    if len(heads) != 1:
        listed = ", ".join(sorted(heads)) or "none"
        return [f"expected exactly one head revision, found {len(heads)}: {listed}"]

    # Walk the declared ancestry from the single head and make sure it covers
    # every revision exactly once, which rules out cycles and orphans.
    order, cycle_at = _ancestry_order(by_id, heads[0])
    if cycle_at is not None:
        failures.append(f"cycle detected in revision chain at {cycle_at!r}")
        return failures

    unreachable = sorted(set(by_id) - {revision.revision for revision in order})
    if unreachable:
        failures.append(
            "revisions are not reachable from the head: " + ", ".join(unreachable)
        )
        return failures

    failures.extend(check_table_references(order))
    return failures


def main(argv: list[str]) -> int:
    versions_dir = _DEFAULT_VERSIONS_DIR
    if len(argv) > 1:
        print("usage: python scripts/check_migrations.py [VERSIONS_DIR]")
        return 2
    if argv:
        versions_dir = Path(argv[0])

    try:
        failures = check_versions_dir(versions_dir)
    except (OSError, SyntaxError) as exc:
        print(f"migration gate: FAILED — cannot read revisions: {exc}")
        return 2

    if failures:
        print("migration gate: FAILED")
        for failure in failures:
            print(f"  {failure}")
        return 1

    print(
        "migration gate: OK — single head, intact ancestry, no silent no-op "
        "downgrades, every table named by a revision exists by then"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
