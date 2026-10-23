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

from sqlalchemy import MetaData, UniqueConstraint  # noqa: E402

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

#: What an index enforces — table, ordered columns, uniqueness — rather than what
#: it is called. A model may declare ``Index("ix_users_email", "email",
#: unique=True)`` where the revision creates ``UniqueConstraint("email",
#: name="uq_users_email")``: one unique btree over one column under two names,
#: which is not a difference. A generated migration, however, would drop one and
#: create the other, which is why the *coverage* is compared and the names are not.
IndexKey = tuple[str, tuple[str, ...], bool]

#: Indexes the revision chain creates that no model can declare, each with the
#: reason. Every entry here is one line of the difference list: a decision, not an
#: oversight. An index a model *could* declare belongs on the model — the test
#: schema is built from the models, so declaring it there is what keeps the two
#: schemas the same shape.
_REVISION_ONLY_INDEXES: dict[str, str] = {
    # The matching rule the asset and breach reads compare against, spelled as
    # PostgreSQL stores it. No ORM index renders `lower(rtrim(trim(x), '.'))`.
    "ix_assets_normalized_value_key": "expression index over the asset matching rule",
    "ix_dns_security_observations_subject_key": "expression index over the DNS matching rule",
    "ix_dns_security_observations_value_key": "expression index over the DNS matching rule",
    "ix_drp_breaches_matched_domain_key": "expression index over the breach matching rule",
    "ix_drp_breaches_matched_email_key": "expression index over the breach matching rule",
    "ix_drp_breaches_matched_email_domain": "expression index over the email's domain",
    "ix_drp_findings_matched_asset_key": "expression index over the findings matching rule",
    "ix_drp_phishing_domains_matched_asset_key": "expression index over the candidate matching rule",
    "ix_source_observations_matched_asset_key": "expression index over the observation matching rule",
    # Audit details are JSON; these index one key inside it, which no ORM index
    # declares for a JSON column.
    "ix_audit_job_id": "expression index over a key inside the JSON details",
    "ix_audit_request_id": "expression index over a key inside the JSON details",
    # Trigram GIN indexes: a btree cannot answer `ILIKE '%term%'`, and the
    # operator class has no portable spelling, so the SQLite test schema cannot
    # carry them.
    "ix_assets_asset_value_trgm": "trigram GIN index for substring search",
    "ix_assets_normalized_value_trgm": "trigram GIN index for substring search",
    "ix_drp_phishing_domains_ip_address_trgm": "trigram GIN index for substring search",
    "ix_drp_phishing_domains_matched_asset_trgm": "trigram GIN index for substring search",
    "ix_drp_phishing_domains_phishing_domain_trgm": "trigram GIN index for substring search",
}

#: ``(table, column)`` pairs a model gives a server default and the revision
#: deliberately does not. Empty, and meant to stay that way: the ORM's INSERT
#: omits a column it expects the database to fill, so a model default the schema
#: does not supply is a statement that fails on PostgreSQL and passes on SQLite.
_REVISION_DEFAULT_EXCEPTIONS: dict[tuple[str, str], str] = {}


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


def _target_names(target: ast.AST) -> set[str]:
    """Names assigned by a simple or unpacked assignment target."""
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_target_names(item) for item in target.elts))
    return set()


def _column_calls(
    expression: ast.AST,
    *,
    function: ast.FunctionDef,
    use_node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    resolving: frozenset[str] = frozenset(),
) -> list[ast.Call]:
    """Resolve Column calls, including a loop variable over a literal tuple.

    Alembic migrations commonly build a tuple of ``sa.Column`` values and add
    each one in a loop. The call to ``op.add_column`` then receives a ``Name``,
    rather than the ``Column`` AST node itself. Resolve that name only when its
    local assignment or enclosing loop iterable can be read statically; the
    caller reports an unresolved name instead of silently omitting schema.
    """
    if isinstance(expression, ast.Call) and _call_name(expression) == _COLUMN_CALL:
        return [expression]
    if isinstance(expression, (ast.Tuple, ast.List)):
        return [
            column
            for item in expression.elts
            for column in _column_calls(
                item,
                function=function,
                use_node=use_node,
                parents=parents,
                resolving=resolving,
            )
        ]
    if not isinstance(expression, ast.Name) or expression.id in resolving:
        return []

    name = expression.id
    ancestor = parents.get(use_node)
    while ancestor is not None and ancestor is not function:
        if isinstance(ancestor, (ast.For, ast.AsyncFor)) and name in _target_names(ancestor.target):
            if use_node in ancestor.orelse:
                return []
            return _column_calls(
                ancestor.iter,
                function=function,
                use_node=ancestor,
                parents=parents,
                resolving=resolving | _target_names(ancestor.target),
            )
        ancestor = parents.get(ancestor)

    assignments: list[tuple[int, ast.AST, ast.AST]] = []
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        if value is not None and node.lineno < use_node.lineno and any(
            name in _target_names(target) for target in targets
        ):
            ancestor = parents.get(node)
            inactive_branch = False
            while ancestor is not None and ancestor is not function:
                if isinstance(ancestor, (ast.If, ast.IfExp)) and node in ancestor.body:
                    inactive_branch = True
                    break
                ancestor = parents.get(ancestor)
            if not inactive_branch:
                assignments.append((node.lineno, node, value))

    if not assignments:
        return []
    _, assignment, value = max(assignments, key=lambda item: item[0])
    return _column_calls(
        value,
        function=function,
        use_node=assignment,
        parents=parents,
        resolving=resolving | {name},
    )


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
    parents = {
        child: parent
        for parent in ast.walk(function)
        for child in ast.iter_child_nodes(parent)
    }

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
                columns = _column_calls(
                    candidate,
                    function=function,
                    use_node=node,
                    parents=parents,
                )
                if not columns:
                    failures.append(
                        f"{filename}: the column passed to op.add_column() at line "
                        f"{node.lineno} is not statically readable — pass a literal "
                        f"sa.Column(...) or iterate a literal tuple/list of columns"
                    )
                    continue
                for column in columns:
                    name = _column_name(column, filename, failures)
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


class RevisionSchema:
    """What the revision chain creates, as far as it can be read from source.

    ``columns`` is the table/column map ``build_schema`` has always returned;
    ``defaults`` holds the ``(table, column)`` pairs a revision gives a
    server-side default; ``indexes`` maps what an index enforces to the name the
    revision gives it (``None`` for a constraint written without one); and
    ``unreadable_indexes`` holds the indexes whose columns are an expression, which
    this reader cannot compare with a model and therefore has to report.
    """

    __slots__ = ("columns", "defaults", "indexes", "unreadable_indexes")

    def __init__(self) -> None:
        self.columns: dict[str, set[str]] = {}
        self.defaults: set[tuple[str, str]] = set()
        self.indexes: dict[IndexKey, str | None] = {}
        self.unreadable_indexes: dict[str, str] = {}


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_null(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is None


def _column_list(node: ast.AST) -> tuple[str, ...] | None:
    """The column names an index argument lists, or ``None`` for an expression."""
    if isinstance(node, (ast.List, ast.Tuple)):
        names: list[str] = []
        for element in node.elts:
            name = _literal_string(element)
            if name is None:
                return None
            names.append(name)
        return tuple(names)
    name = _literal_string(node)
    return (name,) if name else None


def _quoted(columns: tuple[str, ...]) -> str:
    return ", ".join(columns)


class _IndexEffect:
    """One index-level effect of a migration function, in source order.

    ``kind`` is ``create``, ``drop`` (only ``name`` matters) or ``unreadable`` — a
    column list written as an expression, ``sa.text("lower(email)")``, which this
    reader cannot compare with a model. Skipping that last one silently is how the
    shipped tree accumulated indexes no gate saw, so it is reported unless the
    name is listed in ``_REVISION_ONLY_INDEXES``.
    """

    __slots__ = ("kind", "table", "columns", "unique", "name")

    def __init__(
        self,
        kind: str,
        *,
        table: str = "",
        columns: tuple[str, ...] = (),
        unique: bool = False,
        name: str | None = None,
    ) -> None:
        self.kind = kind
        self.table = table
        self.columns = columns
        self.unique = unique
        self.name = name


def _secondary_effects(
    function: ast.FunctionDef, filename: str
) -> tuple[
    list[tuple[int, str, tuple[str, str]]],
    list[tuple[int, _IndexEffect]],
    list[str],
]:
    """Server defaults and index coverage of one migration function, in order.

    Returns the default effects — ``(line, "set"|"clear", (table, column))`` —
    and the index effects, each sorted by line so a create and a drop in the same
    function apply the way the file reads.
    """
    defaults: list[tuple[int, str, tuple[str, str]]] = []
    indexes: list[tuple[int, _IndexEffect]] = []
    failures: list[str] = []

    for node in ast.walk(function):
        method = _operation(node)
        if method is None or not isinstance(node, ast.Call):
            continue
        keywords = _keywords(node)
        # The first positional argument is a table for `create_table` and
        # `alter_column`, and the *index name* for `create_index` — which is why
        # each branch below reads its own.
        table = _literal_string(node.args[0]) if node.args else None
        if table is None:
            table = _literal_string(keywords.get("table_name"))

        if method == "create_table" and table:
            for argument in node.args[1:]:
                if not isinstance(argument, ast.Call):
                    continue
                name = _call_name(argument)
                if name == _COLUMN_CALL and argument.args:
                    column = _literal_string(argument.args[0])
                    if column is None:
                        continue  # the column walk already reports it
                    column_keywords = _keywords(argument)
                    default = column_keywords.get("server_default")
                    if default is not None:
                        kind = "clear" if _is_null(default) else "set"
                        defaults.append((argument.lineno, kind, (table, column)))
                    if _is_true(column_keywords.get("unique")):
                        indexes.append(
                            (
                                argument.lineno,
                                _IndexEffect(
                                    "create",
                                    table=table,
                                    columns=(column,),
                                    unique=True,
                                    name=f"UNIQUE ({column})",
                                ),
                            )
                        )
                    elif _is_true(column_keywords.get("index")):
                        indexes.append(
                            (
                                argument.lineno,
                                _IndexEffect("create", table=table, columns=(column,)),
                            )
                        )
                elif name == "UniqueConstraint":
                    listed: list[str] = []
                    for element in argument.args:
                        value = _literal_string(element)
                        if value is None:
                            listed = []
                            break
                        listed.append(value)
                    if not listed:
                        failures.append(
                            f"{filename}: the UniqueConstraint on line "
                            f"{argument.lineno} lists a column that is not a literal "
                            f"string — the schema gate reads coverage from the source "
                            f"and cannot verify it"
                        )
                        continue
                    columns = tuple(listed)
                    label = _literal_string(_keywords(argument).get("name"))
                    indexes.append(
                        (
                            argument.lineno,
                            _IndexEffect(
                                "create",
                                table=table,
                                columns=columns,
                                unique=True,
                                name=label or f"UNIQUE ({_quoted(columns)})",
                            ),
                        )
                    )
                elif name == "Index" and len(argument.args) >= 2:
                    index_columns = _column_list(argument.args[1])
                    label = _literal_string(argument.args[0])
                    if index_columns is None or label is None:
                        failures.append(
                            f"{filename}: the Index() on line {argument.lineno} has a "
                            f"name or column list the gate cannot read — write both as "
                            f"literals so the schema gate can compare it"
                        )
                        continue
                    indexes.append(
                        (
                            argument.lineno,
                            _IndexEffect(
                                "create",
                                table=table,
                                columns=index_columns,
                                unique=_is_true(_keywords(argument).get("unique")),
                                name=label,
                            ),
                        )
                    )
        elif method == "create_index" and len(node.args) >= 3:
            label = _literal_string(node.args[0])
            indexed_table = _literal_string(node.args[1])
            index_columns = _column_list(node.args[2])
            if indexed_table is None:
                failures.append(
                    f"{filename}: the table passed to op.create_index() at line "
                    f"{node.lineno} is not a literal string — write it literally so "
                    f"the schema gate can tell which table the index belongs to"
                )
                continue
            if index_columns is None:
                indexes.append(
                    (node.lineno, _IndexEffect("unreadable", table=indexed_table, name=label))
                )
                continue
            if label is None:
                failures.append(
                    f"{filename}: the index name at line {node.lineno} is not a "
                    f"literal string — write `op.create_index(\"name\", ...)` so the "
                    f"schema gate can read it"
                )
                continue
            indexes.append(
                (
                    node.lineno,
                    _IndexEffect(
                        "create",
                        table=indexed_table,
                        columns=index_columns,
                        unique=_is_true(keywords.get("unique")),
                        name=label,
                    ),
                )
            )
        elif method == "drop_index":
            label = _literal_string(node.args[0]) if node.args else None
            label = label or _literal_string(keywords.get("index_name"))
            if label:
                indexes.append((node.lineno, _IndexEffect("drop", name=label)))
        elif method == "alter_column" and table and len(node.args) > 1:
            column = _literal_string(node.args[1])
            if column is None or "server_default" not in keywords:
                continue
            kind = "clear" if _is_null(keywords["server_default"]) else "set"
            defaults.append((node.lineno, kind, (table, column)))

    defaults.sort(key=lambda item: item[0])
    indexes.sort(key=lambda item: item[0])
    return defaults, indexes, failures


def _read_chain(versions_dir: Path) -> tuple[RevisionSchema, list[str]]:
    """The chain's tables, columns, defaults and index coverage, or why not."""
    schema = RevisionSchema()
    revisions = _load_revisions(versions_dir)
    if not revisions:
        return schema, [f"no revision files found in {versions_dir}"]

    by_id: dict[str, Revision] = {}
    for revision in revisions:
        if revision.revision is None:
            return schema, [f"{revision.path.name}: missing or non-literal 'revision'"]
        by_id[revision.revision] = revision

    referenced = {parent for revision in revisions for parent in revision.down_revisions}
    heads = [revision_id for revision_id in by_id if revision_id not in referenced]
    if len(heads) != 1:
        listed = ", ".join(sorted(heads)) or "none"
        return schema, [f"expected exactly one head revision, found {len(heads)}: {listed}"]

    order, cycle_at = _ancestry_order(by_id, heads[0])
    if cycle_at is not None:
        return schema, [f"cycle detected in revision chain at {cycle_at!r}"]

    failures: list[str] = []
    by_name: dict[str, IndexKey] = {}
    for revision in order:
        upgrade = _function_node(revision.tree, "upgrade")
        if upgrade is None:
            continue
        effects, effect_failures = _column_effects(upgrade, revision.path.name)
        default_effects, index_effects, secondary_failures = _secondary_effects(
            upgrade, revision.path.name
        )
        failures.extend(effect_failures)
        failures.extend(secondary_failures)

        for effect in effects:
            if effect.kind == "table":
                schema.columns.setdefault(effect.table, set())
            elif effect.kind == "add":
                schema.columns.setdefault(effect.table, set()).add(effect.column)
            elif effect.kind == "drop_column":
                schema.columns.get(effect.table, set()).discard(effect.column)
            elif effect.kind == "drop_table":
                schema.columns.pop(effect.table, None)
            elif effect.kind == "rename_table":
                schema.columns[effect.column] = schema.columns.pop(effect.table, set())

        for _, kind, pair in default_effects:
            if kind == "set":
                schema.defaults.add(pair)
            else:
                schema.defaults.discard(pair)

        for _, index_effect in index_effects:
            if index_effect.kind == "create":
                key = (index_effect.table, index_effect.columns, index_effect.unique)
                schema.indexes[key] = index_effect.name
                if index_effect.name:
                    by_name[index_effect.name] = key
            elif index_effect.kind == "drop" and index_effect.name:
                dropped = by_name.pop(index_effect.name, None)
                if dropped is not None:
                    schema.indexes.pop(dropped, None)
                schema.unreadable_indexes.pop(index_effect.name, None)
            elif index_effect.kind == "unreadable" and index_effect.name:
                schema.unreadable_indexes[index_effect.name] = index_effect.table

    return schema, failures


def build_schema(versions_dir: Path) -> tuple[dict[str, set[str]], list[str]]:
    """The tables and columns the revision chain creates, in ancestry order.

    Returns the schema and the reasons it could not be read. A non-empty second
    element means the first must not be trusted: reporting drift from a partially
    read chain would produce findings that are artefacts of the reading.
    """
    schema, failures = _read_chain(versions_dir)
    if failures:
        return {}, failures
    return schema.columns, []


def _model_indexes(metadata: MetaData) -> dict[IndexKey, str]:
    """What the models say is indexed or unique, by coverage rather than name."""
    declared: dict[IndexKey, str] = {}
    for table_name, table in metadata.tables.items():
        for index in table.indexes:
            columns = tuple(getattr(column, "name", "") for column in index.columns)
            if not all(columns):
                continue  # a functional index; the models carry none today
            label = str(index.name) if index.name else _quoted(columns)
            declared[(table_name, columns, bool(index.unique))] = label
        for constraint in table.constraints:
            if not isinstance(constraint, UniqueConstraint):
                continue
            columns = tuple(column.name for column in constraint.columns)
            declared[(table_name, columns, True)] = (
                str(constraint.name)
                if constraint.name
                else f"UNIQUE ({_quoted(columns)})"
            )
    return declared


def _default_problems(
    metadata: MetaData, defaults: set[tuple[str, str]]
) -> list[str]:
    """A server default the models promise and the revision does not supply.

    One direction only. The baseline defaults ``status``, ``id`` and the JSON
    columns so a row can be written by hand, and no model has to declare those —
    the database supplying more than the ORM expects is harmless. The reverse is
    not: the ORM omits a column it expects the database to fill, so it fails
    ``NotNullViolation`` on PostgreSQL while the SQLite test schema, built from
    the same models, accepts the same statement.
    """
    problems: list[str] = []
    for table_name in sorted(metadata.tables):
        for column in metadata.tables[table_name].columns:
            if column.server_default is None:
                continue
            key = (table_name, column.name)
            if key in defaults or key in _REVISION_DEFAULT_EXCEPTIONS:
                continue
            problems.append(
                f"{table_name}.{column.name}: the models declare a server default but "
                f"no revision sets one — the migrated column is NOT NULL without a "
                f"default, so an INSERT that omits it fails (asyncpg "
                f"NotNullViolation) while the SQLite test schema, built from these "
                f"models, accepts it"
            )
    return problems


def _index_problems(metadata: MetaData, chain: RevisionSchema) -> list[str]:
    """Index coverage in both directions."""
    problems: list[str] = []
    declared = _model_indexes(metadata)

    for key in sorted(declared):
        if key in chain.indexes:
            continue
        table_name, columns, unique = key
        problems.append(
            f"{table_name}: the models declare {'unique ' if unique else ''}index "
            f"{declared[key]} on ({_quoted(columns)}) but no revision creates it — a "
            f"database built from the migrations has no access path for that read, and "
            f"only the test schema (built from the models) has one"
        )

    for key in sorted(chain.indexes):
        if key in declared:
            continue
        label = chain.indexes[key]
        if label and label in _REVISION_ONLY_INDEXES:
            continue
        table_name, columns, unique = key
        problems.append(
            f"{table_name}: the revision creates {'unique ' if unique else ''}index "
            f"{label or f'UNIQUE ({_quoted(columns)})'} on ({_quoted(columns)}) but no "
            f"model declares it — declare it on the model so the two schemas agree, or "
            f"name it in _REVISION_ONLY_INDEXES with the reason it cannot be declared"
        )

    for label, table_name in sorted(chain.unreadable_indexes.items()):
        if label in _REVISION_ONLY_INDEXES:
            continue
        problems.append(
            f"{table_name}: the revision creates index {label} over an expression, "
            f"which no model can be compared with — name it in "
            f"_REVISION_ONLY_INDEXES with the reason it exists, so the exception is a "
            f"decision rather than a blind spot"
        )

    return problems


def check_revision_only_indexes(chain: RevisionSchema) -> list[str]:
    """Every allowlist entry the chain no longer creates.

    Kept apart from ``check_schema_drift`` because it is a property of *this*
    repository's allowlist, not of the chain a caller passed in: a temporary
    revision directory in a test describes another tree, and its indexes are
    legitimately not the ones the list names. ``main`` runs both.
    """
    created = set(chain.indexes.values()) | set(chain.unreadable_indexes)
    return [
        f"_REVISION_ONLY_INDEXES lists {label}, which no revision creates — remove "
        f"the entry (or restore the index), so the list keeps describing the tree"
        for label in sorted(set(_REVISION_ONLY_INDEXES) - created)
    ]


def check_schema_drift(metadata: MetaData, versions_dir: Path) -> list[str]:
    """Every difference between the models and the revision-built schema."""
    chain, failures = _read_chain(versions_dir)
    if failures:
        return failures
    schema = chain.columns

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

    problems.extend(_default_problems(metadata, chain.defaults))
    problems.extend(_index_problems(metadata, chain))

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
        chain, unreadable = _read_chain(versions_dir)
        if not unreadable:
            problems.extend(check_revision_only_indexes(chain))
    except (OSError, SyntaxError) as exc:
        print(f"schema drift gate: FAILED — cannot read revisions: {exc}")
        return 2

    if problems:
        print("schema drift gate: FAILED")
        for problem in problems:
            print(f"  {problem}")
        return 1

    print(
        "schema drift gate: OK — every table, column and server default the models "
        f"map is created by the revision chain, every index the models declare is "
        f"covered by one the chain creates, and everything the chain creates is "
        f"mapped or listed ({len(Base.metadata.tables)} tables)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
