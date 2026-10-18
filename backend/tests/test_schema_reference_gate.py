"""The reference schema in ``docs/db.sql`` against the models this platform maps.

``docs/db.sql`` is the readable snapshot an operator opens when they want to know
what the platform stores without starting it. It is not migration input, so
nothing applies it and, until this file existed, nothing compared it: the audit
of 2026-10-15 read it table by table and found no difference, and two days later
four tables the baseline creates were missing from it — the whole TLS certificate
review workflow (``tls_certificate_identities``, ``tls_certificate_sightings``,
``certificate_scope_exceptions``) and the phishing signal trail
(``phishing_candidate_signals``) were invisible to anyone reading the reference.
The first run also found eighteen columns that later waves had added to the
models and the baseline and never to the file.

This gate asks the audit's question on every run, in both directions:

* *mapped, not documented* — the reference a reader trusts silently omits part of
  the schema, which is what happened;
* *documented, not mapped* — the file promises storage the platform does not have,
  which sends a reader writing a report against a column that does not exist.

Tables, columns, nullability, primary keys and server defaults are compared with
the models, because that is the declaration the code is written against and
``scripts/check_schema_drift.py`` already proves the revision chain builds exactly
what they map.

Two defaults are exceptions, and both are decisions rather than drift:

* ``drp_audit_logs.seq`` — the revision creates the column with
  ``nextval('drp_audit_logs_seq_seq'::regclass)``, and the model deliberately does
  not: the single writer assigns the position in the same transaction as the
  insert, so the insert carries its own value.
* ``breach_catalogue.last_synced_at`` — the revision defaults it to ``now()``;
  the model leaves it to the catalogue sync, which is the only writer, so a row
  cannot claim a confirmation nobody made.

Each is named below with its reason. A third one is not expected: a new default
the model does not declare makes this test fail, and the choice is then explicit.

Limits, stated rather than hidden:

* **Types are not compared.** PostgreSQL renders ``sa.String(64)`` as
  ``character varying(64)``, ``sa.Uuid()`` as ``uuid`` and JSON as ``json``; the
  mapping is the server's, and a comparison here would fail on spelling rather
  than on meaning. Type drift that matters is what ``check_schema_drift.py`` and
  ``tests/test_alembic_migrations.py`` cover against a real database.
* **A server default only the model declares is not a finding here.** The file
  describes what a deployed database has; the model's ``server_default`` is what
  ``create_all`` builds in the test suite, and where the two disagree the revision
  is the deployment's answer. ``jobs.created_at`` is that case today — the
  revision creates it with no default, ``TimestampMixin`` declares ``now()`` — and
  it is the schema gate's subject, not this file's.
* **A default this file cannot normalize is reported, not guessed at.** The two
  dialects differ by a cast (``'candidate'::character varying``) and by quoting;
  both are removed before comparing.
"""

from __future__ import annotations

import re
from pathlib import Path

import app.models  # noqa: F401  (populates Base.metadata)

from app.core.database import Base

_ROOT = Path(__file__).resolve().parents[2]
_REFERENCE = _ROOT / "docs" / "db.sql"

_CREATE_TABLE = re.compile(
    r"CREATE TABLE (?P<name>[a-z_][a-z0-9_]*) \(\n(?P<body>.*?)\n\);",
    re.DOTALL,
)
_PRIMARY_KEY = re.compile(
    r"ALTER TABLE ONLY (?P<table>[a-z_][a-z0-9_]*)\n"
    r"\s+ADD CONSTRAINT \S+ PRIMARY KEY \((?P<columns>[^)]*)\);"
)
#: A trailing cast on a default — ``'pending'::character varying`` — and never a
#: cast inside an expression, because ``nextval('seq'::regclass)`` is one value.
_TRAILING_CAST = re.compile(r"::[a-z_]+(?: [a-z_]+)*(?:\(\d+(?:,\d+)?\))?$")
#: A table-body line that declares a constraint rather than a column. The word
#: boundary matters: a column may legitimately be named ``checked_at`` or
#: ``unique_key``, and a prefix test without it would hide both.
_CONSTRAINT_LINE = re.compile(
    r"^(?:CONSTRAINT|PRIMARY\s+KEY|UNIQUE|FOREIGN\s+KEY|CHECK|EXCLUDE)\b",
    re.IGNORECASE,
)

#: Server defaults the revision creates that the model deliberately leaves to the
#: writer, each with the reason it is not a defect.
_REFERENCE_DEFAULT_EXCEPTIONS = {
    ("drp_audit_logs", "seq"): (
        "the sequence default lives in the revision; the model's single writer "
        "assigns the position in the same transaction as the insert"
    ),
    ("breach_catalogue", "last_synced_at"): (
        "the revision defaults the sync instant; the model leaves it to the sync, "
        "which is the only writer"
    ),
}


def _split_definitions(body: str) -> list[str]:
    """Split a table body on the commas that separate definitions.

    A comma inside ``character varying(16)`` is not a separator, so the split
    tracks parenthesis depth.
    """
    parts, current, depth = [], [], 0
    for character in body:
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        if character == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    parts.append("".join(current))
    return parts


def _normalise_default(raw: str | None) -> str | None:
    """One comparable token for a default stated in either dialect.

    ``'candidate'::character varying`` and ``candidate`` are the same default;
    ``nextval('drp_audit_logs_seq_seq'::regclass)`` keeps its inner cast because
    that cast is part of the expression.
    """
    if raw is None:
        return None
    token = raw.strip()
    while True:
        stripped = _TRAILING_CAST.sub("", token).strip()
        if stripped == token:
            break
        token = stripped
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
        token = token[1:-1]
    return " ".join(token.split()).lower() or None


def _reference_schema() -> (
    tuple[
        dict[str, dict[str, dict[str, object]]],
        dict[str, set[str]],
    ]
):
    """Every table, column, nullability and default ``docs/db.sql`` states."""
    text = _REFERENCE.read_text(encoding="utf-8")
    tables: dict[str, dict[str, dict[str, object]]] = {}
    for match in _CREATE_TABLE.finditer(text):
        columns: dict[str, dict[str, object]] = {}
        for definition in _split_definitions(match.group("body")):
            line = definition.strip()
            if not line or _CONSTRAINT_LINE.match(line):
                continue
            name = line.split(maxsplit=1)[0].strip('"')
            default = None
            if " DEFAULT " in line:
                default = line.split(" DEFAULT ", 1)[1]
                if " NOT NULL" in default:
                    default = default.split(" NOT NULL", 1)[0]
            columns[name] = {
                "not_null": " NOT NULL" in line,
                "default": _normalise_default(default),
            }
        tables[match.group("name")] = columns

    primary_keys: dict[str, set[str]] = {}
    for match in _PRIMARY_KEY.finditer(text):
        primary_keys.setdefault(match.group("table"), set()).update(
            column.strip().strip('"') for column in match.group("columns").split(",")
        )
    return tables, primary_keys


def _model_schema() -> tuple[
    dict[str, dict[str, dict[str, object]]],
    dict[str, set[str]],
]:
    """The same shape, read off the mapped models."""
    tables: dict[str, dict[str, dict[str, object]]] = {}
    primary_keys: dict[str, set[str]] = {}
    for name, table in Base.metadata.tables.items():
        columns: dict[str, dict[str, object]] = {}
        for column in table.columns:
            server_default = None
            if column.server_default is not None:
                server_default = _normalise_default(str(column.server_default.arg))
            columns[column.name] = {
                "not_null": not column.nullable,
                "server_default": server_default,
                "client_default": column.default is not None,
            }
        tables[name] = columns
        primary_keys[name] = {column.name for column in table.primary_key.columns}
    return tables, primary_keys


def _differences() -> list[str]:
    reference, reference_pk = _reference_schema()
    mapped, mapped_pk = _model_schema()
    problems: list[str] = []

    for name in sorted(set(mapped) - set(reference)):
        problems.append(
            f"table `{name}` is mapped but not described in docs/db.sql — a reader "
            f"of the reference cannot see storage the platform uses"
        )
    for name in sorted(set(reference) - set(mapped)):
        problems.append(
            f"table `{name}` is described in docs/db.sql but no model maps it — "
            f"the reference promises storage the platform does not have"
        )

    for name in sorted(set(reference) & set(mapped)):
        documented = reference[name]
        columns = mapped[name]
        for column in sorted(set(columns) - set(documented)):
            problems.append(f"`{name}.{column}` is mapped but not described in docs/db.sql")
        for column in sorted(set(documented) - set(columns)):
            problems.append(
                f"`{name}.{column}` is described in docs/db.sql but no model maps it"
            )
        for column in sorted(set(documented) & set(columns)):
            described = documented[column]
            model = columns[column]
            if described["not_null"] != model["not_null"]:
                problems.append(
                    f"`{name}.{column}` is "
                    f"{'NOT NULL' if described['not_null'] else 'nullable'} in "
                    f"docs/db.sql but "
                    f"{'NOT NULL' if model['not_null'] else 'nullable'} in the model"
                )
            documented_default = described["default"]
            model_default = model["server_default"]
            if documented_default is None:
                continue
            if model_default is not None:
                if documented_default != model_default:
                    problems.append(
                        f"`{name}.{column}` defaults to {documented_default!r} in "
                        f"docs/db.sql but {model_default!r} on the model"
                    )
            elif model["client_default"]:
                # A Python-side default is not a server default to compare; the
                # file naming one is the deployment's answer, not an invention.
                continue
            elif (name, column) not in _REFERENCE_DEFAULT_EXCEPTIONS:
                problems.append(
                    f"`{name}.{column}` has DEFAULT {documented_default!r} in "
                    f"docs/db.sql but the model declares no default at all"
                )

    for name in sorted(set(reference_pk) | set(mapped_pk)):
        if reference_pk.get(name, set()) != mapped_pk.get(name, set()):
            problems.append(
                f"`{name}` has primary key {sorted(reference_pk.get(name, set()))} in "
                f"docs/db.sql but {sorted(mapped_pk.get(name, set()))} on the model"
            )
    return problems


def test_the_reference_schema_names_every_mapped_table_and_column() -> None:
    problems = _differences()
    assert problems == [], "\n".join(problems)


def test_the_reference_is_not_empty() -> None:
    """A file that parsed to nothing would make the comparison pass vacuously."""
    reference, _ = _reference_schema()
    mapped, _ = _model_schema()
    assert len(reference) >= 30
    assert set(reference) == set(mapped)


def test_the_four_tables_the_audit_missed_are_described() -> None:
    """The defect this gate was written for, in the words it shipped in.

    The four names were absent from a file that had been read and found correct,
    so the test names them explicitly and fails if a future edit drops one again.
    """
    reference, _ = _reference_schema()
    for name in (
        "certificate_scope_exceptions",
        "phishing_candidate_signals",
        "tls_certificate_identities",
        "tls_certificate_sightings",
    ):
        assert name in reference
