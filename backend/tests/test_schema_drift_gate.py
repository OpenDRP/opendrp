"""The schema gate must see a mapped column that no revision creates.

The failure this guards against shipped once: ``SystemSettings`` mapped
``telegram_chat_id``, the consolidated baseline revision never created it, and
the first place that became visible was a *fresh* deployment — ``seed_defaults``
raised ``asyncpg UndefinedColumnError``, the ``set -e`` entrypoint exited, the
container entered a restart loop, and ``docker compose up`` reported only
``dependency failed to start: container opendrp-backend is unhealthy``.

Every other test in this suite stayed green, and none of them could have caught
it: the unit suite builds its schema with ``Base.metadata.create_all`` — from the
same metadata under test — and the PostgreSQL round trip asserted a hand-written
subset of tables and columns. So these tests drive the gate from *both* sides: a
temporary revisions directory rendered from source strings, and an in-memory
``MetaData``, so a finding can be provoked deliberately. A gate whose own failure
mode is "reports nothing" is worse than no gate.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sqlalchemy import Column, Integer, MetaData, Table

from scripts.check_schema_drift import build_schema, check_schema_drift

#: The versions directory and the models the platform actually ships.
SHIPPED_VERSIONS = Path(__file__).resolve().parents[1] / "alembic" / "versions"
_BACKEND_ROOT = SHIPPED_VERSIONS.parents[1]

_HEADER = '''"""Test revision."""

from alembic import op
import sqlalchemy as sa

revision = "{revision}"
down_revision = {down_revision}


def upgrade() -> None:
{upgrade}


def downgrade() -> None:
{downgrade}
'''

_NOOP = "# migration-downgrade: intentional-noop\npass\n"


def _render(revision: str, down_revision: str | None, upgrade: str, downgrade: str) -> str:
    down = "None" if down_revision is None else f'"{down_revision}"'
    return _HEADER.format(
        revision=revision,
        down_revision=down,
        upgrade="\n".join(f"    {line}" if line else "" for line in upgrade.splitlines()),
        downgrade="\n".join(
            f"    {line}" if line else "" for line in downgrade.splitlines()
        ),
    )


def _write_versions(tmp_path: Path, *revisions: tuple[str, str | None, str, str]) -> Path:
    versions = tmp_path / "versions"
    versions.mkdir(parents=True, exist_ok=True)
    for revision, down_revision, upgrade, downgrade in revisions:
        (versions / f"{revision}.py").write_text(
            _render(revision, down_revision, upgrade, downgrade), encoding="utf-8"
        )
    return versions


def _metadata(*tables: tuple[str, list[str]]) -> MetaData:
    """A model-side metadata, without importing the application."""
    metadata = MetaData()
    for table_name, columns in tables:
        Table(table_name, metadata, *[Column(name, Integer) for name in columns])
    return metadata


def test_the_shipped_revisions_and_the_shipped_models_agree() -> None:
    """The real pair, through the entry point CI and `make` actually run.

    A subprocess rather than an import: the gate compares ``Base.metadata`` with
    the shipped revisions, and a test module that declares a throwaway model on
    the application's ``Base`` adds a table to that metadata for the rest of the
    session. A clean interpreter means this test asserts what the operator runs,
    not what this session's collection order happens to have left behind.
    """
    result = subprocess.run(
        [sys.executable, "-m", "scripts.check_schema_drift"],
        cwd=_BACKEND_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "schema drift gate: OK" in result.stdout


def test_a_mapped_column_no_revision_creates_is_reported(tmp_path: Path) -> None:
    """The shape that shipped: the model maps it, the baseline does not create it."""
    versions = _write_versions(
        tmp_path,
        (
            "0001_baseline",
            None,
            'op.create_table("system_settings", sa.Column("telegram_chat_ids", sa.JSON()))',
            _NOOP,
        ),
    )
    metadata = _metadata(("system_settings", ["telegram_chat_ids", "telegram_chat_id"]))

    failures = check_schema_drift(metadata, versions)

    assert len(failures) == 1
    assert "system_settings.telegram_chat_id" in failures[0]
    # The message has to say *why* it is fatal, or the next reader treats it as
    # a style complaint and adds an ignore.
    assert "UndefinedColumnError" in failures[0]


def test_a_mapped_table_no_revision_creates_is_reported(tmp_path: Path) -> None:
    versions = _write_versions(
        tmp_path,
        ("0001_baseline", None, 'op.create_table("users", sa.Column("id", sa.Integer()))', _NOOP),
    )
    metadata = _metadata(("users", ["id"]), ("reports", ["id"]))

    failures = check_schema_drift(metadata, versions)

    assert len(failures) == 1
    assert failures[0].startswith("reports:")


def test_a_column_no_model_maps_is_reported(tmp_path: Path) -> None:
    """The other half of a removal: the field went, the column stayed."""
    versions = _write_versions(
        tmp_path,
        (
            "0001_baseline",
            None,
            'op.create_table("system_settings", sa.Column("id", sa.Integer()), '
            'sa.Column("telegram_chat_id", sa.String(255)))',
            _NOOP,
        ),
    )
    metadata = _metadata(("system_settings", ["id"]))

    failures = check_schema_drift(metadata, versions)

    assert len(failures) == 1
    assert "system_settings.telegram_chat_id" in failures[0]


def test_a_table_no_model_maps_is_reported(tmp_path: Path) -> None:
    versions = _write_versions(
        tmp_path,
        (
            "0001_baseline",
            None,
            'op.create_table("users", sa.Column("id", sa.Integer()))\n'
            'op.create_table("drp_reports", sa.Column("id", sa.Integer()))',
            _NOOP,
        ),
    )

    failures = check_schema_drift(_metadata(("users", ["id"])), versions)

    assert len(failures) == 1
    assert failures[0].startswith("drp_reports:")


def test_a_column_added_by_a_later_revision_is_seen(tmp_path: Path) -> None:
    versions = _write_versions(
        tmp_path,
        ("0001_baseline", None, 'op.create_table("users", sa.Column("id", sa.Integer()))', _NOOP),
        (
            "0002_add_email",
            "0001_baseline",
            'op.add_column("users", sa.Column("email", sa.String(255)))',
            _NOOP,
        ),
    )

    assert check_schema_drift(_metadata(("users", ["id", "email"])), versions) == []
    # And the column is genuinely required: a model that maps it is satisfied,
    # a model that lacks it is a finding, which is what makes the walk real.
    assert check_schema_drift(_metadata(("users", ["id"])), versions) == [
        "users.email: created by a revision but no model maps it — usually the "
        "leftover half of a removal that deleted the model field and forgot the "
        "column, or the reverse"
    ]


def test_a_column_dropped_by_a_later_revision_is_not_required(tmp_path: Path) -> None:
    versions = _write_versions(
        tmp_path,
        (
            "0001_baseline",
            None,
            'op.create_table("users", sa.Column("id", sa.Integer()), '
            'sa.Column("legacy_flag", sa.Boolean()))',
            _NOOP,
        ),
        (
            "0002_drop_legacy",
            "0001_baseline",
            'op.drop_column("users", "legacy_flag")',
            _NOOP,
        ),
    )

    assert check_schema_drift(_metadata(("users", ["id"])), versions) == []


def test_a_table_dropped_by_a_later_revision_is_not_required(tmp_path: Path) -> None:
    versions = _write_versions(
        tmp_path,
        (
            "0001_baseline",
            None,
            'op.create_table("users", sa.Column("id", sa.Integer()))\n'
            'op.create_table("drp_opencti", sa.Column("id", sa.Integer()))',
            _NOOP,
        ),
        (
            "0002_remove_opencti",
            "0001_baseline",
            'op.drop_table("drp_opencti")',
            _NOOP,
        ),
    )

    assert check_schema_drift(_metadata(("users", ["id"])), versions) == []


def test_a_renamed_table_is_followed(tmp_path: Path) -> None:
    versions = _write_versions(
        tmp_path,
        (
            "0001_baseline",
            None,
            'op.create_table("drp_breach_emails", sa.Column("id", sa.Integer()))',
            _NOOP,
        ),
        (
            "0002_rename",
            "0001_baseline",
            'op.rename_table("drp_breach_emails", "drp_breaches")',
            _NOOP,
        ),
    )

    assert check_schema_drift(_metadata(("drp_breaches", ["id"])), versions) == []


def test_a_renamed_column_is_followed(tmp_path: Path) -> None:
    versions = _write_versions(
        tmp_path,
        ("0001_baseline", None, 'op.create_table("users", sa.Column("pwd", sa.String(255)))', _NOOP),
        (
            "0002_rename",
            "0001_baseline",
            'op.alter_column("users", "pwd", new_column_name="password_hash")',
            _NOOP,
        ),
    )

    assert check_schema_drift(_metadata(("users", ["password_hash"])), versions) == []


def test_a_revision_that_creates_no_column_parses_cleanly(tmp_path: Path) -> None:
    """Constraint arguments must not be mistaken for columns.

    An autogenerated ``create_table`` ends with ``sa.PrimaryKeyConstraint(...)``
    and ``sa.UniqueConstraint(...)`` calls whose first argument is a column name
    or a SQL expression. Reading those as columns would invent schema and produce
    findings against correct code.
    """
    versions = _write_versions(
        tmp_path,
        (
            "0001_baseline",
            None,
            'op.create_table(\n'
            '    "users",\n'
            '    sa.Column("id", sa.Integer()),\n'
            '    sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),\n'
            '    sa.CheckConstraint("id > 0", name=op.f("ck_users_id_positive")),\n'
            ')',
            _NOOP,
        ),
    )

    schema, failures = build_schema(versions)

    assert failures == []
    assert schema == {"users": {"id"}}


def test_an_unreadable_column_name_fails_the_gate_instead_of_guessing(tmp_path: Path) -> None:
    """A name held in a variable is reported, not skipped.

    Skipping it would look later like "the models declare a column the revisions
    do not create" — a wrong finding — and a gate that can invent a finding is a
    gate somebody switches off. The fix is one line in the revision.
    """
    versions = _write_versions(
        tmp_path,
        (
            "0001_baseline",
            None,
            'for name in ("id", "email"):\n'
            '    op.create_table("users", sa.Column(name, sa.Integer()))',
            _NOOP,
        ),
    )

    failures = check_schema_drift(_metadata(("users", ["id", "email"])), versions)

    assert len(failures) == 1
    assert "0001_baseline.py" in failures[0]
    assert "not a literal" in failures[0]


def test_a_broken_revision_graph_is_reported_rather_than_guessed(tmp_path: Path) -> None:
    """Two heads: the schema cannot be reconstructed at all, so say that."""
    versions = _write_versions(
        tmp_path,
        ("0001_baseline", None, 'op.create_table("users", sa.Column("id", sa.Integer()))', _NOOP),
        ("0002_other", None, 'op.create_table("reports", sa.Column("id", sa.Integer()))', _NOOP),
    )

    failures = check_schema_drift(_metadata(("users", ["id"])), versions)

    assert len(failures) == 1
    assert "expected exactly one head revision" in failures[0]
