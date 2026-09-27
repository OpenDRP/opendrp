"""The migration gate must see a table name that does not exist yet.

The failure this guards against is invisible without a PostgreSQL: ``0022``
referenced ``drp_reports`` (the table is ``reports``), so every local suite stayed
green and only the PostgreSQL round trip — at the far end of ``upgrade head`` —
raised ``NoSuchTableError``. These tests build revision files in a temporary
directory and assert on the gate's verdict, because a gate whose own failure mode
is "reports nothing" is worse than no gate.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_migrations import check_versions_dir

#: The versions directory the platform actually ships. A revision that fails the
#: gate here is a revision that will fail against a real database.
SHIPPED_VERSIONS = Path(__file__).resolve().parents[1] / "alembic" / "versions"

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


def test_the_shipped_revisions_pass_the_gate() -> None:
    assert check_versions_dir(SHIPPED_VERSIONS) == []


def test_a_reflected_table_no_revision_creates_is_reported(tmp_path: Path) -> None:
    """The ``drp_reports`` shape: a reflection over a table with a wrong name."""
    versions = _write_versions(
        tmp_path,
        (
            "0001_first",
            None,
            'op.create_table("reports", sa.Column("id", sa.Integer()))',
            _NOOP,
        ),
        (
            "0002_second",
            "0001_first",
            'columns = sa.inspect(op.get_bind()).get_columns("drp_reports")',
            _NOOP,
        ),
    )

    failures = check_versions_dir(versions)

    assert len(failures) == 1
    assert "0002_second.py" in failures[0]
    assert "upgrade()" in failures[0]
    assert "'drp_reports'" in failures[0]


def test_the_aliased_inspector_spelling_is_checked_too(tmp_path: Path) -> None:
    """``inspector = sa.inspect(bind)`` is the spelling a reader skips over."""
    versions = _write_versions(
        tmp_path,
        (
            "0001_first",
            None,
            'inspector = sa.inspect(op.get_bind())\n'
            'columns = {c["name"] for c in inspector.get_columns("nowhere")}',
            _NOOP,
        ),
    )

    failures = check_versions_dir(versions)

    assert len(failures) == 1
    assert "'nowhere'" in failures[0]


def test_a_lightweight_sa_table_reference_is_checked(tmp_path: Path) -> None:
    versions = _write_versions(
        tmp_path,
        (
            "0001_first",
            None,
            'rows = op.get_bind().execute(sa.select(sa.table("ghosts").c.id))',
            _NOOP,
        ),
    )

    failures = check_versions_dir(versions)

    assert len(failures) == 1
    assert "'ghosts'" in failures[0]


def test_a_table_created_by_a_later_revision_is_still_a_failure(tmp_path: Path) -> None:
    """Forward references fail at the same point, so they are the same finding."""
    versions = _write_versions(
        tmp_path,
        (
            "0001_first",
            None,
            'columns = sa.inspect(op.get_bind()).get_columns("future")',
            _NOOP,
        ),
        (
            "0002_second",
            "0001_first",
            'op.create_table("future", sa.Column("id", sa.Integer()))',
            _NOOP,
        ),
    )

    failures = check_versions_dir(versions)

    assert len(failures) == 1
    assert "0001_first.py" in failures[0]
    assert "'future'" in failures[0]


def test_a_table_created_by_an_earlier_revision_is_fine(tmp_path: Path) -> None:
    versions = _write_versions(
        tmp_path,
        (
            "0001_first",
            None,
            'op.create_table("reports", sa.Column("id", sa.Integer()))',
            _NOOP,
        ),
        (
            "0002_second",
            "0001_first",
            'columns = sa.inspect(op.get_bind()).get_columns("reports")',
            _NOOP,
        ),
    )

    assert check_versions_dir(versions) == []


def test_a_revision_may_drop_what_it_created(tmp_path: Path) -> None:
    """A drop of a table the same revision creates is not a missing table."""
    versions = _write_versions(
        tmp_path,
        (
            "0001_first",
            None,
            'op.create_table("scratch", sa.Column("id", sa.Integer()))\n'
            'op.drop_table("scratch")',
            'op.drop_table("scratch")',
        ),
    )

    assert check_versions_dir(versions) == []


def test_the_downgrade_body_is_checked_as_well(tmp_path: Path) -> None:
    versions = _write_versions(
        tmp_path,
        (
            "0001_first",
            None,
            'op.create_table("reports", sa.Column("id", sa.Integer()))',
            'op.drop_table("missing_table")',
        ),
    )

    failures = check_versions_dir(versions)

    assert len(failures) == 1
    assert "downgrade()" in failures[0]
    assert "'missing_table'" in failures[0]


def test_a_computed_table_name_is_not_guessed(tmp_path: Path) -> None:
    """The gate must not invent a finding for a name it cannot read."""
    versions = _write_versions(
        tmp_path,
        (
            "0001_first",
            None,
            "table = op.get_bind().dialect.name\n"
            'name = "reports" if table else "other"\n'
            "columns = sa.inspect(op.get_bind()).get_columns(name)",
            _NOOP,
        ),
    )

    assert check_versions_dir(versions) == []


@pytest.mark.parametrize("table", ["alembic_version"])
def test_alembic_bookkeeping_tables_are_allowed(tmp_path: Path, table: str) -> None:
    versions = _write_versions(
        tmp_path,
        (
            "0001_first",
            None,
            f'columns = sa.inspect(op.get_bind()).get_columns("{table}")',
            _NOOP,
        ),
    )

    assert check_versions_dir(versions) == []
