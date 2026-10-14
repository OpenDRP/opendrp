"""Regression tests for reconstructing Alembic column changes from source."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Column, Integer, MetaData, String, Table

from scripts.check_schema_drift import (
    _DEFAULT_VERSIONS_DIR,
    build_schema,
    check_schema_drift,
)


def _write_revision(tmp_path: Path, upgrade: str) -> Path:
    versions = tmp_path / "versions"
    versions.mkdir()
    (versions / "0001_initial.py").write_text(
        '''from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None


def upgrade():
'''
        + "\n".join(f"    {line}" if line else "" for line in upgrade.splitlines())
        + '''


def downgrade():
    op.drop_table("drp_connectors")
''',
        encoding="utf-8",
    )
    return versions


def test_resolves_columns_added_from_a_literal_tuple_loop(tmp_path: Path) -> None:
    versions = _write_revision(
        tmp_path,
        '''op.create_table("drp_connectors", sa.Column("id", sa.Integer()))
columns = (
    sa.Column("provider", sa.String(32)),
    sa.Column("readiness", sa.JSON()),
    sa.Column("last_success_at", sa.DateTime(timezone=True)),
)
for column in columns:
    op.add_column("drp_connectors", column)''',
    )

    schema, failures = build_schema(versions)

    assert failures == []
    assert schema["drp_connectors"] == {
        "id",
        "provider",
        "readiness",
        "last_success_at",
    }


def test_unreadable_add_column_is_reported_instead_of_silently_omitted(
    tmp_path: Path,
) -> None:
    versions = _write_revision(
        tmp_path,
        '''op.create_table("drp_connectors", sa.Column("id", sa.Integer()))
op.add_column("drp_connectors", make_column())''',
    )

    _, failures = build_schema(versions)

    assert len(failures) == 1
    assert "op.add_column()" in failures[0]
    assert "line" in failures[0]


def test_the_shipped_models_match_the_complete_revision_chain() -> None:
    from app.core.database import Base

    import app.models  # noqa: F401  (populate Base.metadata)

    problems = check_schema_drift(Base.metadata, _DEFAULT_VERSIONS_DIR)

    assert problems == []


def test_loop_migration_columns_are_compared_with_model_metadata(
    tmp_path: Path,
) -> None:
    versions = _write_revision(
        tmp_path,
        '''op.create_table("drp_connectors", sa.Column("id", sa.Integer()))
columns = (sa.Column("provider", sa.String(32)), sa.Column("readiness", sa.JSON()))
for column in columns:
    op.add_column("drp_connectors", column)''',
    )
    metadata = MetaData()
    Table(
        "drp_connectors",
        metadata,
        Column("id", Integer()),
        Column("provider", String(32)),
        Column("readiness", String()),
    )

    assert check_schema_drift(metadata, versions) == []
