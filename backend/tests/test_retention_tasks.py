"""Retention sweep: batched deletes, artifact containment, audit trail.

The sweep is the only code in the platform that *deletes* history, so it is
tested against the two ways it can do real damage:

1. deleting rows it was not asked to delete (cutoff and batch boundaries), and
2. unlinking a file outside the report store, because a path is read from a
   database column and therefore treated as untrusted input.

It is also tested for the failure mode that looks like success: a sweep that
hits its batch cap every night and never actually keeps up must report that it
was truncated rather than quietly reporting a bounded number of deletions.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select

from app.core.audit import AUDIT_ALLOWED_ACTIONS, AuditLog
from app.core.audit_chain import prepare_entry
from app.core.config import settings
from app.models import Report
from app.models.token import RefreshTokenFamily
from app.tasks import retention_tasks as rt


def _old(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


async def _add_session(db, *, created_days_ago: int, revoked_days_ago: int | None = None):
    """One `drp_refresh_families` row, as login (and a password change) writes it."""
    family_id = uuid.uuid4()
    db.add(
        RefreshTokenFamily(
            id=family_id,
            family_id=family_id,
            user_id=uuid.uuid4(),
            last_jti=str(uuid.uuid4()),
            last_issued_at=_old(created_days_ago),
            revoked=revoked_days_ago is not None,
            revoked_at=None if revoked_days_ago is None else _old(revoked_days_ago),
            revoked_reason=None if revoked_days_ago is None else "password_change",
            created_at=_old(created_days_ago),
        )
    )
    await db.commit()
    return family_id


async def _session_rows(db) -> set[uuid.UUID]:
    return {
        row for row in (await db.execute(select(RefreshTokenFamily.family_id))).scalars().all()
    }


async def _add_audit_rows(db, count: int, *, age_days: int, action: str = "asset.view"):
    """Insert rows the way the audit logger writes them: signed chain links.

    Retention deletes a *prefix* of the chain, so what it deletes has to be a
    chain: `entry_hash` and `prev_hash` are NOT NULL and the verifier treats a
    row without them as a break, not as history.
    """
    for _ in range(count):
        timestamp = _old(age_days)
        link = await prepare_entry(
            db,
            timestamp=timestamp,
            user_id=None,
            action=action,
            ip_address="127.0.0.1",
            details={},
        )
        db.add(
            AuditLog(
                timestamp=timestamp,
                user_id=None,
                action=action,
                ip_address="127.0.0.1",
                details={},
                seq=link.seq,
                entry_hash=link.entry_hash,
                prev_hash=link.prev_hash,
                key_id=link.key_id,
            )
        )
        await db.flush()
    await db.commit()


async def _audit_count(db) -> int:
    return int((await db.execute(select(func.count(AuditLog.id)))).scalar() or 0)


# ---------------------------------------------------------------------------
# Artifact containment
# ---------------------------------------------------------------------------


class TestResolveStoreArtifact:
    """A path from the database must never escape the report store."""

    @pytest.fixture(autouse=True)
    def _store_dir(self, tmp_path, monkeypatch):
        self.store = tmp_path / "reports_store"
        self.store.mkdir()
        monkeypatch.setattr(settings, "REPORTS_STORE_DIR", str(self.store))

    def test_accepts_an_artifact_name(self):
        artifact = self.store / "report-1.pdf"
        artifact.write_bytes(b"%PDF-1.7")
        assert rt.resolve_store_artifact("report-1.pdf") == str(artifact)

    def test_rejects_anything_with_a_directory_component(self):
        """The column holds a name, so a path in it is already a finding.

        Both spellings matter: the absolute path an older release stored, and the
        traversal someone would add by hand.
        """
        outside = self.store.parent / "secret.pdf"
        outside.write_bytes(b"secret")
        assert rt.resolve_store_artifact(str(outside)) is None
        assert rt.resolve_store_artifact("../secret.pdf") is None
        assert rt.resolve_store_artifact(str(self.store / ".." / "secret.pdf")) is None
        assert rt.resolve_store_artifact("..\\secret.pdf") is None

    def test_rejects_a_sibling_directory_with_a_shared_prefix(self):
        """``/data/reports_store_evil`` is not inside ``/data/reports_store``.

        The naive containment check — ``str.startswith(store_root)`` — accepts
        this value. Resolving the candidate against the store and requiring the
        result to stay inside it does not.
        """
        sibling = self.store.parent / f"{self.store.name}_evil"
        sibling.mkdir()
        artifact = sibling / "report.pdf"
        artifact.write_bytes(b"%PDF-1.7")
        assert rt.resolve_store_artifact(f"{sibling.name}/report.pdf") is None

    def test_rejects_nested_paths(self):
        nested = self.store / "nested"
        nested.mkdir()
        artifact = nested / "report.pdf"
        artifact.write_bytes(b"%PDF-1.7")
        assert rt.resolve_store_artifact("nested/report.pdf") is None

    def test_rejects_a_symlink_that_leaves_the_store(self):
        """A name is not enough: the file it resolves to must be inside too."""
        outside = self.store.parent / "secret.pdf"
        outside.write_bytes(b"secret")
        link = self.store / "linked.pdf"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):  # pragma: no cover - platform
            pytest.skip("symlinks are not available in this environment")
        assert rt.resolve_store_artifact("linked.pdf") is None
        assert rt.resolve_store_artifact(str(link)) is None

    def test_rejects_a_name_the_platform_does_not_produce(self):
        (self.store / "notes.txt").write_text("not a report", encoding="utf-8")
        assert rt.resolve_store_artifact("notes.txt") is None

    def test_rejects_empty_and_missing_values(self):
        assert rt.resolve_store_artifact(None) is None
        assert rt.resolve_store_artifact("") is None
        assert rt.resolve_store_artifact("   ") is None
        assert rt.resolve_store_artifact("never-written.pdf") is None

    def test_removes_only_old_report_render_temporary_files(self, monkeypatch):
        from app.core import config as config_module

        old = self.store / ".0123456789abcdef0123456789abcdef.pdf.tmp"
        fresh = self.store / ".fedcba9876543210fedcba9876543210.pdf.tmp"
        unrelated = self.store / ".notes.pdf.tmp"
        old.write_bytes(b"old")
        fresh.write_bytes(b"fresh")
        unrelated.write_bytes(b"keep")
        old_timestamp = (datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()
        os.utime(old, (old_timestamp, old_timestamp))
        monkeypatch.setattr(config_module.settings, "REPORT_GENERATION_TIMEOUT_SECONDS", 120)

        removed = rt.purge_stale_report_temporary_files(now=datetime.now(timezone.utc))

        assert removed == 1
        assert not old.exists()
        assert fresh.exists()
        assert unrelated.exists()


# ---------------------------------------------------------------------------
# Batched row deletion
# ---------------------------------------------------------------------------


class TestPurgeTable:
    @pytest.mark.asyncio
    async def test_deletes_only_rows_older_than_the_cutoff(self, db_session):
        await _add_audit_rows(db_session, 3, age_days=400)
        await _add_audit_rows(db_session, 2, age_days=1)
        before = await _audit_count(db_session)

        result = await rt.purge_table(
            db_session,
            model=AuditLog,
            timestamp_column=AuditLog.timestamp,
            cutoff=_old(365),
            batch_size=100,
            max_batches=50,
        )

        assert result.deleted_rows == 3
        assert result.truncated is False
        assert await _audit_count(db_session) == before - 3

    @pytest.mark.asyncio
    async def test_drains_in_batches_and_counts_them(self, db_session):
        await _add_audit_rows(db_session, 5, age_days=400)

        result = await rt.purge_table(
            db_session,
            model=AuditLog,
            timestamp_column=AuditLog.timestamp,
            cutoff=_old(365),
            batch_size=2,
            max_batches=50,
        )

        assert result.deleted_rows == 5
        # 2 + 2 + 1: the short batch is what proves the predicate is drained.
        assert result.batches == 3
        assert result.truncated is False
        assert await _audit_count(db_session) == 0

    @pytest.mark.asyncio
    async def test_reports_truncation_when_the_batch_cap_is_reached(self, db_session):
        await _add_audit_rows(db_session, 4, age_days=400)

        result = await rt.purge_table(
            db_session,
            model=AuditLog,
            timestamp_column=AuditLog.timestamp,
            cutoff=_old(365),
            batch_size=2,
            max_batches=1,
        )

        assert result.deleted_rows == 2
        assert result.batches == 1
        # Two rows past the cutoff remain, so the run must not claim success.
        assert result.truncated is True
        assert await _audit_count(db_session) == 2

    @pytest.mark.asyncio
    async def test_empty_table_is_not_truncated(self, db_session):
        result = await rt.purge_table(
            db_session,
            model=AuditLog,
            timestamp_column=AuditLog.timestamp,
            cutoff=_old(365),
            batch_size=10,
            max_batches=1,
        )
        assert result.deleted_rows == 0
        assert result.batches == 0
        assert result.truncated is False


# ---------------------------------------------------------------------------
# Reports: rows first, then artifacts
# ---------------------------------------------------------------------------


class TestPurgeExpiredReports:
    @pytest.fixture(autouse=True)
    def _store_dir(self, tmp_path, monkeypatch):
        self.store = tmp_path / "reports_store"
        self.store.mkdir()
        monkeypatch.setattr(settings, "REPORTS_STORE_DIR", str(self.store))

    async def _add_report(self, db, *, age_days: int, name: str) -> tuple[object, str]:
        artifact = self.store / f"{name}.pdf"
        artifact.write_bytes(b"%PDF-1.7")
        report = Report(
            report_name=name,
            # The column holds the artifact *name* since 0022; the store
            # directory is configuration and is not part of the value.
            file_path=artifact.name,
            status="completed",
            created_at=_old(age_days),
            updated_at=_old(age_days),
        )
        db.add(report)
        await db.commit()
        return report, str(artifact)

    @pytest.mark.asyncio
    async def test_removes_rows_and_their_pdfs(self, db_session):
        _report, artifact = await self._add_report(db_session, age_days=400, name="old")
        _fresh, fresh_artifact = await self._add_report(
            db_session, age_days=1, name="fresh"
        )

        result = await rt.purge_expired_reports(
            db_session, cutoff=_old(365), batch_size=100, max_batches=10
        )

        assert result.deleted_rows == 1
        assert result.removed_artifacts == 1
        assert not os.path.exists(artifact)
        # The recent report and its PDF are untouched.
        assert os.path.exists(fresh_artifact)
        assert len((await db_session.execute(select(Report))).scalars().all()) == 1

    @pytest.mark.asyncio
    async def test_skips_paths_outside_the_store_and_reports_them(self, db_session):
        outside = self.store.parent / "outside.pdf"
        outside.write_bytes(b"must survive")
        db_session.add(
            Report(
                report_name="outside",
                file_path=str(outside),
                status="completed",
                created_at=_old(400),
                updated_at=_old(400),
            )
        )
        await db_session.commit()

        result = await rt.purge_expired_reports(
            db_session, cutoff=_old(365), batch_size=100, max_batches=10
        )

        # The row goes (retention was asked for it), the file outside the store
        # does not, and the refusal is reported rather than silent.
        assert result.deleted_rows == 1
        assert result.removed_artifacts == 0
        assert result.outside_store_paths == [str(outside)]
        assert outside.exists()

    @pytest.mark.asyncio
    async def test_tolerates_a_row_whose_pdf_is_already_gone(self, db_session):
        db_session.add(
            Report(
                report_name="vanished",
                file_path="never-written.pdf",
                status="failed",
                created_at=_old(400),
                updated_at=_old(400),
            )
        )
        await db_session.commit()

        result = await rt.purge_expired_reports(
            db_session, cutoff=_old(365), batch_size=100, max_batches=10
        )

        assert result.deleted_rows == 1
        assert result.removed_artifacts == 0
        assert result.outside_store_paths == []

    @pytest.mark.asyncio
    async def test_truncation_is_reported_for_partially_drained_runs(self, db_session):
        for index in range(3):
            await self._add_report(db_session, age_days=400, name=f"r{index}")

        result = await rt.purge_expired_reports(
            db_session, cutoff=_old(365), batch_size=2, max_batches=1
        )

        assert result.deleted_rows == 2
        assert result.truncated is True

    @pytest.mark.asyncio
    async def test_exact_batch_size_still_counts_as_drained(self, db_session):
        """A final batch that exactly fills the batch size must not look truncated.

        The loop cannot tell "drained" from "there is more" from the row count
        alone at this boundary, and a false ``truncated`` every night is a
        signal operators learn to ignore.
        """
        for index in range(2):
            await self._add_report(db_session, age_days=400, name=f"e{index}")

        result = await rt.purge_expired_reports(
            db_session, cutoff=_old(365), batch_size=2, max_batches=10
        )

        assert result.deleted_rows == 2
        assert result.truncated is False


# ---------------------------------------------------------------------------
# Sweep orchestration and its audit trail
# ---------------------------------------------------------------------------


class TestPurgeExpiredSessions:
    """Sign-in rows have to expire, and only once their tokens already have.

    Every sign-in writes a family, and so does every password change (it rotates
    the session), so an installation that is merely *used* grew a table nothing
    ever read or removed. What the sweep must not do is the opposite mistake:
    deleting a row that is still the only reason a replayed refresh token is
    answered with `family_revoked` rather than silently `family_not_found`.
    """

    @pytest.fixture(autouse=True)
    def _lifetime(self, monkeypatch):
        monkeypatch.setattr(settings, "JWT_REFRESH_TOKEN_EXPIRE_DAYS", 3)

    @pytest.mark.asyncio
    async def test_a_live_session_is_never_selected(self, db_session):
        # The predicate is `revoked_at < cutoff`, and a session in use has no
        # `revoked_at` — including one that was created long ago, which is what
        # a refresh cookie keeps alive.
        live_recent = await _add_session(db_session, created_days_ago=1)
        live_old = await _add_session(db_session, created_days_ago=90)

        result = await rt.purge_expired_sessions(db_session)

        assert result.deleted_rows == 0
        assert await _session_rows(db_session) == {live_recent, live_old}

    @pytest.mark.asyncio
    async def test_a_recently_ended_session_is_kept(self, db_session):
        ended = await _add_session(db_session, created_days_ago=8, revoked_days_ago=1)

        result = await rt.purge_expired_sessions(db_session)

        assert result.deleted_rows == 0
        assert await _session_rows(db_session) == {ended}

    @pytest.mark.asyncio
    async def test_a_session_whose_tokens_expired_is_removed(self, db_session):
        # Revoked at the last moment a token of this family could have been
        # minted: three days later that token expires, and the row is weight.
        await _add_session(db_session, created_days_ago=30, revoked_days_ago=5)
        ended = await _add_session(db_session, created_days_ago=8, revoked_days_ago=1)

        result = await rt.purge_expired_sessions(db_session)

        assert result.deleted_rows == 1
        assert await _session_rows(db_session) == {ended}

    @pytest.mark.asyncio
    async def test_a_nonsensical_lifetime_keeps_at_least_a_day(self, db_session, monkeypatch):
        # 0 would mean "delete the session of the browser that is using it", and
        # the refresh window is the only thing that makes the row useful.
        monkeypatch.setattr(settings, "JWT_REFRESH_TOKEN_EXPIRE_DAYS", 0)
        just_ended = await _add_session(db_session, created_days_ago=1, revoked_days_ago=0)

        result = await rt.purge_expired_sessions(db_session)

        assert result.deleted_rows == 0
        assert await _session_rows(db_session) == {just_ended}

    @pytest.mark.asyncio
    async def test_the_sweep_runs_it_and_reports_the_table(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "AUDIT_RETENTION_DAYS", 0)
        monkeypatch.setattr(settings, "REPORT_RETENTION_DAYS", 0)
        await _add_session(db_session, created_days_ago=30, revoked_days_ago=9)

        results = await rt.run_retention_sweep(db_session)

        assert results["drp_refresh_families"].deleted_rows == 1
        await rt._emit_sweep_audit(results)
        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == rt.ACTION_RETENTION_PURGED)
            )
        ).scalars().all()
        assert rows[0].details["tables"]["drp_refresh_families"]["deleted_rows"] == 1
        assert rows[0].details["session_retention_days"] == 3


class TestRetentionSweep:
    @pytest.mark.asyncio
    async def test_zero_days_keeps_the_audit_history(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "AUDIT_RETENTION_DAYS", 0)
        await _add_audit_rows(db_session, 3, age_days=4000)

        results = await rt.run_retention_sweep(db_session)

        assert results["drp_audit_logs"].deleted_rows == 0
        assert await _audit_count(db_session) == 3

    @pytest.mark.asyncio
    async def test_enabled_retention_deletes_the_expired_rows(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "AUDIT_RETENTION_DAYS", 365)
        monkeypatch.setattr(settings, "REPORT_RETENTION_DAYS", 0)
        await _add_audit_rows(db_session, 4, age_days=400)

        results = await rt.run_retention_sweep(db_session)

        assert results["drp_audit_logs"].deleted_rows == 4
        assert await _audit_count(db_session) == 0

    @pytest.mark.asyncio
    async def test_sweep_writes_an_audit_row_when_it_deletes(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "AUDIT_RETENTION_DAYS", 365)
        monkeypatch.setattr(settings, "REPORT_RETENTION_DAYS", 0)
        await _add_audit_rows(db_session, 2, age_days=400)

        results = await rt.run_retention_sweep(db_session)
        await rt._emit_sweep_audit(results)

        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == rt.ACTION_RETENTION_PURGED)
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].details["tables"]["drp_audit_logs"]["deleted_rows"] == 2

    @pytest.mark.asyncio
    async def test_sweep_writes_nothing_when_it_deletes_nothing(
        self, db_session, monkeypatch
    ):
        monkeypatch.setattr(settings, "AUDIT_RETENTION_DAYS", 365)
        monkeypatch.setattr(settings, "REPORT_RETENTION_DAYS", 365)

        results = await rt.run_retention_sweep(db_session)
        await rt._emit_sweep_audit(results)

        assert await _audit_count(db_session) == 0

    def test_the_purge_action_is_allowlisted(self):
        """An unlisted action is stored under a name the UI cannot label."""
        assert rt.ACTION_RETENTION_PURGED in AUDIT_ALLOWED_ACTIONS


class TestPurgeTask:
    @pytest.mark.asyncio
    async def test_task_returns_a_json_serializable_summary(self, db_session, monkeypatch):
        from app.tasks.retention_tasks import purge_expired_data_task

        monkeypatch.setattr(settings, "AUDIT_RETENTION_DAYS", 365)
        monkeypatch.setattr(settings, "REPORT_RETENTION_DAYS", 365)
        await _add_audit_rows(db_session, 1, age_days=400)
        await db_session.commit()

        import asyncio
        import functools
        import json

        # ``.run`` is the ``async_task``-wrapped callable, which drives its own
        # event loop, so it must be invoked off the test loop.
        summary = await asyncio.get_running_loop().run_in_executor(
            None, functools.partial(purge_expired_data_task.run)
        )

        assert set(summary) == {"drp_audit_logs", "reports", "drp_refresh_families"}
        json.dumps(summary)  # the Celery result must be JSON-serializable
