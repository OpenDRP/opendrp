"""The corners of the sweep that a normal run does not reach.

`test_retention_tasks.py` covers the paths an operator sees every night: the
cutoff, the batch cap, the artifact containment. This file covers the runs that
only happen when something else went wrong — a file the sweep cannot unlink, an
artifact name it refuses, a backlog deeper than the per-run batch cap, a chain
delete that has to record what it retired, and an audit write that fails after the
deletions are already committed.
"""

from __future__ import annotations

import asyncio
import functools
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.audit import AuditLog
from app.core.config import settings
from app.models.alert_delivery import AlertDelivery, AlertDeliveryStatus
from app.models.report import Report, ReportArtifactCleanup
from app.models.tls_certificate import TLSCertificateIdentity
from app.tasks import retention_tasks as rt



def now() -> datetime:
    """Read at call time: a full-suite run is long enough to age a constant."""
    return datetime.now(timezone.utc)


def _old(days: int) -> datetime:
    return now() - timedelta(days=days)


async def _signed_rows(db, count: int, *, age_days: int = 400) -> list[AuditLog]:
    """Old rows written the way the logger writes them: signed chain links."""
    from app.core.audit import AuditLogger

    for index in range(count):
        await AuditLogger.emit(
            db,
            action="asset.view",
            ip_address="internal:test",
            details={"index": index},
            # Distinct moments: a batch is ordered by the timestamp column, so
            # equal values would make "which two rows" a database's choice.
            timestamp=_old(age_days) + timedelta(seconds=index),
            require_persistence=True,
        )
    return list((await db.execute(select(AuditLog).order_by(AuditLog.seq))).scalars())


# ---------------------------------------------------------------------------
# A chain delete has to record what it retired
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_chain_table_delete_reports_the_positions_it_retired(db_session):
    """The watermark and tip are read before the delete, in the same transaction.

    A separate transaction would be a crash window: rows gone, watermark not moved,
    and the next verification reporting a breach that never happened. The callback
    is how the sweep moves the state, so what it is handed has to be the batch's
    highest position and hash.
    """
    rows = await _signed_rows(db_session, 3)
    calls: list[tuple[int, int, str | None]] = []

    async def on_batch(db, result):
        calls.append((result.batches, result.retired_through_seq, result.retired_tip_hash))

    result = await rt.purge_table(
        db_session,
        model=AuditLog,
        timestamp_column=AuditLog.timestamp,
        cutoff=_old(365),
        batch_size=2,
        max_batches=10,
        seq_column=AuditLog.seq,
        hash_column=AuditLog.entry_hash,
        on_batch=on_batch,
    )

    assert result.deleted_rows == 3
    assert calls[0][1] == rows[1].seq and calls[0][2] == rows[1].entry_hash
    assert calls[1][1] == rows[2].seq and calls[1][2] == rows[2].entry_hash
    assert list((await db_session.execute(select(AuditLog.seq))).scalars()) == []


# ---------------------------------------------------------------------------
# Files the sweep is not allowed to remove, and files it cannot
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "reports_store"
    directory.mkdir()
    monkeypatch.setattr(settings, "REPORTS_STORE_DIR", str(directory))
    return directory


def test_a_temporary_file_that_cannot_be_unlinked_is_reported_not_raised(store, monkeypatch):
    """A locked file on a network share must not end the sweep before the rows go."""
    stale = store / f".{uuid.uuid4().hex}.pdf.tmp"
    stale.write_bytes(b"abandoned")
    moment = now()
    old = (moment - timedelta(hours=2)).timestamp()
    os.utime(stale, (old, old))
    real_unlink = Path.unlink

    def locked(self, *args, **kwargs):
        if self.name == stale.name:
            raise OSError("another process has it open")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", locked)
    assert rt.purge_stale_report_temporary_files(now=moment) == 0
    assert Path(stale).exists()


@pytest.mark.asyncio
async def test_an_intent_naming_an_artifact_outside_the_store_is_not_retried_forever(db_session, store):
    """A name the store can never contain is a finding, not a transient failure.

    It is kept with its reason and a backoff rather than deleted, because deleting
    it would erase the only record that a row pointed somewhere it should not.
    """
    intent = ReportArtifactCleanup(
        artifact_name="../outside.pdf",
        available_at=_old(1),
        attempts=0,
    )
    db_session.add(intent)
    await db_session.commit()

    moment = now()
    cleaned = await rt.retry_report_artifact_cleanup(db_session, now=moment, batch_size=10)

    assert cleaned == 0
    stored = await db_session.get(ReportArtifactCleanup, "../outside.pdf")
    assert stored is not None
    assert stored.attempts == 1
    assert stored.last_error == "artifact rejected: not_a_name"
    # SQLite hands the column back naive; the intent is in the future either way.
    available = stored.available_at if stored.available_at.tzinfo else stored.available_at.replace(tzinfo=timezone.utc)
    assert available > moment


@pytest.mark.asyncio
async def test_a_file_that_vanished_between_the_check_and_the_unlink_is_success(db_session, store, monkeypatch):
    """The intent's whole job is to make the file gone; already gone is the same answer."""
    artifact = store / f"{uuid.uuid4().hex}.pdf"
    artifact.write_bytes(b"%PDF-1.7")
    db_session.add(ReportArtifactCleanup(artifact_name=artifact.name, available_at=_old(1)))
    await db_session.commit()

    def already_gone(_path):
        raise FileNotFoundError(_path)

    monkeypatch.setattr(rt.os, "remove", already_gone)
    assert await rt.retry_report_artifact_cleanup(db_session, now=now(), batch_size=10) == 1
    assert await db_session.get(ReportArtifactCleanup, artifact.name) is None


@pytest.mark.asyncio
async def test_an_unlink_that_fails_for_another_reason_is_scheduled_with_a_backoff(db_session, store, monkeypatch):
    """The retry keeps the intent and says why, so the log names the artifact."""
    artifact = store / f"{uuid.uuid4().hex}.pdf"
    artifact.write_bytes(b"%PDF-1.7")
    db_session.add(ReportArtifactCleanup(artifact_name=artifact.name, available_at=_old(1), attempts=2))
    await db_session.commit()

    def permission_denied(_path):
        raise PermissionError("read-only store")

    monkeypatch.setattr(rt.os, "remove", permission_denied)
    moment = now()
    assert await rt.retry_report_artifact_cleanup(db_session, now=moment, batch_size=10) == 0

    stored = await db_session.get(ReportArtifactCleanup, artifact.name)
    await db_session.refresh(stored)
    assert stored.attempts == 3
    assert "read-only store" in stored.last_error
    available = stored.available_at if stored.available_at.tzinfo else stored.available_at.replace(tzinfo=timezone.utc)
    assert available == moment + timedelta(minutes=min(60, 2**3))


@pytest.mark.asyncio
async def test_a_report_row_without_an_artifact_name_is_deleted_without_a_cleanup_intent(db_session, store):
    """The row is what retention was asked for; an empty name is not a file."""
    db_session.add(
        Report(
            report_name="no-artifact",
            file_path="",
            status="completed",
            created_at=_old(400),
            updated_at=_old(400),
        )
    )
    await db_session.commit()

    result = await rt.purge_expired_reports(db_session, cutoff=_old(365), batch_size=100, max_batches=10, now=now())

    assert result.deleted_rows == 1
    assert list((await db_session.execute(select(ReportArtifactCleanup))).scalars()) == []


@pytest.mark.asyncio
async def test_intents_outside_the_store_are_named_in_the_sweep_result(db_session, store):
    """The sweep result is what the audit row is built from, so the refusal is in it."""
    db_session.add(ReportArtifactCleanup(artifact_name="notes.txt", available_at=_old(1)))
    await db_session.commit()

    result = await rt.purge_expired_reports(db_session, cutoff=_old(365), batch_size=100, max_batches=10, now=now())

    assert "notes.txt" in result.outside_store_paths


# ---------------------------------------------------------------------------
# Backlogs deeper than one run
# ---------------------------------------------------------------------------


@pytest.fixture
def narrow_run(monkeypatch):
    """One batch of one row per run: the smallest cap the sweep accepts."""
    monkeypatch.setattr(settings, "RETENTION_BATCH_SIZE", 1)
    monkeypatch.setattr(settings, "RETENTION_MAX_BATCHES_PER_RUN", 1)


@pytest.mark.asyncio
async def test_a_chain_backlog_deeper_than_the_cap_is_reported_truncated(db_session, monkeypatch, tmp_path, narrow_run):
    """A sweep that never finishes must not look like one that keeps up."""
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "AUDIT_RETENTION_DAYS", 365)
    monkeypatch.setattr(settings, "REPORT_RETENTION_DAYS", 0)
    await _signed_rows(db_session, 3)

    results = await rt.run_retention_sweep(db_session, now=now())

    assert results["drp_audit_logs"].deleted_rows == 1
    assert results["drp_audit_logs"].batches == 1
    assert results["drp_audit_logs"].truncated is True
    assert results["drp_audit_logs"].retired_through_seq == 1


@pytest.mark.asyncio
async def test_an_identity_backlog_deeper_than_the_cap_is_reported_truncated(db_session, monkeypatch, narrow_run):
    monkeypatch.setattr(settings, "TLS_CERTIFICATE_RETENTION_DAYS", 365)
    for fingerprint in ("a" * 64, "b" * 64):
        db_session.add(
            TLSCertificateIdentity(
                fingerprint_sha256=fingerprint,
                origin="ct",
                first_seen_at=_old(400),
                last_seen_at=_old(400),
                san_dns=[],
            )
        )
    await db_session.commit()

    results = await rt.purge_expired_certificate_evidence(db_session, now=now())

    assert results["tls_certificate_identities"].deleted_rows == 1
    assert results["tls_certificate_identities"].truncated is True
    assert len(list((await db_session.execute(select(TLSCertificateIdentity))).scalars())) == 1


@pytest.mark.asyncio
async def test_alert_history_can_be_switched_off_and_reports_its_own_truncation(db_session, monkeypatch, narrow_run):
    """A deployment that keeps alert history for its own reasons must not lose it."""
    monkeypatch.setattr(settings, "ALERT_HISTORY_RETENTION_DAYS", 0)
    for _ in range(2):
        db_session.add(
            AlertDelivery(
                channel="telegram",
                target="1234",
                threat_type="phishing",
                payload={},
                status=AlertDeliveryStatus.sent,
                created_at=_old(200),
                updated_at=_old(200),
            )
        )
    await db_session.commit()

    assert await rt.purge_terminal_alert_history(db_session, now=now()) == {}
    assert len(list((await db_session.execute(select(AlertDelivery))).scalars())) == 2

    monkeypatch.setattr(settings, "ALERT_HISTORY_RETENTION_DAYS", 90)
    results = await rt.purge_terminal_alert_history(db_session, now=now())

    assert results["alert_deliveries"].deleted_rows == 1
    assert results["alert_deliveries"].truncated is True


# ---------------------------------------------------------------------------
# What the run leaves behind, and what it does when that fails
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_truncated_run_says_so_on_its_audit_row(db_session, monkeypatch, narrow_run):
    """The row is read by whoever asks "is retention keeping up", so it must carry it."""
    monkeypatch.setattr(settings, "AUDIT_RETENTION_DAYS", 0)
    monkeypatch.setattr(settings, "REPORT_RETENTION_DAYS", 0)
    monkeypatch.setattr(settings, "TLS_CERTIFICATE_RETENTION_DAYS", 365)
    for fingerprint in ("c" * 64, "d" * 64):
        db_session.add(
            TLSCertificateIdentity(
                fingerprint_sha256=fingerprint,
                origin="ct",
                first_seen_at=_old(400),
                last_seen_at=_old(400),
                san_dns=[],
            )
        )
    await db_session.commit()

    results = await rt.run_retention_sweep(db_session, now=now())
    await rt._emit_sweep_audit(results)

    row = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == rt.ACTION_RETENTION_PURGED))
    ).scalars().one()
    assert row.details["truncated"] is True
    assert row.details["tables"]["tls_certificate_identities"]["truncated"] is True


@pytest.mark.asyncio
async def test_a_failed_audit_write_does_not_turn_a_finished_sweep_into_a_failure(db_session, monkeypatch):
    """The deletions are committed before the row is written, so failing to write it
    must not report the whole run as a failure the scheduler would retry.
    """
    monkeypatch.setattr(settings, "AUDIT_RETENTION_DAYS", 0)
    monkeypatch.setattr(settings, "REPORT_RETENTION_DAYS", 0)
    monkeypatch.setattr(settings, "TLS_CERTIFICATE_RETENTION_DAYS", 0)

    async def broken_emit(_results):
        raise RuntimeError("audit chain is locked")

    monkeypatch.setattr(rt, "_emit_sweep_audit", broken_emit)
    summary = await asyncio.get_running_loop().run_in_executor(
        None, functools.partial(rt.purge_expired_data_task.run)
    )

    assert "drp_audit_logs" in summary
    assert summary["drp_audit_logs"]["deleted_rows"] == 0
