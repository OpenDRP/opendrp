"""Nightly retention sweep for audit rows, report artifacts and dead sessions.

Why this exists
---------------
``AuditLogger.emit`` writes a row for every authenticated read, so
``drp_audit_logs`` grows with *usage* rather than with the size of the
inventory: the busiest table in the schema had no bound at all. Generated
reports accumulate next to it in ``REPORTS_STORE_DIR``, where nothing removed
them either. ``drp_refresh_families`` had the same shape from the other
direction: one row per sign-in, and a password change adds another (it rotates
the session), so an installation that is merely *used* grew a table nobody ever
read again. On a long-lived installation all three eventually fill the volume,
and the failure mode is the worst possible one for a security product — the
audit pipeline stops recording because the disk is full.

What this does not do
---------------------
It does not touch the log pipeline. Audit events are *also* emitted to stdout
and shipped to a SIEM by the collector; retention here governs the database
copy only, and the operator chooses how long the SIEM keeps its own copy. Nor
does it partition the table: batching keeps each transaction short on the
existing ``timestamp`` index, and partitioning is worth its complexity only
once the row count is known to justify it (see docs/production-readiness.md).

The sweep is bounded by ``RETENTION_MAX_BATCHES_PER_RUN`` so a first run
against years of backlog cannot hold the worker for an unbounded time; a
truncated run reports how far it got and the next night continues.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import delete, exists, func, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.core.celery_app import async_task, celery_app
from app.core.config import settings

log = structlog.get_logger()

#: Audit action recorded when the sweep actually deletes something. A run that
#: deletes nothing writes no row: an audit trail that records daily no-ops
#: trains its readers to ignore it.
ACTION_RETENTION_PURGED = "audit.retention.purged"
#: The state a report is left in when the worker that owned it disappeared.
#: Recorded as its own action: a generation that nobody is running is an
#: operational fact (a killed worker, a lost message), not a retention decision.
ACTION_REPORT_GENERATION_ABANDONED = "report.generate.abandoned"
_TEMP_ARTIFACT_RE = re.compile(r"^\.[0-9a-f]{32}\.pdf\.tmp$")

#: A report is abandoned when it has been `generating` for twice the configured
#: generation timeout (and never for less than ten minutes). The task's own hard
#: limit is the timeout plus thirty seconds, so a renderer that is still alive
#: cannot be older than this guard — the sweep cannot take a report away from a
#: worker that is merely slow.
ABANDONED_GENERATION_MIN_AGE_SECONDS = 600

#: How long a `schedule_occurrences` row is kept. The scheduler re-examines the
#: current minute and the nine before it, so an occurrence older than that window
#: can never be consulted again; the window is kept long enough that an operator
#: investigating a missed scan still finds the ledger. Thirty days is a reading
#: aid, not a correctness bound.
SCHEDULE_OCCURRENCE_RETENTION_DAYS = 30


@dataclass
class PurgeResult:
    """Outcome of one table's sweep."""

    table: str
    deleted_rows: int = 0
    batches: int = 0
    #: Rows the sweep *repaired* rather than deleted (reports only: a generation
    #: that no worker owns any more is moved to `failed`, not removed).
    reconciled: int = 0
    #: True when the batch cap was hit and rows past the cutoff remain.
    truncated: bool = False
    #: Artifacts the sweep removed from the report store (reports only).
    removed_artifacts: int = 0
    #: Paths outside the store directory, skipped rather than unlinked.
    outside_store_paths: list[str] = field(default_factory=list)
    #: Highest audit-chain position this sweep deleted, and the last hash it
    #: removed. Recorded on the chain state in the same transaction, so that the
    #: deletion and the bookkeeping cannot disagree.
    retired_through_seq: int = 0
    retired_tip_hash: str | None = None

    @property
    def deleted_anything(self) -> bool:
        return self.deleted_rows > 0 or self.removed_artifacts > 0


def resolve_store_artifact(stored: str | None) -> str | None:
    """Return an absolute path inside the report store, else ``None``.

    The value comes from a database column, so it is treated as untrusted input:
    an artifact that does not resolve to a regular file inside
    ``REPORTS_STORE_DIR`` must never be unlinked by a scheduled job. The rules
    live in `app/core/artifact_path.py`, which the API's download route and the
    report task use too — a sweep with its own private notion of containment is
    a second implementation waiting to disagree with the first one.
    """
    from app.core.artifact_path import REASON_OK, classify_artifact

    resolved, reason = classify_artifact(stored)
    if reason != REASON_OK:
        return None
    return str(resolved)


async def purge_table(
    db,
    *,
    model,
    timestamp_column,
    cutoff: datetime,
    batch_size: int,
    max_batches: int,
    seq_column=None,
    hash_column=None,
    on_batch=None,
    key_column=None,
) -> PurgeResult:
    """Delete rows older than ``cutoff`` in bounded batches.

    Each batch is its own transaction: the alternative — one statement for the
    whole history — locks every row it touches for the duration, inflates the
    WAL, and on PostgreSQL delays vacuum precisely when the table most needs it.
    """
    result = PurgeResult(table=model.__tablename__)
    # A ledger table may be keyed by something other than `id`
    # (`schedule_occurrences` is keyed by the occurrence itself), and the
    # batched delete is worth having one implementation of rather than two.
    primary_key = key_column if key_column is not None else model.id
    while result.batches < max_batches:
        subquery = (
            select(primary_key)
            .where(timestamp_column < cutoff)
            .order_by(timestamp_column)
            .limit(batch_size)
        )
        # The positions and hashes of the batch are read *before* the delete, so
        # that a table which is part of the audit chain can record what it is
        # about to retire in the same transaction that retires it. A separate
        # transaction would be a crash window: rows deleted, watermark not moved,
        # and the next verification reporting a breach that never happened.
        if seq_column is not None:
            batch_rows = (
                await db.execute(
                    select(seq_column, hash_column).where(primary_key.in_(subquery))
                )
            ).all()
            if batch_rows:
                result.retired_through_seq = max(
                    [result.retired_through_seq]
                    + [int(row[0]) for row in batch_rows if row[0] is not None]
                )
                signed = [
                    (int(row[0]), str(row[1]))
                    for row in batch_rows
                    if row[0] is not None and row[1]
                ]
                if signed:
                    highest = max(signed, key=lambda item: item[0])
                    result.retired_tip_hash = highest[1]

        outcome = await db.execute(delete(model).where(primary_key.in_(subquery)))
        if on_batch is not None and seq_column is not None:
            await on_batch(db, result)
        await db.commit()
        deleted = int(outcome.rowcount or 0)
        if deleted == 0:
            return result
        result.batches += 1
        result.deleted_rows += deleted
        if deleted < batch_size:
            # Drained: fewer rows than a full batch means the predicate is
            # exhausted, which is the only signal that the sweep is complete.
            return result

    # Ran out of batches with the last one full, so rows past the cutoff may
    # remain. Reported rather than assumed either way: the next run continues.
    result.truncated = True
    return result


def purge_stale_report_temporary_files(*, now: datetime) -> int:
    """Remove only abandoned temporary PDFs from timed-out render attempts.

    A timed-out executor thread cleans its own file when it finishes. This
    sweep is the crash-recovery boundary for a worker killed after rendering
    started but before that callback ran. The age guard is deliberately longer
    than the report timeout so an active renderer is never touched.
    """
    from app.core.artifact_path import store_directory

    directory = store_directory()
    minimum_age = max(settings.REPORT_GENERATION_TIMEOUT_SECONDS * 2, 600)
    removed = 0
    try:
        entries = list(directory.iterdir())
    except OSError:
        return 0
    for entry in entries:
        if not entry.is_file() or not _TEMP_ARTIFACT_RE.fullmatch(entry.name):
            continue
        try:
            age = now.timestamp() - entry.stat().st_mtime
            if age < minimum_age:
                continue
            entry.unlink()
            removed += 1
        except OSError as exc:
            log.warning(
                "report_stale_temporary_not_removed",
                artifact=entry.name,
                err=str(exc)[:200],
            )
    return removed


async def retry_report_audit_outbox(db, *, now: datetime, batch_size: int) -> int:
    from app.tasks.report_tasks import deliver_report_audit_outbox

    return await deliver_report_audit_outbox(db, now=now, batch_size=batch_size)


async def retry_report_artifact_cleanup(db, *, now: datetime, batch_size: int) -> int:
    """Retry durable cleanup intents without deleting anything outside the store."""
    from app.core.artifact_path import classify_artifact, REASON_MISSING, REASON_NO_NAME
    from app.models import ReportArtifactCleanup, Report

    cleaned = 0
    intents = list(
        (
            await db.execute(
                select(ReportArtifactCleanup)
                .where(
                    ReportArtifactCleanup.available_at <= now,
                    # A retained soft-deleted report is the normal owner of a
                    # delete cleanup intent. Only defer while a matching report
                    # is still pending/generating; excluding `deleted` here
                    # would strand every retry after an unlink failure.
                    ~select(Report.id)
                    .where(
                        Report.id == ReportArtifactCleanup.report_id,
                        Report.status.in_(("pending", "generating")),
                    )
                    .exists(),
                    ~select(Report.id)
                    .where(
                        Report.file_path == ReportArtifactCleanup.artifact_name,
                        Report.status.notin_(("deleted", "failed")),
                    )
                    .exists(),
                )
                .order_by(
                    ReportArtifactCleanup.available_at,
                    ReportArtifactCleanup.artifact_name,
                )
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    for intent in intents:
        intent_id = intent.artifact_name
        resolved, reason = classify_artifact(intent_id)
        if resolved is None and reason not in {REASON_MISSING, REASON_NO_NAME}:
            intent.attempts += 1
            intent.last_error = f"artifact rejected: {reason}"[:500]
            intent.available_at = now + timedelta(minutes=min(60, 2 ** min(intent.attempts, 6)))
            continue
        if resolved is not None:
            try:
                await __import__("asyncio").to_thread(os.remove, resolved)
            except FileNotFoundError:
                pass
            except OSError as exc:
                intent.attempts += 1
                intent.last_error = str(exc)[:500]
                intent.available_at = now + timedelta(minutes=min(60, 2 ** min(intent.attempts, 6)))
                log.warning("report_artifact_cleanup_retry_scheduled", artifact=intent_id, attempts=intent.attempts)
                continue
        await db.delete(intent)
        cleaned += 1
    await db.commit()
    await retry_report_audit_outbox(db, now=now, batch_size=batch_size)
    return cleaned


async def purge_expired_reports(
    db, *, cutoff: datetime, batch_size: int, max_batches: int, now: datetime | None = None
) -> PurgeResult:
    """Delete expired report rows, then their PDFs.

    Rows first, artifacts second, and the artifact is only removed once the row
    that referenced it is gone. The reverse order could delete a PDF and then
    fail to delete its row, leaving a report that can never be downloaded.
    """
    from app.models import Report, ReportArtifactCleanup, ReportAuditOutbox, ReportQueueControl

    result = PurgeResult(table=Report.__tablename__)
    drained = False
    while result.batches < max_batches:
        # Admission and retention share this singleton lock. Acquire it before
        # reading queue rows so the capacity decision and deletion cannot race.
        if db.get_bind().dialect.name == "sqlite":
            await db.execute(sqlite_insert(ReportQueueControl).values(id=1).on_conflict_do_nothing(index_elements=[ReportQueueControl.id]))
        else:
            await db.execute(pg_insert(ReportQueueControl).values(id=1).on_conflict_do_nothing(index_elements=[ReportQueueControl.id]))
        await db.execute(
            update(ReportQueueControl)
            .where(ReportQueueControl.id == 1)
            .values(touched_at=datetime.now(timezone.utc))
        )
        subquery = (
            select(Report.id)
            .where(
                Report.created_at < cutoff,
                Report.status.notin_(("pending", "generating", "deleted")),
            )
            .order_by(Report.created_at)
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        )
        rows = (
            await db.execute(
                select(Report.id, Report.file_path).where(Report.id.in_(subquery))
            )
        ).all()
        if not rows:
            drained = True
            break
        ids = [row[0] for row in rows]
        from app.core.artifact_path import classify_artifact, REASON_NOT_A_NAME, REASON_OUTSIDE_STORE
        for _report_id, stored in rows:
            if not stored:
                continue
            resolved, reason = classify_artifact(stored)
            if resolved is not None:
                if await db.get(ReportArtifactCleanup, str(stored)) is None:
                    db.add(ReportArtifactCleanup(artifact_name=str(stored), report_id=_report_id))
            elif reason in {REASON_NOT_A_NAME, REASON_OUTSIDE_STORE}:
                result.outside_store_paths.append(str(stored))
        await db.execute(
            delete(Report).where(
                Report.id.in_(ids),
                Report.status.notin_(("pending", "generating", "deleted")),
            )
        )
        for report_id in ids:
            event_key = f"{report_id}:report.retention.expired"
            exists = await db.scalar(
                select(ReportAuditOutbox.id).where(ReportAuditOutbox.event_key == event_key)
            )
            if exists is None:
                db.add(
                    ReportAuditOutbox(
                        event_key=event_key,
                        action="report.retention.expired",
                        report_id=report_id,
                        job_id=None,
                        details={
                            "report_id": str(report_id),
                            "status": "expired",
                        "artifact_cleanup_pending": any(
                            row[0] == report_id
                            and classify_artifact(row[1])[0] is not None
                            for row in rows
                        ),
                        },
                    )
                )
        await db.commit()
        result.batches += 1
        result.deleted_rows += len(ids)
        if len(ids) < batch_size:
            drained = True
            break

    result.truncated = not drained
    # Also recover temporary files left by a worker crash. This is independent
    # of expired report rows because temporary files are intentionally never
    # referenced by the database.
    result.removed_artifacts += purge_stale_report_temporary_files(
        now=now or datetime.now(timezone.utc)
    )

    from app.core.artifact_path import classify_artifact, REASON_MISSING, REASON_NO_NAME
    cleanup_intents = (await db.execute(
        select(ReportArtifactCleanup).limit(batch_size)
    )).scalars().all()
    for intent in cleanup_intents:
        _resolved, reason = classify_artifact(intent.artifact_name)
        if reason not in {REASON_MISSING, REASON_NO_NAME, "ok"}:
            result.outside_store_paths.append(intent.artifact_name)
    cleanup_now = now or datetime.now(timezone.utc)
    result.removed_artifacts += await retry_report_artifact_cleanup(
        db, now=cleanup_now, batch_size=batch_size
    )
    await retry_report_audit_outbox(db, now=cleanup_now, batch_size=batch_size)
    pending_cleanup = int((await db.execute(
        select(func.count(ReportArtifactCleanup.artifact_name)).where(
            ReportArtifactCleanup.available_at <= cleanup_now,
            ~select(Report.id).where(
                Report.file_path == ReportArtifactCleanup.artifact_name,
                Report.status.notin_(("deleted", "failed")),
            ).exists(),
        )
    )).scalar_one())
    if pending_cleanup:
        log.error("report_artifact_cleanup_pending", pending=pending_cleanup)
    return result


def abandoned_generation_cutoff(*, now: datetime) -> datetime:
    """The instant before which a `generating` report has no worker behind it."""
    seconds = max(
        settings.REPORT_GENERATION_TIMEOUT_SECONDS * 2,
        ABANDONED_GENERATION_MIN_AGE_SECONDS,
    )
    return now - timedelta(seconds=seconds)


async def reconcile_abandoned_report_generations(
    db, *, now: datetime, batch_size: int = 200
) -> list[str]:
    """Move reports nobody is generating any more to `failed`.

    A report is admitted against a *global* cap: ``POST /reports/generate``
    counts the rows that are ``pending`` or ``generating`` and answers ``429`` at
    ``REPORT_QUEUE_MAX_PENDING``. Retention deliberately skips both states, so a
    worker killed between the ``generating`` update and the terminal one — or a
    message the broker never redelivers — would otherwise own one of those slots
    for the life of the installation, and enough of them close the queue to
    everyone.

    The repair is a transition, not a deletion: the row becomes ``failed`` (which
    the API already renders and an operator can regenerate from), the job that
    owned it becomes ``error`` with the reason, and the sweep records one audit
    row naming the reports it moved. Nothing is unlinked here — the artifact, if
    the renderer finished writing one, is still the row's and is handled by the
    ordinary cleanup paths.
    """
    from app.core.audit import AuditLogger
    from app.models import Job, Report

    cutoff = abandoned_generation_cutoff(now=now)
    rows = list(
        (
            await db.execute(
                select(Report)
                .where(
                    Report.status == "generating",
                    Report.generation_started_at.is_not(None),
                    Report.generation_started_at <= cutoff,
                )
                .order_by(Report.generation_started_at)
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return []

    report_ids = [row.id for row in rows]
    for row in rows:
        row.status = "failed"
        row.generation_started_at = None

    # The job row is found by the report id its request put in `params`, which is
    # the only link the two share; `task_id` is the broker's, and a job whose
    # message was lost keeps one that will never be used again.
    job_ids = [
        job_id
        for job_id in (
            await db.execute(
                select(Job.id).where(
                    Job.job_type == "report.generate",
                    Job.status.in_(("pending", "running")),
                    Job.params["report_id"].as_string().in_(
                        [str(report_id) for report_id in report_ids]
                    ),
                )
            )
        )
        .scalars()
        .all()
    ]
    if job_ids:
        await db.execute(
            update(Job)
            .where(Job.id.in_(job_ids))
            .values(
                status="error",
                finished_at=datetime.now(timezone.utc),
                error_message="report_generation_abandoned",
            )
        )

    await AuditLogger.emit(
        db,
        action=ACTION_REPORT_GENERATION_ABANDONED,
        ip_address="internal:celery-beat",
        user_id=None,
        details={
            "reconciled": len(report_ids),
            "report_ids": [str(report_id) for report_id in report_ids[:50]],
            "job_ids": [str(job_id) for job_id in job_ids[:50]],
            "reason": "generation_abandoned",
            "generating_since_before": cutoff.isoformat(),
            "timeout_seconds": settings.REPORT_GENERATION_TIMEOUT_SECONDS,
        },
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    log.warning(
        "report_generation_abandoned",
        reconciled=len(report_ids),
        report_ids=[str(report_id) for report_id in report_ids[:20]],
    )
    return [str(report_id) for report_id in report_ids]


async def purge_schedule_occurrences(
    db, *, now: datetime, batch_size: int, max_batches: int = 1
) -> PurgeResult:
    """Delete schedule-ledger rows that can never be consulted again.

    The scheduler looks at the current minute and the nine before it, and its
    ledger key is the connector plus the occurrence minute — so an entry older
    than that window is unreachable, while the window itself is what makes a
    re-examined minute dispatch once (and survives the deletion of the job it
    produced). Nothing pruned the table, so it grew with every fired occurrence
    for the life of the installation.
    """
    from app.models.job import ScheduleOccurrence

    return await purge_table(
        db,
        model=ScheduleOccurrence,
        timestamp_column=ScheduleOccurrence.created_at,
        cutoff=now - timedelta(days=SCHEDULE_OCCURRENCE_RETENTION_DAYS),
        batch_size=batch_size,
        max_batches=max_batches,
        key_column=ScheduleOccurrence.key,
    )


async def run_retention_sweep(
    db, *, now: datetime | None = None
) -> dict[str, PurgeResult]:
    """Run both sweeps. Returns per-table results, including disabled ones."""
    moment = now or datetime.now(timezone.utc)
    results: dict[str, PurgeResult] = {}

    if settings.AUDIT_RETENTION_DAYS <= 0:
        results["drp_audit_logs"] = PurgeResult(
            table="drp_audit_logs", truncated=False
        )
    else:
        from app.services.audit_archive import archive_prefix

        cutoff = moment - timedelta(days=settings.AUDIT_RETENTION_DAYS)
        audit_result = PurgeResult(table="drp_audit_logs")
        results["drp_audit_logs"] = audit_result
        try:
            for _ in range(settings.RETENTION_MAX_BATCHES_PER_RUN):
                archived = await archive_prefix(db, cutoff=cutoff, limit=settings.RETENTION_BATCH_SIZE)
                count = archived["deleted"]
                if not count:
                    break
                audit_result.deleted_rows += count
                audit_result.batches += 1
                audit_result.retired_through_seq = archived["through_seq"]
                audit_result.retired_tip_hash = archived["tip_hash"]
            else:
                audit_result.truncated = True
        except (ValueError, OSError) as exc:
            await db.rollback()
            log.error("audit_archive_retention_blocked", error=type(exc).__name__)

    if settings.REPORT_RETENTION_DAYS <= 0:
        results["reports"] = PurgeResult(table="reports")
        results["reports"].removed_artifacts += await retry_report_artifact_cleanup(
            db, now=moment, batch_size=settings.RETENTION_BATCH_SIZE
        )
        await retry_report_audit_outbox(
            db, now=moment, batch_size=settings.RETENTION_BATCH_SIZE
        )
    else:
        cutoff = moment - timedelta(days=settings.REPORT_RETENTION_DAYS)
        results["reports"] = await purge_expired_reports(
            db,
            cutoff=cutoff,
            batch_size=settings.RETENTION_BATCH_SIZE,
            max_batches=settings.RETENTION_MAX_BATCHES_PER_RUN,
            now=moment,
        )

    # Repaired after the retention decision on purpose: `purge_expired_reports`
    # skips `pending` and `generating`, so the order cannot change what is
    # deleted. What it changes is the admission count — the queue counts both
    # states, and a generation nobody owns must stop being one of them.
    results["reports"].reconciled = len(
        await reconcile_abandoned_report_generations(
            db, now=moment, batch_size=settings.RETENTION_BATCH_SIZE
        )
    )

    results["schedule_occurrences"] = await purge_schedule_occurrences(
        db,
        now=moment,
        batch_size=settings.RETENTION_BATCH_SIZE,
        max_batches=settings.RETENTION_MAX_BATCHES_PER_RUN,
    )

    results["drp_refresh_families"] = await purge_expired_sessions(db, now=moment)

    results.update(await purge_terminal_alert_history(db, now=moment))
    results.update(await purge_expired_certificate_evidence(db, now=moment))
    return results


async def purge_expired_certificate_evidence(db, *, now) -> dict[str, PurgeResult]:
    """Bound the certificate identity/sighting evidence the design adds (WI-23).

    Two tables grow with every scan and provider read, and neither had a policy: a
    sighting that has not been observed for the configured window is history, an
    identity with no sightings left is only weight, and a scope exception past its
    own expiry date is a rule that silently stopped applying.
    """
    from app.models.tls_certificate import (
        CertificateScopeException,
        TLSCertificateIdentity,
        TLSCertificateSighting,
    )

    results: dict[str, PurgeResult] = {}
    if settings.TLS_CERTIFICATE_RETENTION_DAYS <= 0:
        for model in (TLSCertificateSighting, TLSCertificateIdentity, CertificateScopeException):
            results[model.__tablename__] = PurgeResult(table=model.__tablename__)
        return results
    cutoff = now - timedelta(days=settings.TLS_CERTIFICATE_RETENTION_DAYS)
    results[TLSCertificateSighting.__tablename__] = await purge_table(
        db,
        model=TLSCertificateSighting,
        timestamp_column=TLSCertificateSighting.last_seen_at,
        cutoff=cutoff,
        batch_size=settings.RETENTION_BATCH_SIZE,
        max_batches=settings.RETENTION_MAX_BATCHES_PER_RUN,
    )
    # An identity is kept while any sighting still refers to it: the fingerprint is what
    # the review workflow and the rules name, so an orphaned one is unreachable.
    orphan = ~exists().where(TLSCertificateSighting.identity_id == TLSCertificateIdentity.id)
    result = PurgeResult(table=TLSCertificateIdentity.__tablename__)
    for _ in range(settings.RETENTION_MAX_BATCHES_PER_RUN):
        ids = (
            select(TLSCertificateIdentity.id)
            .where(TLSCertificateIdentity.last_seen_at < cutoff, orphan)
            .order_by(TLSCertificateIdentity.last_seen_at)
            .limit(settings.RETENTION_BATCH_SIZE)
        )
        outcome = await db.execute(delete(TLSCertificateIdentity).where(TLSCertificateIdentity.id.in_(ids)))
        await db.commit()
        count = outcome.rowcount or 0
        result.deleted_rows += count
        result.batches += int(count > 0)
        if count < settings.RETENTION_BATCH_SIZE:
            break
    else:
        result.truncated = True
    results[TLSCertificateIdentity.__tablename__] = result
    results[CertificateScopeException.__tablename__] = await purge_table(
        db,
        model=CertificateScopeException,
        timestamp_column=CertificateScopeException.expires_at,
        cutoff=now,
        batch_size=settings.RETENTION_BATCH_SIZE,
        max_batches=settings.RETENTION_MAX_BATCHES_PER_RUN,
    )
    return results


async def purge_terminal_alert_history(db, *, now):
    from app.models.alert_delivery import AlertDelivery, AlertDeliveryStatus
    from app.models.ingestion_event import IngestionEvent
    results = {}
    if settings.ALERT_HISTORY_RETENTION_DAYS <= 0:
        return results
    cutoff = now - timedelta(days=settings.ALERT_HISTORY_RETENTION_DAYS)
    specs = [(AlertDelivery, AlertDelivery.updated_at < cutoff, AlertDelivery.status.in_([AlertDeliveryStatus.sent, AlertDeliveryStatus.failed, AlertDeliveryStatus.cancelled])), (IngestionEvent, IngestionEvent.processed_at < cutoff, IngestionEvent.processed_at.is_not(None))]
    for model, expired, terminal in specs:
        result = PurgeResult(table=model.__tablename__)
        for _ in range(settings.RETENTION_MAX_BATCHES_PER_RUN):
            ids = select(model.id).where(expired, terminal).order_by(model.created_at, model.id).limit(settings.RETENTION_BATCH_SIZE)
            outcome = await db.execute(delete(model).where(model.id.in_(ids)))
            await db.commit()
            count = outcome.rowcount or 0
            result.deleted_rows += count
            result.batches += int(count > 0)
            if count < settings.RETENTION_BATCH_SIZE:
                break
        else:
            result.truncated = True
        results[model.__tablename__] = result
    return results


async def purge_expired_sessions(db, *, now: datetime | None = None) -> PurgeResult:
    """Remove session rows whose tokens can no longer be presented.

    Every sign-in, and every password change (which rotates the session), writes
    a `drp_refresh_families` row that nothing removed: a long-lived installation
    accumulated one per sign-in forever, and the sessions API returned them, so
    the list grew without a bound and dead rows competed with live ones. A row
    is only useful for as long as one of its tokens can be presented: the last
    token of a revoked family was minted at `revoked_at`, and it expires
    `JWT_REFRESH_TOKEN_EXPIRE_DAYS` later. Until that moment the row is what
    turns a replayed token into `family_revoked` — a refusal that says the
    session was *signed out* — instead of the indistinguishable
    `family_not_found`. After it, presenting one fails on expiry before any
    lookup, so the row is only weight.

    The predicate is `revoked_at < cutoff` and needs no `revoked` test beside
    it: a live family has no `revoked_at`, and SQL never matches NULL against a
    comparison, so a session in use cannot be selected here.
    """
    from app.models.token import RefreshTokenFamily

    moment = now or datetime.now(timezone.utc)
    # At least a day, so a nonsensical setting cannot delete the session of a
    # running browser whose refresh cookie is still valid.
    lifetime = max(settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 1)
    return await purge_table(
        db,
        model=RefreshTokenFamily,
        timestamp_column=RefreshTokenFamily.revoked_at,
        cutoff=moment - timedelta(days=lifetime),
        batch_size=settings.RETENTION_BATCH_SIZE,
        max_batches=settings.RETENTION_MAX_BATCHES_PER_RUN,
    )


async def _emit_sweep_audit(results: dict[str, PurgeResult]) -> None:
    """Record a row only for a sweep that actually removed something."""
    deletable = {name: r for name, r in results.items() if r.deleted_anything}
    if not deletable:
        return
    from app.core.audit import AuditLogger
    from app.core.database import AsyncSessionLocal

    details = {
        "tables": {
            name: {
                "deleted_rows": r.deleted_rows,
                "removed_artifacts": r.removed_artifacts,
                "reconciled": r.reconciled,
                "batches": r.batches,
                "truncated": r.truncated,
            }
            for name, r in deletable.items()
        },
        "audit_retention_days": settings.AUDIT_RETENTION_DAYS,
        "report_retention_days": settings.REPORT_RETENTION_DAYS,
        "session_retention_days": max(settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 1),
        # Deleting certificate evidence is the only way a certificate the operator
        # could still triage disappears, so the window that did it is on the record
        # next to the tables it emptied.
        "certificate_retention_days": settings.TLS_CERTIFICATE_RETENTION_DAYS,
    }
    if any(r.truncated for r in deletable.values()):
        # Visible in the audit trail as well as in the logs, because a sweep
        # that never finishes is indistinguishable from one that keeps up.
        details["truncated"] = True

    # Where the hash chain's surviving history now starts. Published to the log
    # stream as well as kept in the database: it is the value a verifier holding
    # only the SIEM's copy of the audit trail needs in order to know which
    # positions were retired on purpose.
    audit_result = results.get("drp_audit_logs")
    if audit_result is not None and audit_result.retired_through_seq:
        details["chain"] = {
            "retired_through_seq": audit_result.retired_through_seq,
            "retired_tip_hash": audit_result.retired_tip_hash,
        }

    async with AsyncSessionLocal() as session:
        await AuditLogger.emit(
            session,
            action=ACTION_RETENTION_PURGED,
            ip_address="internal:celery-beat",
            user_id=None,
            details=details,
        )


@celery_app.task(name="purge_expired_data", ignore_result=False)
@async_task
async def purge_expired_data_task(self=None, _now: datetime | None = None) -> dict:
    """Celery entry point. ``_now`` is injectable so tests control the cutoff."""
    from app.core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        results = await run_retention_sweep(db, now=_now)

    summary = {
        name: {
            "deleted_rows": r.deleted_rows,
            "removed_artifacts": r.removed_artifacts,
            "reconciled": r.reconciled,
            "batches": r.batches,
            "truncated": r.truncated,
            "outside_store_paths": len(r.outside_store_paths),
        }
        for name, r in results.items()
    }
    log.info("retention_sweep_completed", **summary)

    # The audit write opens its own session: the sweep's transaction is already
    # committed, and a failure to record must not roll the deletions back.
    try:
        await _emit_sweep_audit(results)
    except Exception as exc:
        log.error("retention_audit_emit_failed", err=str(exc)[:200])
    return summary
