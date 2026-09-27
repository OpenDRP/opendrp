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
from sqlalchemy import delete, select

from app.core.celery_app import async_task, celery_app
from app.core.config import settings

log = structlog.get_logger()

#: Audit action recorded when the sweep actually deletes something. A run that
#: deletes nothing writes no row: an audit trail that records daily no-ops
#: trains its readers to ignore it.
ACTION_RETENTION_PURGED = "audit.retention.purged"
_TEMP_ARTIFACT_RE = re.compile(r"^\.[0-9a-f]{32}\.pdf\.tmp$")


@dataclass
class PurgeResult:
    """Outcome of one table's sweep."""

    table: str
    deleted_rows: int = 0
    batches: int = 0
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
) -> PurgeResult:
    """Delete rows older than ``cutoff`` in bounded batches.

    Each batch is its own transaction: the alternative — one statement for the
    whole history — locks every row it touches for the duration, inflates the
    WAL, and on PostgreSQL delays vacuum precisely when the table most needs it.
    """
    result = PurgeResult(table=model.__tablename__)
    while result.batches < max_batches:
        subquery = (
            select(model.id)
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
                    select(seq_column, hash_column).where(model.id.in_(subquery))
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

        outcome = await db.execute(delete(model).where(model.id.in_(subquery)))
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


async def purge_expired_reports(
    db, *, cutoff: datetime, batch_size: int, max_batches: int, now: datetime | None = None
) -> PurgeResult:
    """Delete expired report rows, then their PDFs.

    Rows first, artifacts second, and the artifact is only removed once the row
    that referenced it is gone. The reverse order could delete a PDF and then
    fail to delete its row, leaving a report that can never be downloaded.
    """
    from app.models import Report

    result = PurgeResult(table=Report.__tablename__)
    paths: list[str] = []
    drained = False
    while result.batches < max_batches:
        subquery = (
            select(Report.id)
            .where(Report.created_at < cutoff)
            .order_by(Report.created_at)
            .limit(batch_size)
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
        paths.extend(str(row[1]) for row in rows if row[1])
        await db.execute(delete(Report).where(Report.id.in_(ids)))
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

    from app.core.artifact_path import (
        REASON_MISSING,
        REASON_NO_NAME,
        classify_artifact,
    )

    for stored in paths:
        resolved, reason = classify_artifact(stored)
        if resolved is None:
            # Two refusals that mean different things. An artifact that is
            # already gone is not news — the row was expired, the sweep deleted
            # it, and the file had been removed earlier (a failed generation, a
            # restore that did not carry the volume). A value that is not an
            # artifact name at all *is* news: it is a row pointing somewhere
            # this platform never writes, and it is reported so that someone can
            # look at it instead of it being silently corrected or deleted.
            if reason not in {REASON_MISSING, REASON_NO_NAME}:
                result.outside_store_paths.append(stored)
            continue
        try:
            os.remove(resolved)
            result.removed_artifacts += 1
        except OSError as exc:
            # A PDF that cannot be unlinked is a disk-space problem, not a
            # reason to fail the sweep: the row is already gone, and the next
            # run will not see it again.
            log.warning(
                "retention_artifact_not_removed", path=str(resolved), err=str(exc)[:200]
            )
    return result


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
        from app.models.audit import AuditLog

        from app.core.audit_chain import retire

        cutoff = moment - timedelta(days=settings.AUDIT_RETENTION_DAYS)

        async def _record_retirement(session, result: PurgeResult) -> None:
            await retire(
                session,
                through_seq=result.retired_through_seq,
                tip_hash=result.retired_tip_hash,
            )

        results["drp_audit_logs"] = await purge_table(
            db,
            model=AuditLog,
            timestamp_column=AuditLog.timestamp,
            cutoff=cutoff,
            batch_size=settings.RETENTION_BATCH_SIZE,
            max_batches=settings.RETENTION_MAX_BATCHES_PER_RUN,
            seq_column=AuditLog.seq,
            hash_column=AuditLog.entry_hash,
            on_batch=_record_retirement,
        )

    if settings.REPORT_RETENTION_DAYS <= 0:
        results["reports"] = PurgeResult(table="reports")
    else:
        cutoff = moment - timedelta(days=settings.REPORT_RETENTION_DAYS)
        results["reports"] = await purge_expired_reports(
            db,
            cutoff=cutoff,
            batch_size=settings.RETENTION_BATCH_SIZE,
            max_batches=settings.RETENTION_MAX_BATCHES_PER_RUN,
            now=moment,
        )

    results["drp_refresh_families"] = await purge_expired_sessions(db, now=moment)

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
                "batches": r.batches,
                "truncated": r.truncated,
            }
            for name, r in deletable.items()
        },
        "audit_retention_days": settings.AUDIT_RETENTION_DAYS,
        "report_retention_days": settings.REPORT_RETENTION_DAYS,
        "session_retention_days": max(settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS, 1),
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
