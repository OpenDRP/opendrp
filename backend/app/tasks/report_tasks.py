import asyncio
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
import structlog
from sqlalchemy import update

from app.core.config import settings

from app.core.celery_app import async_task, celery_app

log = structlog.get_logger()


class ReportDeletedDuringGeneration(RuntimeError):
    """The report row disappeared while its PDF was being produced.

    Reported as this instead of letting SQLAlchemy's ``StaleDataError`` escape:
    the underlying situation is ordinary (a report was deleted while it was
    generating), and the previous code surfaced it as
    "Session's transaction has been rolled back due to a previous exception
    during flush" — because the failure handler tried to write ``failed`` on the
    session the failed flush had already poisoned.
    """

    def __init__(self, report_id) -> None:
        super().__init__(
            f"report {report_id} was deleted while it was being generated; "
            "nothing was left to update"
        )


def _completed_report_result(report, job_id: str | None) -> dict | None:
    """Return a stable result for a redelivered task whose artifact exists."""
    from app.core.artifact_path import resolve_artifact

    stored = getattr(report, "file_path", None)
    if getattr(report, "status", None) != "completed" or not stored:
        return None
    if resolve_artifact(stored) is None:
        return None
    return {
        "status": "completed",
        "report_id": str(report.id),
        "file": stored,
        "job_id": job_id,
    }


def _discard_artifact(stored: str | None) -> None:
    """Remove a PDF that no report row references any more.

    The stored value goes through the same containment check as a download. A
    cleanup path is not a reason to unlink whatever a string in a column happens
    to point at: "the platform deletes only what it can prove it wrote" is the
    property that makes this call site safe to keep.
    """
    from app.core.artifact_path import resolve_artifact

    if not stored:
        return
    resolved = resolve_artifact(stored)
    if resolved is None:
        log.warning("report_orphan_artifact_kept", file=stored)
        return
    try:
        os.remove(resolved)
    except FileNotFoundError:
        return
    except OSError as exc:
        log.warning("report_orphan_artifact_kept", file=stored, err=str(exc)[:200])


async def _discard_artifact_with_intent(db, stored: str | None) -> None:
    """Delete an unreferenced PDF or persist a cleanup intent if unlink fails."""
    from app.core.artifact_path import artifact_filename, resolve_artifact
    from app.models import ReportArtifactCleanup

    if not stored:
        return
    try:
        report_id = uuid.UUID(str(stored).removesuffix(".pdf"))
        if stored != artifact_filename(report_id):
            return
    except (ValueError, TypeError, AttributeError):
        return

    # The corresponding report was deleted during generation. Ensure the
    # durable tombstone exists before unlink so a transient filesystem error
    # remains recoverable by retention.
    intent = await db.get(ReportArtifactCleanup, stored)
    if intent is None:
        intent = ReportArtifactCleanup(artifact_name=stored, report_id=report_id)
        db.add(intent)
    await db.commit()

    resolved = resolve_artifact(stored)
    if resolved is None:
        return
    try:
        await asyncio.to_thread(os.remove, resolved)
    except FileNotFoundError:
        pass
    except OSError as exc:
        intent = await db.get(ReportArtifactCleanup, stored)
        if intent is not None:
            intent.report_id = report_id
            intent.attempts += 1
            intent.last_error = str(exc)[:500]
            intent.available_at = datetime.now(timezone.utc) + timedelta(minutes=2)
        await db.commit()
        log.warning("report_orphan_artifact_kept", file=stored, err=str(exc)[:200])
    else:
        await db.execute(
            sa.delete(ReportArtifactCleanup).where(
                ReportArtifactCleanup.artifact_name == stored
            )
        )
        await db.commit()


async def _set_status(
    db,
    report_id,
    *,
    status: str,
    file_path: str | None = None,
    is_truncated: bool | None = None,
    truncation_metadata: dict | None = None,
    audit_event: dict | None = None,
    job_id: str | None = None,
    job_status: str | None = None,
    job_error_message: str | None = None,
) -> bool:
    """Move a report to a state, returning False when the row no longer exists.

    Written as an explicit ``UPDATE`` with a row-count check rather than an ORM
    mutation: the task loads the row, then spends seconds building the PDF, and
    the row can be deleted in that window. An ORM flush would raise
    ``StaleDataError`` ("UPDATE ... expected to update 1 row(s); 0 were
    matched"), which is a *race that callers must handle*, not an internal
    error. Reporting a missing row as ``False`` keeps that decision with the
    caller.
    """
    from app.models import Report

    values: dict = {"status": status}
    if status == "generating":
        values["generation_started_at"] = datetime.now(timezone.utc)
    if file_path is not None:
        values["file_path"] = file_path
    if is_truncated is not None:
        values["is_truncated"] = is_truncated
        values["truncation_metadata"] = truncation_metadata
    if status in {"completed", "failed"}:
        values["generation_started_at"] = None
    elif status == "pending":
        values["generation_started_at"] = None
    result = await db.execute(
        update(Report)
        .where(Report.id == report_id, Report.status != "deleted")
        .values(**values)
    )

    if (result.rowcount or 0) == 0:
        await db.rollback()
        return False
    if job_id and job_status:
        from uuid import UUID
        from app.models import Job

        values = {"status": job_status}
        if job_status in {"pending", "running"}:
            values.update(finished_at=None, error_message=None)
            if job_status == "running":
                values["started_at"] = datetime.now(timezone.utc)
        else:
            values.update(
                finished_at=datetime.now(timezone.utc),
                error_message=job_error_message,
            )
        await db.execute(
            update(Job).where(Job.id == UUID(job_id)).values(**values)
        )
    if audit_event is not None:
        await _enqueue_report_audit(db, **audit_event)
    await db.commit()
    return True


async def _enqueue_report_audit(
    db,
    *,
    event_key: str,
    action: str,
    report_id,
    job_id: str | None,
    details: dict,
) -> None:
    """Persist a unique, retryable audit intent with its lifecycle change."""
    from app.models import ReportAuditOutbox
    from sqlalchemy import select

    exists = await db.scalar(
        select(ReportAuditOutbox.id).where(ReportAuditOutbox.event_key == event_key)
    )
    if exists is None:
        db.add(
            ReportAuditOutbox(
                event_key=event_key,
                action=action,
                report_id=report_id,
                job_id=uuid.UUID(str(job_id)) if job_id else None,
                details=details,
            )
        )


async def deliver_report_audit_outbox(db, *, now=None, batch_size: int = 100) -> int:
    """Append durable report outcomes to the signed audit chain exactly once."""
    from datetime import timedelta

    from app.core.audit import AuditLogger
    from app.models import ReportAuditOutbox
    from sqlalchemy import select

    moment = now or datetime.now(timezone.utc)
    events = list(
        (
            await db.execute(
                select(ReportAuditOutbox)
                .where(ReportAuditOutbox.available_at <= moment)
                .order_by(ReportAuditOutbox.created_at, ReportAuditOutbox.id)
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    delivered = 0
    for event in events:
        event_id = event.id
        report_id = event.report_id
        event_key = event.event_key
        action = event.action
        details = dict(event.details)
        try:
            await AuditLogger.emit(
                db,
                action=action,
                ip_address="internal:celery",
                user_id=None,
                details=details,
                require_persistence=True,
                commit=False,
            )
            await db.delete(event)
            await db.commit()
            delivered += 1
        except Exception as exc:
            await db.rollback()
            try:
                retry = await db.get(ReportAuditOutbox, event_id)
                if retry is not None:
                    retry.attempts += 1
                    retry.last_error = type(exc).__name__[:200]
                    retry.available_at = moment + timedelta(
                        minutes=min(60, 2 ** min(retry.attempts, 6))
                    )
                    await db.commit()
            except Exception:
                await db.rollback()
            log.error(
                "report_outcome_audit_pending",
                report_id=str(report_id),
                event_key=event_key,
                error_type=type(exc).__name__,
            )
            break
    return delivered


@celery_app.task(
    name="generate_report",
    bind=True,
    acks_late=True,
    reject_on_worker_lost=True,
    soft_time_limit=settings.REPORT_GENERATION_TIMEOUT_SECONDS + 10,
    time_limit=settings.REPORT_GENERATION_TIMEOUT_SECONDS + 30,
    max_retries=1,
    autoretry_for=(TimeoutError, ConnectionError, OSError),
    retry_backoff=True,
    retry_jitter=True,
)
@async_task
async def generate_report_task(self, report_id: str, user_id: str, user_email: str, job_id: str | None = None):
    from uuid import UUID
    from app.core.database import AsyncSessionLocal
    from app.models import Report
    from app.services.report_service import ReportService

    async with AsyncSessionLocal() as db:
        from sqlalchemy import select

        r = (await db.execute(select(Report).where(Report.id == UUID(report_id)))).scalar_one_or_none()
        if not r:
            return {"error": "not_found", "job_id": job_id}
        existing_result = _completed_report_result(r, job_id)
        if existing_result is not None:
            return existing_result

        # Address the report by id from here on. Everything after the first
        # commit goes through ``_set_status``, so a concurrent DELETE is handled
        # as an outcome rather than as a stale ORM object in the session.
        rid = r.id
        if not await _set_status(
            db,
            rid,
            status="generating",
            job_id=job_id,
            job_status="running" if job_id else None,
        ):
            # Deleted between the SELECT and the UPDATE.
            log.warning("report_generate_vanished", report_id=str(rid), job_id=job_id)
            return {"error": "not_found", "job_id": job_id}

        generation_started = time.monotonic()
        try:
            generated = await ReportService(db).generate_and_save(report_id=report_id, user_email=user_email)
            fp, truncation_metadata = generated if isinstance(generated, tuple) else (generated, None)
        except Exception as e:
            # The flush that failed may have poisoned the session; recover it
            # before touching the database again, otherwise the diagnosis is
            # lost behind a secondary "transaction has been rolled back" error.
            await db.rollback()
            retryable = isinstance(e, (TimeoutError, ConnectionError, OSError))
            retries = int(getattr(getattr(self, "request", None), "retries", 0) or 0)
            max_retries = int(getattr(self, "max_retries", 0) or 0)
            will_retry = retryable and retries < max_retries
            log.error("report_retry_scheduled" if will_retry else "report_failed", err=str(e)[:500], report_id=str(rid), job_id=job_id, retryable=retryable, retries=retries)
            outcome_status = "pending" if will_retry else "failed"
            audit_action = "report.generate.retry" if will_retry else "report.generate.failed"
            audit_details = {
                "report_id": str(rid),
                "job_id": job_id,
                "status": outcome_status,
                "error_type": type(e).__name__,
                "retryable": retryable,
                "attempt": retries + 1,
                "duration_ms": max(0, int((time.monotonic() - generation_started) * 1000)),
            }
            if not await _set_status(
                db,
                rid,
                status=outcome_status,
                audit_event={
                    "event_key": f"{rid}:{audit_action}:{retries + 1}",
                    "action": audit_action,
                    "report_id": rid,
                    "job_id": job_id,
                    "details": audit_details,
                },
                job_id=job_id,
                job_status="pending" if will_retry else "error",
                job_error_message=None if will_retry else "report_generation_failed",
            ):
                raise ReportDeletedDuringGeneration(rid) from e
            await deliver_report_audit_outbox(db, batch_size=100)
            raise

        is_truncated = bool(
            truncation_metadata.get("truncated")
            if isinstance(truncation_metadata, dict)
            else False
        )
        # Keep completion and its explanation in one UPDATE. A list request must
        # never observe a completed report without the metadata that explains its
        # row limit.
        if not await _set_status(
            db,
            rid,
            status="completed",
            file_path=fp,
            is_truncated=is_truncated,
            truncation_metadata=truncation_metadata,
            job_id=job_id,
            job_status="success" if job_id else None,
            audit_event={
                "event_key": f"{rid}:report.generate.completed",
                "action": "report.generate.completed",
                "report_id": rid,
                "job_id": job_id,
                "details": {
                    "report_id": str(rid),
                    "job_id": job_id,
                    "status": "completed",
                    "is_truncated": is_truncated,
                    "duration_ms": max(0, int((time.monotonic() - generation_started) * 1000)),
                    "included_rows": sum(
                        section.get("included", 0)
                        for section in (truncation_metadata or {}).get("sections", {}).values()
                    ) if isinstance(truncation_metadata, dict) else 0,
                    "total_rows": sum(
                        section.get("total", 0)
                        for section in (truncation_metadata or {}).get("sections", {}).values()
                    ) if isinstance(truncation_metadata, dict) else 0,
                },
            },
        ):
            await _discard_artifact_with_intent(db, fp)
            log.warning("report_generate_vanished", report_id=str(rid), job_id=job_id)
            raise ReportDeletedDuringGeneration(rid)
        await deliver_report_audit_outbox(db, batch_size=100)
        return {"status": "completed", "report_id": report_id, "file": fp, "job_id": job_id, "is_truncated": is_truncated, "truncation": truncation_metadata}
