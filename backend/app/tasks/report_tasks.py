import os

import structlog
from sqlalchemy import update

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
    except OSError as exc:
        log.warning("report_orphan_artifact_kept", file=stored, err=str(exc)[:200])


async def _set_status(
    db,
    report_id,
    *,
    status: str,
    file_path: str | None = None,
    is_truncated: bool | None = None,
    truncation_metadata: dict | None = None,
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
    if file_path is not None:
        values["file_path"] = file_path
    if is_truncated is not None:
        values["is_truncated"] = is_truncated
        values["truncation_metadata"] = truncation_metadata
    result = await db.execute(update(Report).where(Report.id == report_id).values(**values))
    await db.commit()
    return (result.rowcount or 0) > 0


@celery_app.task(
    name="generate_report",
    bind=True,
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
        if not await _set_status(db, rid, status="generating"):
            # Deleted between the SELECT and the UPDATE.
            log.warning("report_generate_vanished", report_id=str(rid), job_id=job_id)
            return {"error": "not_found", "job_id": job_id}

        try:
            generated = await ReportService(db).generate_and_save(report_id=report_id, user_email=user_email)
            fp, truncation_metadata = generated if isinstance(generated, tuple) else (generated, None)
        except Exception as e:
            # The flush that failed may have poisoned the session; recover it
            # before touching the database again, otherwise the diagnosis is
            # lost behind a secondary "transaction has been rolled back" error.
            await db.rollback()
            log.error("report_failed", err=str(e), report_id=str(rid), job_id=job_id)
            if not await _set_status(db, rid, status="failed"):
                raise ReportDeletedDuringGeneration(rid) from e
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
        ):
            _discard_artifact(fp)
            log.warning("report_generate_vanished", report_id=str(rid), job_id=job_id)
            raise ReportDeletedDuringGeneration(rid)
        return {"status": "completed", "report_id": report_id, "file": fp, "job_id": job_id, "is_truncated": is_truncated, "truncation": truncation_metadata}
