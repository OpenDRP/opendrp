import asyncio
import math
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import delete, func, orm, select, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    extract_ip,
    get_db,
    require_admin,
    require_viewer_plus,
)
from app.core.config import settings
from app.core.artifact_path import (
    REASON_NOT_A_NAME,
    REASON_OUTSIDE_STORE,
    classify_artifact,
    describe_rejection,
    resolve_artifact,
)
from app.core.audit import AuditLogger
from app.core.exceptions import NotFoundException
from app.core.logging_config import get_logger
from app.core.manual_rate_limit import SCOPE_REPORTS, enforce_manual_rate_limit
from app.core.request_context import request_id_header
from app.models import Report, ReportArtifactCleanup
from app.schemas.common import MAX_PAGE_SIZE, PaginatedResponse
from app.schemas.report import ReportCreate, ReportListResponse, ReportResponse


router = APIRouter(prefix="/reports", tags=["Reports"])

log = get_logger("opendrp.reports")

#: Reasons a stored artifact is refused *because the row is wrong* rather than
#: because the file is gone. The two are answered with the same 404 — the caller
#: learns nothing either way, and should not — but they are different events for
#: the operator: one is a missing PDF, the other is a row pointing somewhere the
#: platform never writes.
_INTEGRITY_REASONS = frozenset({REASON_NOT_A_NAME, REASON_OUTSIDE_STORE})


@router.post("/generate", status_code=202, response_model=dict)
async def generate_report(
    request: Request,
    data_in: ReportCreate,
    db: AsyncSession = Depends(get_db),
    u=Depends(require_viewer_plus),
):
    from app.models import ReportQueueControl
    from app.models.job import JobType
    from app.services.job_service import JobService
    from app.tasks.report_tasks import generate_report_task

    # Every role may generate a report, so the throttle is what keeps a single
    # account from flooding the report queue.
    await enforce_manual_rate_limit(
        db=db,
        user=u,
        scope=SCOPE_REPORTS,
        action="report.generate",
        ip_address=extract_ip(request),
    )

    # The singleton is inserted by the additive migration. A no-op conflict
    # update obtains PostgreSQL's row lock without taking SQLite's database-wide
    # write lock (SQLite serializes the following transaction itself).
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    def queue_lock_statement():
        if db.get_bind().dialect.name == "sqlite":
            return sqlite_insert(ReportQueueControl)
        return pg_insert(ReportQueueControl)
    await db.execute(
        queue_lock_statement()
        .values(id=1, touched_at=datetime.now(timezone.utc))
        .on_conflict_do_update(
            index_elements=[ReportQueueControl.id],
            set_={"touched_at": datetime.now(timezone.utc)},
        )
    )
    pending_count = int((await db.execute(
        select(func.count(Report.id)).where(Report.status.in_(("pending", "generating")))
    )).scalar_one())
    if pending_count >= settings.REPORT_QUEUE_MAX_PENDING:
        await db.rollback()
        raise HTTPException(status_code=429, detail="Report queue is full; try again later")

    name = data_in.report_name or f"OpenDRP Report {datetime.now(timezone.utc).strftime('%Y-%m-%d %H%M UTC')}"
    r = Report(report_name=name, created_by=u.id, file_path="", status="pending")
    db.add(r)
    await db.flush()
    job_service = JobService(db)
    job = await job_service.create_job(
        job_type=JobType.report_generate,
        created_by=u.id,
        title=f"Generate report: {name}",
        params={"report_id": str(r.id), "report_name": name},
    )
    await db.commit()
    await db.refresh(r)
    job_id = job.id
    schedule_ok = True
    schedule_error = None
    try:
        celery_res = generate_report_task.apply_async(
            args=[str(r.id), str(u.id), u.email, str(job_id)],
            queue="reports",
            # Carries this request's id into the worker, so the task's audit rows
            # and log lines join up with the HTTP request that caused them.
            headers=request_id_header(),
        )
        task_id = celery_res.id
        job.task_id = task_id
        await db.commit()
    except Exception as e:
        # Do not execute report generation inside the API process. A local
        # asyncio task would be lost on restart and would violate the
        # stateless API contract when several replicas are behind a load
        # balancer. Leave an explicit failed job for the operator to retry.
        schedule_ok = False
        schedule_error = str(e)[:100]
        r.status = "failed"
        await job_service.fail_job(job_id, error_message=schedule_error or "celery_unavailable")
        await db.commit()

    await AuditLogger.emit(
        db,
        action="report.generate",
        ip_address=extract_ip(request),
        user_id=u.id,
        details={
            "report_id": str(r.id),
            "report_name": name,
            "schedule_ok": schedule_ok,
            "schedule_error": schedule_error,
            "job_id": str(job_id),
        },
    )
    await db.commit()
    if not schedule_ok:
        raise HTTPException(
            status_code=503,
            detail="Report queue is temporarily unavailable; the report job was marked failed",
        )
    return {"status": "scheduled", "queue_state": "queued", "report_id": str(r.id), "job_id": str(job_id)}


@router.get("", response_model=ReportListResponse)
async def list_reports(
    request: Request,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    skip = (page - 1) * size
    visible_reports = Report.status != "deleted"
    page_rows = (
        select(Report.id.label("id"), Report.created_at.label("created_at"))
        .where(visible_reports)
        .order_by(Report.created_at.desc(), Report.id.desc())
        .offset(skip)
        .limit(size)
        .cte("report_page")
    )
    report_count = (
        select(func.count(Report.id).label("total"))
        .where(visible_reports)
        .cte("report_count")
    )
    # Both page rows and total are evaluated by one statement/snapshot. The
    # count CTE is the preserved left side so an out-of-range page still returns
    # its real total with an empty item list.
    result_rows = (
        await db.execute(
            select(Report, report_count.c.total)
            .select_from(
                report_count.outerjoin(page_rows, true()).outerjoin(
                    Report, Report.id == page_rows.c.id
                )
            )
            .options(orm.joinedload(Report.created_by_user))
            .order_by(
                page_rows.c.created_at.desc().nulls_last(),
                page_rows.c.id.desc().nulls_last(),
            )
        )
    ).unique().all()
    total = int(result_rows[0][1]) if result_rows else 0
    items = [row[0] for row in result_rows if row[0] is not None]
    items_dto = []
    for r in items:
        dto = ReportResponse.model_validate(r, from_attributes=True)
        dto.created_by_email = r.created_by_user.email if r.created_by_user else None
        items_dto.append(dto)
    # realpath/is_file may touch a slow or network-mounted volume. Keep those
    # bounded checks off the async event loop; the list page is capped at 200.
    availability = await asyncio.gather(
        *(
            asyncio.to_thread(resolve_artifact, report.file_path)
            for report in items
        )
    )
    for dto, artifact in zip(items_dto, availability):
        dto.file_available = artifact is not None
    pages = math.ceil(total / size) if size > 0 else 0
    await AuditLogger.emit_background(
        db,
        action="report.list",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"page": page, "size": size, "results": int(total)},
    )
    return PaginatedResponse(items=items_dto, total=total, page=page, size=size, pages=pages)


@router.get("/{report_id}/download")
async def download_report(
    request: Request,
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    from fastapi.responses import FileResponse
    from app.models import Report

    r = (await db.execute(select(Report).where(Report.id == report_id, Report.status != "deleted"))).scalar_one_or_none()
    if not r or r.status != "completed" or not r.file_path:
        raise NotFoundException("Report file not found or not ready")
    resolved, reason = classify_artifact(r.file_path)
    if resolved is None:
        # The response is the same 404 either way — a caller has no business
        # learning the layout of the host, and "the row is wrong" is not their
        # problem to fix. The audit record distinguishes them, because for the
        # operator they are different events: an artifact that is gone is an
        # operational incident (a backup that missed the volume, a manual
        # cleanup), while a value that is not an artifact name is a row pointing
        # somewhere this platform never writes.
        if reason in _INTEGRITY_REASONS:
            await AuditLogger.emit(
                db,
                action="report.artifact.rejected",
                ip_address=extract_ip(request),
                user_id=user.id,
                details={
                    "report_id": str(report_id),
                    "report_name": r.report_name,
                    "operation": "download",
                    **describe_rejection(r.file_path, reason),
                },
            )
        else:
            await AuditLogger.emit(
                db,
                action="report.download.missing",
                ip_address=extract_ip(request),
                user_id=user.id,
                details={
                    "report_id": str(report_id),
                    "report_name": r.report_name,
                    "status": r.status,
                    "reason": reason,
                },
            )
        raise NotFoundException(
            "Report file is no longer available on the server — regenerate the report"
        )
    fname = r.report_name.replace("/", "_").replace("\\", "_") or f"opendrp-report-{report_id}"
    await AuditLogger.emit(
        db,
        action="report.download",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "report_id": str(report_id),
            "report_name": r.report_name,
            "status": r.status,
            "artifact_name": resolved.name,
            "file_name": f"{fname}.pdf",
            "delivery_state": "response_started",
        },
    )
    return FileResponse(resolved, media_type="application/pdf", filename=f"{fname}.pdf")


@router.delete("/{report_id}", status_code=204)
async def delete_report(
    request: Request,
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    from app.models import Report

    r = (await db.execute(select(Report).where(Report.id == report_id, Report.status != "deleted").with_for_update())).scalar_one_or_none()
    if not r:
        raise NotFoundException("Report not found")

    original_status = r.status
    stored = r.file_path
    resolved, reason = classify_artifact(stored)
    details = {
        "report_id": str(report_id),
        "report_name": r.report_name,
        "status": r.status,
        "artifact_removed": False,
    }
    if stored and resolved is None:
        # The row is still deleted — this is an administrator acting on a report
        # record, and refusing would leave a broken report in the list forever —
        # but the file is left exactly where it is, with the reason recorded. A
        # path the platform cannot prove it wrote is not a path it deletes.
        details.update(describe_rejection(stored, reason))

    try:
        if stored and resolved is not None:
            if await db.get(ReportArtifactCleanup, stored) is None:
                db.add(ReportArtifactCleanup(artifact_name=stored, report_id=report_id))
        elif stored and reason not in {"missing", "no_name"}:
            details["cleanup_refused"] = reason
        if original_status in {"pending", "generating"}:
            details["cancelled_generation"] = True
        r.status = "deleted"
        r.file_path = ""
        await AuditLogger.emit(
            db,
            action="report.delete",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={
                **details,
                "artifact_cleanup_pending": bool(stored and resolved is not None),
            },
            require_persistence=True,
            commit=False,
        )
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    if stored and resolved is not None:
        # A report being generated derives its final artifact name from report_id.
        # Retain its tombstone until that worker has stopped so cleanup cannot win
        # against a late atomic publication. Other artifacts can be unlinked now.
        intent = await db.get(ReportArtifactCleanup, stored)
        if original_status not in {"pending", "generating"}:
            try:
                await asyncio.to_thread(os.remove, resolved)
                await db.execute(
                    delete(ReportArtifactCleanup).where(ReportArtifactCleanup.artifact_name == stored)
                )
                await db.commit()
            except FileNotFoundError:
                await db.execute(
                    delete(ReportArtifactCleanup).where(ReportArtifactCleanup.artifact_name == stored)
                )
                await db.commit()
            except OSError as exc:
                from datetime import timedelta
                from sqlalchemy import update as sql_update

                await db.execute(
                    sql_update(ReportArtifactCleanup)
                    .where(ReportArtifactCleanup.artifact_name == stored)
                    .values(
                        attempts=ReportArtifactCleanup.attempts + 1,
                        last_error=str(exc)[:500],
                        available_at=datetime.now(timezone.utc) + timedelta(minutes=2),
                    )
                )
                await db.commit()
                log.warning("report_delete_artifact_kept", report_id=str(report_id), err=str(exc)[:200])
        elif intent is not None:
            from datetime import timedelta

            intent.available_at = datetime.now(timezone.utc) + timedelta(
                seconds=settings.REPORT_GENERATION_TIMEOUT_SECONDS + 60
            )
            await db.commit()
    return None
