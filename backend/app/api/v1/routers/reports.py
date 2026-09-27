import math
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, orm, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    extract_ip,
    get_db,
    require_admin,
    require_viewer_plus,
)
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
from app.models import Report
from app.schemas.common import PaginatedResponse
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
    return {"status": "scheduled", "report_id": str(r.id), "estimated_seconds": 15, "job_id": str(job_id)}


@router.get("", response_model=ReportListResponse)
async def list_reports(
    request: Request,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    skip = (page - 1) * size
    q = select(Report).options(orm.joinedload(Report.created_by_user)).order_by(Report.created_at.desc(), Report.id.desc())
    items = list((await db.execute(q.offset(skip).limit(size))).scalars().unique().all())
    total = (await db.execute(select(func.count(Report.id)))).scalar_one()
    items_dto = []
    for r in items:
        dto = ReportResponse.model_validate(r, from_attributes=True)
        dto.created_by_email = r.created_by_user.email if r.created_by_user else None
        dto.file_available = resolve_artifact(r.file_path) is not None
        items_dto.append(dto)
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

    r = (await db.execute(select(Report).where(Report.id == report_id))).scalar_one_or_none()
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

    r = (await db.execute(select(Report).where(Report.id == report_id))).scalar_one_or_none()
    if not r:
        raise NotFoundException("Report not found")

    stored = r.file_path
    resolved, reason = classify_artifact(stored)
    details = {
        "report_id": str(report_id),
        "report_name": r.report_name,
        "status": r.status,
        "artifact_removed": resolved is not None,
    }
    if stored and resolved is None:
        # The row is still deleted — this is an administrator acting on a report
        # record, and refusing would leave a broken report in the list forever —
        # but the file is left exactly where it is, with the reason recorded. A
        # path the platform cannot prove it wrote is not a path it deletes.
        details.update(describe_rejection(stored, reason))

    try:
        await db.delete(r)
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    if resolved is not None:
        try:
            os.remove(resolved)
        except OSError as exc:
            log.warning(
                "report_delete_artifact_kept",
                report_id=str(report_id),
                err=str(exc)[:200],
            )
    await AuditLogger.emit(
        db,
        action="report.delete",
        ip_address=extract_ip(request),
        user_id=user.id,
        details=details,
    )
    return None
