import math
import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_admin, require_viewer_plus
from app.core.audit import AuditLogger
from app.core.exceptions import NotFoundException
from app.models.job import Job
from app.models.user import User
from app.schemas.common import PaginatedResponse
from app.schemas.job import JobResponse
from app.services.job_service import JobService

router = APIRouter(prefix="/jobs", tags=["Jobs"])


def _to_response(job) -> JobResponse:
    email: str | None = None
    try:
        user = getattr(job, "created_by_user", None)
        if user is not None:
            email = getattr(user, "email", None)
    except Exception:
        email = None
    return JobResponse(
        id=job.id,
        job_type=job.job_type,
        status=job.status,
        task_id=job.task_id,
        title=job.title,
        error_message=job.error_message,
        params=job.params,
        result_summary=job.result_summary,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        lease_expires_at=job.lease_expires_at,
        last_heartbeat_at=job.last_heartbeat_at,
        attempt_count=job.attempt_count,
        claimed_by_connector=job.claimed_by_connector,
        # Never expose the lease token through the user-facing jobs API.
        created_by=job.created_by,
        created_by_email=email,
    )


@router.get("", response_model=PaginatedResponse[JobResponse])
async def list_jobs(
    request: Request,
    job_type: str | None = None,
    job_type_in: str | None = Query(None, description="Comma-separated list of job types to include"),
    status: str | None = None,
    created_by: uuid.UUID | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer_plus),
):
    user_id = current_user.id
    as_admin = current_user.role == "admin"
    jobs, total = await JobService(db).list_jobs(
        page=page,
        size=size,
        as_admin=as_admin,
        viewer_user_id=user_id,
        job_type=job_type,
        job_type_in=[t.strip() for t in job_type_in.split(",") if t.strip()] if job_type_in else None,
        status=status,
        created_by=created_by,
        search=search,
    )
    pages = max(1, math.ceil(total / size)) if total > 0 else 1
    await AuditLogger.emit(
        db,
        action="jobs.list",
        user_id=str(current_user.id),
        ip_address=extract_ip(request),
        details={
            "page": page,
            "size": size,
            "total": total,
            "as_admin": as_admin,
            "filters": {
                "job_type": job_type,
                "job_type_in": job_type_in,
                "status": status,
                "created_by": str(created_by) if created_by else None,
                "search": search,
            },
        },
    )
    await db.commit()
    return PaginatedResponse[JobResponse](
        items=[_to_response(j) for j in jobs],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    request: Request,
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer_plus),
):
    job = (await db.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
    if job is None:
        raise NotFoundException("Job not found")
    if current_user.role != "admin" and job.created_by not in {None, current_user.id}:
        raise NotFoundException("Job not found")
    await AuditLogger.emit_background(
        db, action="job.view", user_id=current_user.id,
        ip_address=extract_ip(request), details={"job_id": str(job_id)},
    )
    return _to_response(job)


@router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_job(
    request: Request,
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    job = (await db.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
    if job is None:
        raise NotFoundException("Job not found")

    details = {
        "job_id": str(job.id),
        "job_type": job.job_type,
        "status": job.status,
        "task_id": job.task_id,
    }
    await db.delete(job)
    await AuditLogger.emit(
        db,
        action="job.delete",
        user_id=str(current_user.id),
        ip_address=extract_ip(request),
        details=details,
    )
    await db.commit()
    return None
