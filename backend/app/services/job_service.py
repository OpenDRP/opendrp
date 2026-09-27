import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import ColumnElement, and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.job import Job, JobStatus, JobType


class JobService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_job(
        self,
        *,
        job_type: JobType | str,
        created_by: Optional[uuid.UUID],
        title: Optional[str] = None,
        task_id: Optional[str] = None,
        params: Optional[dict[str, Any]] = None,
        status: JobStatus = JobStatus.pending,
    ) -> Job:
        job = Job(
            job_type=job_type,
            status=status,
            created_by=created_by,
            title=title,
            task_id=task_id,
            params=params,
        )
        if status == JobStatus.running:
            job.started_at = datetime.now(timezone.utc)
        self.db.add(job)
        await self.db.flush()
        return job

    async def start_job(self, job_id: uuid.UUID, *, task_id: Optional[str] = None) -> Job:
        """Mark the job running.

        Transition semantics are *unconditional by design* (no state guards);
        this is pinned by ``tests/test_job_service_lifecycle.py``. Introducing
        guards is a separately-reviewed behavior change.
        """
        job = await self.db.get(Job, job_id)
        if job is None:
            raise ValueError(f"Job {job_id} not found")
        job.status = JobStatus.running
        job.started_at = datetime.now(timezone.utc)
        if task_id:
            job.task_id = task_id
        await self.db.flush()
        return job

    async def _finish_job(
        self,
        job: Job,
        *,
        status: JobStatus,
        error_message: Optional[str] = None,
        result_summary: Optional[dict[str, Any]] = None,
    ) -> Job:
        """Shared completion path (single source of truth).

        Transition semantics remain *unconditional by design* (no state
        guards); this is pinned by ``tests/test_job_service_lifecycle.py``.
        Introducing guards is a separately-reviewed behavior change.
        """
        job.status = status
        job.finished_at = datetime.now(timezone.utc)
        if error_message is not None:
            job.error_message = (error_message or "")[:8000]
        elif status in {JobStatus.success, JobStatus.partial, JobStatus.skipped}:
            # A retry may carry a previous lease-expiry diagnostic. Once the
            # connector reports a terminal non-error result, the summary is the
            # source of truth and the stale recovery message must not make a
            # successful/partial scan look like an exception in the UI.
            job.error_message = None
        if result_summary is not None:
            job.result_summary = result_summary
        if status in {JobStatus.success, JobStatus.partial, JobStatus.error, JobStatus.cancelled, JobStatus.skipped}:
            job.lease_expires_at = None
            job.lease_token = None
        await self.db.flush()
        return job

    async def complete_job(
        self,
        job_id: uuid.UUID,
        *,
        result_summary: Optional[dict[str, Any]] = None,
    ) -> Job:
        """Mark the job successful.

        Unconditional by design (pinned): re-completing an already-successful
        job re-runs this path and refreshes ``finished_at``.
        """
        job = await self.db.get(Job, job_id)
        if job is None:
            raise ValueError(f"Job {job_id} not found")
        return await self._finish_job(
            job, status=JobStatus.success, result_summary=result_summary
        )

    async def fail_job(
        self,
        job_id: uuid.UUID,
        *,
        error_message: str,
        result_summary: Optional[dict[str, Any]] = None,
    ) -> Job:
        job = await self.db.get(Job, job_id)
        if job is None:
            raise ValueError(f"Job {job_id} not found")
        return await self._finish_job(
            job,
            status=JobStatus.error,
            error_message=error_message,
            result_summary=result_summary,
        )

    async def complete_by_task_id(
        self,
        task_id: str,
        *,
        result_summary: Optional[dict[str, Any]] = None,
    ) -> Optional[Job]:
        if not task_id:
            return None
        stmt = select(Job).where(Job.task_id == task_id).limit(1)
        res = await self.db.execute(stmt)
        job = res.scalar_one_or_none()
        if job is None:
            return None
        return await self._finish_job(
            job, status=JobStatus.success, result_summary=result_summary
        )

    async def fail_by_task_id(
        self,
        task_id: str,
        *,
        error_message: str,
        result_summary: Optional[dict[str, Any]] = None,
    ) -> Optional[Job]:
        if not task_id:
            return None
        stmt = select(Job).where(Job.task_id == task_id).limit(1)
        res = await self.db.execute(stmt)
        job = res.scalar_one_or_none()
        if job is None:
            return None
        return await self._finish_job(
            job,
            status=JobStatus.error,
            error_message=error_message,
            result_summary=result_summary,
        )

    async def list_jobs(
        self,
        *,
        page: int = 1,
        size: int = 20,
        as_admin: bool = False,
        viewer_user_id: Optional[uuid.UUID] = None,
        job_type: Optional[str] = None,
        job_type_in: Optional[list[str]] = None,
        status: Optional[str] = None,
        created_by: Optional[uuid.UUID] = None,
        search: Optional[str] = None,
    ) -> tuple[list[Job], int]:
        conditions: list[ColumnElement[bool]] = []
        if not as_admin:
            # Non-admins see their own jobs plus the *system* jobs
            # (``created_by IS NULL``) that the scheduler and the connectors
            # run on behalf of the whole platform. Filtering those out left the
            # Jobs history empty for viewers even while scans were running, so
            # the platform looked idle while work was happening.
            conditions.append(
                or_(Job.created_by == viewer_user_id, Job.created_by.is_(None))
            )
        if job_type:
            conditions.append(Job.job_type == job_type)
        if job_type_in:
            conditions.append(Job.job_type.in_(job_type_in))
        if status:
            conditions.append(Job.status == status)
        if created_by:
            conditions.append(Job.created_by == created_by)
        if search:
            raw_search = search.strip()[:100]
            escaped = raw_search.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
            q = f"%{escaped}%"
            conditions.append(
                or_(
                    Job.title.ilike(q, escape="\\"),
                    Job.task_id.ilike(q, escape="\\"),
                    Job.error_message.ilike(q, escape="\\"),
                )
            )

        # and_() with no arguments yields a true() clause, preserving the old
        # unfiltered-listing behavior while keeping the predicate well-typed.
        where = and_(*conditions)

        count_stmt = select(func.count(Job.id)).where(where)
        total_res = await self.db.execute(count_stmt)
        total = int(total_res.scalar_one() or 0)

        offset = (page - 1) * size
        stmt = (
            select(Job)
            .options(selectinload(Job.created_by_user))
            .where(where)
            .order_by(Job.created_at.desc(), Job.id.desc())
            .offset(offset)
            .limit(size)
        )
        res = await self.db.execute(stmt)
        items = list(res.scalars().all())
        return items, total
