"""Characterization tests: job lifecycle service and /api/v1/jobs endpoints.

Part of the safe-refactoring plan (Step 2). These tests pin the CURRENT
behavior of ``app/services/job_service.py`` (38% coverage before) and
``app/api/v1/routers/jobs.py`` (45% before).

Two non-obvious behaviors are pinned deliberately with TODO(refactor-step-2)
markers — they are candidates for later, separately-reviewed behavior changes:

1. The job "state machine" is a set of *unconditional* setters: ``complete_job``
   on an already-successful job re-succeeds it and refreshes ``finished_at``.
   There are no invalid-transition guards. Any future transition map must be
   proven against these pins first.
2. ``GET /api/v1/jobs`` is admin-sees-all; **analysts and viewers see only
   jobs they created themselves** (``as_admin`` is true for the admin role
   only). A job created by another analyst is invisible to non-admins.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.job import Job, JobStatus
from app.services.job_service import JobService


async def _mk_job(
    db,
    *,
    job_type: str = "phishing.dnstwist",
    status: JobStatus = JobStatus.pending,
    created_by: uuid.UUID | None = None,
    title: str | None = None,
    task_id: str | None = None,
    params: dict | None = None,
) -> Job:
    job = await JobService(db).create_job(
        job_type=job_type,
        created_by=created_by,
        title=title,
        task_id=task_id,
        params=params,
        status=status,
    )
    # JobService only flushes; commit so the router's own session (a separate
    # SQLite connection in the test stack) can see the row and is not blocked
    # by an open write transaction on this session (mirrors conftest helpers).
    await db.commit()
    return job


class TestJobServiceLifecycle:
    @pytest.mark.asyncio
    async def test_create_job_defaults_to_pending(self, db_session):
        job = await _mk_job(db_session, title="t", params={"a": 1})
        assert job.id is not None
        assert job.status == "pending"
        assert job.started_at is None
        assert job.finished_at is None
        assert job.params == {"a": 1}
        assert job.title == "t"

    @pytest.mark.asyncio
    async def test_create_job_running_sets_started_at(self, db_session):
        job = await _mk_job(db_session, status=JobStatus.running)
        assert job.status == "running"
        assert job.started_at is not None

    @pytest.mark.asyncio
    async def test_create_job_rejects_invalid_job_type(self, db_session):
        with pytest.raises(ValueError, match="job_type"):
            await _mk_job(db_session, job_type="not-a-type")

    @pytest.mark.asyncio
    async def test_create_job_rejects_invalid_status(self, db_session):
        with pytest.raises(ValueError, match="status"):
            await JobService(db_session).create_job(
                job_type="system",
                created_by=None,
                status="flying",  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_start_job_sets_running_and_task_id(self, db_session):
        job = await _mk_job(db_session)
        started = await JobService(db_session).start_job(job.id, task_id="celery-abc")
        assert started.status == "running"
        assert started.started_at is not None
        assert started.task_id == "celery-abc"

    @pytest.mark.asyncio
    async def test_start_missing_job_raises(self, db_session):
        with pytest.raises(ValueError, match="not found"):
            await JobService(db_session).start_job(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_complete_job_sets_success_and_summary(self, db_session):
        job = await _mk_job(db_session)
        done = await JobService(db_session).complete_job(
            job.id, result_summary={"accepted": 3}
        )
        assert done.status == "success"
        assert done.finished_at is not None
        assert done.result_summary == {"accepted": 3}

    @pytest.mark.asyncio
    async def test_complete_missing_job_raises(self, db_session):
        with pytest.raises(ValueError, match="not found"):
            await JobService(db_session).complete_job(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_fail_missing_job_raises(self, db_session):
        with pytest.raises(ValueError, match="not found"):
            await JobService(db_session).fail_job(uuid.uuid4(), error_message="e")

    @pytest.mark.asyncio
    async def test_fail_job_sets_error_and_truncates_to_8000(self, db_session):
        job = await _mk_job(db_session)
        failed = await JobService(db_session).fail_job(
            job.id, error_message="x" * 9000, result_summary={"rejected": 1}
        )
        assert failed.status == "error"
        assert failed.finished_at is not None
        assert failed.error_message is not None
        assert len(failed.error_message) == 8000
        assert failed.result_summary == {"rejected": 1}

    @pytest.mark.asyncio
    async def test_by_task_id_complete_and_fail(self, db_session):
        await _mk_job(db_session, task_id="task-ok")
        await _mk_job(db_session, task_id="task-bad")
        svc = JobService(db_session)

        done = await svc.complete_by_task_id("task-ok", result_summary={"n": 1})
        assert done is not None and done.status == "success"

        failed = await svc.fail_by_task_id(
            "task-bad", error_message="boom", result_summary={"rejected": 2}
        )
        assert failed is not None and failed.status == "error"
        assert failed.error_message == "boom"
        assert failed.result_summary == {"rejected": 2}

    @pytest.mark.asyncio
    async def test_by_task_id_empty_or_unknown_returns_none(self, db_session):
        svc = JobService(db_session)
        assert await svc.complete_by_task_id("") is None
        assert await svc.fail_by_task_id("", error_message="x") is None
        assert await svc.complete_by_task_id("no-such-task") is None
        assert await svc.fail_by_task_id("no-such-task", error_message="e") is None

    @pytest.mark.asyncio
    async def test_transitions_are_unconditional_current_behavior(
        self, db_session
    ):
        """TODO(refactor-step-2): pins the absence of transition guards.

        Completing an already-successful job re-runs the success path and
        refreshes ``finished_at``; failing a running job works from any state.
        A future explicit state machine must either preserve this or be a
        separately-reviewed behavior change.
        """
        svc = JobService(db_session)
        job = await _mk_job(db_session)
        await svc.complete_job(job.id, result_summary={"first": True})
        first_finished = (
            await db_session.get(Job, job.id)
        ).finished_at

        again = await svc.complete_job(job.id, result_summary={"second": True})
        assert again.status == "success"
        assert again.result_summary == {"second": True}
        assert again.finished_at >= first_finished

        from_error = await _mk_job(db_session, status=JobStatus.running)
        failed_from_running = await svc.fail_job(from_error.id, error_message="late")
        assert failed_from_running.status == "error"


class TestJobServiceListJobs:
    @pytest.mark.asyncio
    async def test_admin_sees_all_viewer_sees_own_only(self, db_session, test_admin, test_viewer):
        await _mk_job(db_session, created_by=test_admin.id, title="admin-job")
        await _mk_job(db_session, created_by=test_viewer.id, title="viewer-job")

        admin_jobs, admin_total = await JobService(db_session).list_jobs(
            as_admin=True, viewer_user_id=test_admin.id
        )
        assert admin_total == 2
        assert {j.title for j in admin_jobs} == {"admin-job", "viewer-job"}

        viewer_jobs, viewer_total = await JobService(db_session).list_jobs(
            as_admin=False, viewer_user_id=test_viewer.id
        )
        assert viewer_total == 1
        assert [j.title for j in viewer_jobs] == ["viewer-job"]

    @pytest.mark.asyncio
    async def test_filters_job_type_status_and_created_by(
        self, db_session, test_admin, test_viewer
    ):
        await _mk_job(
            db_session, job_type="phishing.dnstwist", created_by=test_admin.id
        )
        await _mk_job(
            db_session,
            job_type="breaches.hibp",
            created_by=test_viewer.id,
            status=JobStatus.error,
        )

        svc = JobService(db_session)
        jobs, total = await svc.list_jobs(
            as_admin=True, job_type="breaches.hibp", viewer_user_id=None
        )
        assert total == 1 and jobs[0].job_type == "breaches.hibp"

        jobs, total = await svc.list_jobs(
            as_admin=True, status="error", viewer_user_id=None
        )
        assert total == 1 and jobs[0].status == "error"

        jobs, total = await svc.list_jobs(
            as_admin=True, created_by=test_viewer.id, viewer_user_id=None
        )
        assert total == 1 and jobs[0].created_by == test_viewer.id

    @pytest.mark.asyncio
    async def test_filter_job_type_in(self, db_session):
        await _mk_job(db_session, job_type="phishing.dnstwist")
        await _mk_job(db_session, job_type="breaches.hibp")
        await _mk_job(db_session, job_type="report.generate")

        jobs, total = await JobService(db_session).list_jobs(
            as_admin=True, job_type_in=["phishing.dnstwist", "breaches.hibp"]
        )
        assert total == 2
        assert {j.job_type for j in jobs} == {"phishing.dnstwist", "breaches.hibp"}

    @pytest.mark.asyncio
    async def test_search_matches_title_task_id_and_error_message(self, db_session):
        svc = JobService(db_session)
        await _mk_job(db_session, title="NeedleTitleScan")
        await _mk_job(db_session, task_id="needle-task-42")
        broken = await _mk_job(db_session, title="plain")
        await svc.fail_job(broken.id, error_message="needle-error-detail")

        for needle in ("NeedleTitle", "needle-task-42", "needle-error"):
            jobs, total = await svc.list_jobs(as_admin=True, search=needle)
            assert total == 1, needle
            assert needle.lower() in (
                f"{jobs[0].title or ''} {jobs[0].task_id or ''} {jobs[0].error_message or ''}"
            ).lower()

    @pytest.mark.asyncio
    async def test_pagination_and_total(self, db_session):
        for i in range(3):
            await _mk_job(db_session, title=f"bulk-{i}")

        page1, total = await JobService(db_session).list_jobs(
            as_admin=True, page=1, size=2
        )
        page2, _ = await JobService(db_session).list_jobs(
            as_admin=True, page=2, size=2
        )
        assert total == 3
        assert len(page1) == 2 and len(page2) == 1
        assert {j.id for j in page1}.isdisjoint({j.id for j in page2})


class TestJobsRouter:
    @pytest.mark.asyncio
    async def test_list_jobs_requires_auth(self, client):
        r = await client.get("/api/v1/jobs")
        assert r.status_code in (401, 403), r.text

    @pytest.mark.asyncio
    async def test_list_jobs_analyst_sees_own_only(
        self, client, auth_headers_analyst, auth_headers_admin, db_session,
        test_analyst, test_admin,
    ):
        """TODO(refactor-step-2): pins analyst self-visibility scoping."""
        await _mk_job(db_session, created_by=test_admin.id, title="admins-job")
        await _mk_job(db_session, created_by=test_analyst.id, title="analysts-job")

        r = await client.get("/api/v1/jobs", headers=auth_headers_analyst)
        assert r.status_code == 200, r.text
        titles = {item["title"] for item in r.json()["items"]}
        assert "analysts-job" in titles
        assert "admins-job" not in titles

        r = await client.get("/api/v1/jobs", headers=auth_headers_admin)
        assert r.status_code == 200, r.text
        titles = {item["title"] for item in r.json()["items"]}
        assert {"admins-job", "analysts-job"} <= titles

    @pytest.mark.asyncio
    async def test_list_jobs_empty_pages_is_one(self, client, auth_headers_viewer):
        r = await client.get("/api/v1/jobs", headers=auth_headers_viewer)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["items"] == []
        assert body["pages"] == 1

    @pytest.mark.asyncio
    async def test_list_jobs_shows_system_jobs_to_every_role(
        self, client, auth_headers_viewer, db_session, test_admin
    ):
        """``created_by IS NULL`` jobs belong to the whole platform.

        The scheduler and the connectors create them without an owner, so the
        previous owner-only filter made Jobs history look empty for viewers
        even while scans were running.
        """
        await _mk_job(db_session, created_by=None, job_type="system", title="nightly")
        await _mk_job(db_session, created_by=test_admin.id, title="admins-job")

        r = await client.get("/api/v1/jobs", headers=auth_headers_viewer)
        assert r.status_code == 200, r.text
        body = r.json()
        titles = {item["title"] for item in body["items"]}
        assert "nightly" in titles
        assert "admins-job" not in titles

        system_item = next(i for i in body["items"] if i["title"] == "nightly")
        assert system_item["created_by"] is None
        assert system_item["created_by_email"] is None

    @pytest.mark.asyncio
    async def test_list_jobs_job_type_in_csv_and_status_filters(
        self, client, auth_headers_admin, db_session, test_admin
    ):
        await _mk_job(db_session, created_by=test_admin.id, job_type="phishing.dnstwist")
        await _mk_job(db_session, created_by=test_admin.id, job_type="breaches.hibp")
        await _mk_job(db_session, created_by=test_admin.id, job_type="report.generate")

        r = await client.get(
            "/api/v1/jobs",
            headers=auth_headers_admin,
            params={"job_type_in": "phishing.dnstwist,breaches.hibp"},
        )
        assert r.status_code == 200, r.text
        types = {item["job_type"] for item in r.json()["items"]}
        assert types == {"phishing.dnstwist", "breaches.hibp"}

        r = await client.get(
            "/api/v1/jobs", headers=auth_headers_admin, params={"job_type": "breaches.hibp"}
        )
        assert r.status_code == 200, r.text
        assert {item["job_type"] for item in r.json()["items"]} == {"breaches.hibp"}

    @pytest.mark.asyncio
    async def test_list_jobs_response_shape_and_audit(
        self, client, auth_headers_admin, db_session, test_admin
    ):
        job = await _mk_job(
            db_session, created_by=test_admin.id, title="shape-check", params={"k": "v"}
        )
        r = await client.get("/api/v1/jobs", headers=auth_headers_admin)
        assert r.status_code == 200, r.text
        item = next(i for i in r.json()["items"] if i["id"] == str(job.id))
        assert item["created_by_email"] == test_admin.email
        assert item["params"] == {"k": "v"}
        assert item["status"] == "pending"

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "jobs.list")
                )
            ).scalars()
        )
        assert rows, "jobs listing must be audited"
        assert rows[-1].details.get("total") >= 1

    @pytest.mark.asyncio
    async def test_delete_job_admin_removes_row_and_audits(
        self, client, auth_headers_admin, db_session, test_admin
    ):
        job = await _mk_job(db_session, created_by=test_admin.id, title="doomed")
        r = await client.delete(f"/api/v1/jobs/{job.id}", headers=auth_headers_admin)
        assert r.status_code == 204, r.text
        # Raw count: this session's identity map still holds the deleted
        # instance (the deletion committed on the router's session), mirroring
        # the raw-SQL verification pattern used for report rows.
        from sqlalchemy import text

        remaining = (
            await db_session.execute(
                text("SELECT COUNT(*) FROM jobs WHERE id = :i"), {"i": str(job.id)}
            )
        ).scalar_one()
        assert remaining == 0

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "job.delete")
                )
            ).scalars()
        )
        assert rows
        assert rows[-1].details.get("job_id") == str(job.id)
        assert rows[-1].details.get("job_type") == "phishing.dnstwist"

    @pytest.mark.asyncio
    async def test_delete_job_404_and_rbac(self, client, auth_headers_admin, auth_headers_analyst):
        r = await client.delete(f"/api/v1/jobs/{uuid.uuid4()}", headers=auth_headers_admin)
        assert r.status_code == 404, r.text

        r = await client.get("/api/v1/jobs", headers=auth_headers_analyst)
        assert r.status_code == 200
        items = r.json()["items"]
        assert items == []  # nothing created by analyst yet

        r = await client.delete(f"/api/v1/jobs/{uuid.uuid4()}", headers=auth_headers_analyst)
        assert r.status_code == 403, r.text
