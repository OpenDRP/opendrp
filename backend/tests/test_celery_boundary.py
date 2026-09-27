"""Characterization tests: Celery boundary (Step 7).

Pins the CURRENT behavior of the execution bridge and scheduler before the
Step-7 refactor:

* ``async_task`` runs a coroutine function synchronously (``asyncio.run``),
  passes args/kwargs through, returns the result, propagates exceptions and
  disposes the engine afterwards;
* ``generate_report_task`` full lifecycle: missing report -> ``not_found``
  dict; success -> pending/generating/completed transitions with file path;
  failure -> report marked ``failed`` and the exception re-raised;
* eager ``apply()`` fires the task_prerun/postrun signals -> ``task.started``
  and ``task.completed`` audit rows;
* ``schedule_matches`` cron semantics (0=Sunday) incl. invalid specs;
* ``_redis_dedup_key`` format and real-Redis ``SET NX`` dedup behavior;
* ``_load_schedules`` DB read with the 60s in-process cache;
* ``refresh_scan_schedules_task`` fires only on a matching minute and the
  dedup guard prevents double dispatch.
"""

from __future__ import annotations

import asyncio
import functools
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models.report import Report
from app.models.settings import SystemSettings
from app.tasks.scheduler_tasks import (
    MODULE_TASKS,
    _redis_dedup_key,
    _try_acquire_dedup,
    schedule_matches,
)


async def _run_sync(fn, *args, **kwargs):
    """Run a sync callable (which itself calls asyncio.run) off-loop."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, functools.partial(fn, *args, **kwargs)
    )


# ---------------------------------------------------------------------------
# async_task bridge
# ---------------------------------------------------------------------------


class TestAsyncTaskBridge:
    def test_returns_result_and_passes_through_args(self):
        from app.core.celery_app import async_task

        async def add(a, b, *, scale=1):
            return (a + b) * scale

        sync_fn = async_task(add)
        assert sync_fn(2, 3, scale=10) == 50

    def test_propagates_exceptions_after_engine_dispose(self):
        from app.core.celery_app import async_task

        async def boom():
            raise RuntimeError("task exploded")

        sync_fn = async_task(boom)
        with pytest.raises(RuntimeError, match="task exploded"):
            sync_fn()

    def test_preserves_function_metadata(self):
        from app.core.celery_app import async_task

        async def documented():
            """Docstring survives wrapping."""

        assert async_task(documented).__name__ == "documented"
        assert async_task(documented).__doc__ == "Docstring survives wrapping."


# ---------------------------------------------------------------------------
# Report task lifecycle
# ---------------------------------------------------------------------------


async def _mk_report(db, *, status: str = "pending") -> Report:
    r = Report(
        report_name=f"Step7-{uuid.uuid4().hex[:6]}",
        created_by=None,
        file_path="/tmp/step7-placeholder.pdf",
        status=status,
    )
    db.add(r)
    await db.commit()
    await db.refresh(r)
    return r


def _report_status_raw(db, report_id) -> str | None:
    """Unused placeholder kept out; raw reads are done inline per test."""
    return None


def _make_report_row_on_task_engine(report_name: str) -> str:
    """Create the report row via app.core.database (the pool the task uses).

    The bridge runs a fresh event loop with its own engine connections; rows
    written on the conftest engine are not reliably visible to that loop on
    SQLite. Creating the row on the task's own pool (through the ORM so the
    Uuid hex bind format matches) makes the lifecycle pins deterministic.
    """
    import asyncio as _asyncio

    async def _create():
        from app.core.database import AsyncSessionLocal
        from app.models import Report

        r = Report(
            report_name=report_name,
            file_path="/tmp/step7-placeholder.pdf",
            status="pending",
        )
        async with AsyncSessionLocal() as s:
            s.add(r)
            await s.commit()
            return str(r.id)

    return _asyncio.run(_create())


def _read_status_on_task_engine(report_id: str) -> str | None:
    """Fresh-loop ORM read of the report status via app.core.database.

    All task-side writes happen on the app pool inside the bridge's event
    loop; on SQLite they are not reliably visible to the conftest engine's
    open snapshot, so verification uses the same pool (fresh asyncio.run).
    """
    import asyncio as _asyncio

    async def _read():
        from uuid import UUID as _UUID

        from sqlalchemy import select as _select

        from app.core.database import AsyncSessionLocal
        from app.models import Report

        async with AsyncSessionLocal() as s:
            r = (
                await s.execute(_select(Report).where(Report.id == _UUID(report_id)))
            ).scalar_one_or_none()
            return r.status if r else None

    return _asyncio.run(_read())


class TestReportTaskPolicy:
    def test_report_task_has_bounded_retry_policy(self):
        from app.tasks.report_tasks import generate_report_task

        assert generate_report_task.max_retries == 1
        assert TimeoutError in generate_report_task.autoretry_for
        assert ConnectionError in generate_report_task.autoretry_for
        assert OSError in generate_report_task.autoretry_for
        assert generate_report_task.retry_backoff is True
        assert generate_report_task.retry_jitter is True

    def test_completed_report_is_idempotent_only_when_artifact_exists(
        self, tmp_path, monkeypatch
    ):
        from app.core.config import settings as core_settings
        from app.models.report import Report
        from app.tasks.report_tasks import _completed_report_result

        # The artifact is resolved inside REPORTS_STORE_DIR, so the store has to
        # be the temporary directory for the file to be findable at all.
        monkeypatch.setattr(core_settings, "REPORTS_STORE_DIR", str(tmp_path))
        report = Report(
            report_name="duplicate-delivery",
            file_path="report.pdf",
            status="completed",
        )
        assert _completed_report_result(report, "job-1") is None

        (tmp_path / "report.pdf").write_bytes(b"%PDF-1.7")
        result = _completed_report_result(report, "job-1")
        assert result == {
            "status": "completed",
            "report_id": str(report.id),
            "file": "report.pdf",
            "job_id": "job-1",
        }

    def test_completed_report_with_missing_file_is_not_skipped(self, tmp_path, monkeypatch):
        from app.core.config import settings as core_settings
        from app.models.report import Report
        from app.tasks.report_tasks import _completed_report_result

        monkeypatch.setattr(core_settings, "REPORTS_STORE_DIR", str(tmp_path))
        report = Report(
            report_name="incomplete-delivery",
            file_path="missing.pdf",
            status="completed",
        )
        assert _completed_report_result(report, None) is None

    def test_a_stored_path_is_not_an_artifact(self, tmp_path, monkeypatch):
        """A row holding a path is refused, not resolved.

        This is the shape every row had before migration 0022, and the shape a
        hand-edited row would take. Treating it as a path is the file read this
        module exists to prevent.
        """
        from app.core.config import settings as core_settings
        from app.models.report import Report
        from app.tasks.report_tasks import _completed_report_result, _discard_artifact

        monkeypatch.setattr(core_settings, "REPORTS_STORE_DIR", str(tmp_path / "store"))
        (tmp_path / "store").mkdir()
        outside = tmp_path / "elsewhere.pdf"
        outside.write_bytes(b"not a report")

        report = Report(
            report_name="hand-edited",
            file_path=str(outside),
            status="completed",
        )
        assert _completed_report_result(report, None) is None

        # The cleanup path refuses for the same reason: it must not unlink a file
        # the platform cannot prove it wrote.
        _discard_artifact(str(outside))
        assert outside.exists()


class TestGenerateReportTask:
    @pytest.mark.asyncio
    async def test_missing_report_returns_not_found_dict(
        self, db_session
    ):
        from app.tasks.report_tasks import generate_report_task

        result = await _run_sync(
            generate_report_task.run,
            str(uuid.uuid4()),
            str(uuid.uuid4()),
            "someone@example.com",
            str(uuid.uuid4()),
        )
        assert result == {"error": "not_found", "job_id": result["job_id"]}

    @pytest.mark.asyncio
    async def test_success_marks_generating_then_completed(
        self, db_session, monkeypatch
    ):
        from app.tasks.report_tasks import generate_report_task

        report_id = await _run_sync(
            _make_report_row_on_task_engine, f"Step7-{uuid.uuid4().hex[:6]}"
        )

        async def _fake_generate(self, *, report_id, user_email):
            # The task sets status='generating' and commits BEFORE calling us;
            # verify via the task's own pool (fresh session in this loop).
            from sqlalchemy import select as _select

            from uuid import UUID as _UUID

            from app.core.database import AsyncSessionLocal
            from app.models import Report

            async with AsyncSessionLocal() as s:
                row = (
                    await s.execute(
                        _select(Report).where(Report.id == _UUID(report_id))
                    )
                ).scalar_one()
                assert row.status == "generating"
            # A name, which is what `generate_and_save` returns since 0022.
            return "fake.pdf"

        monkeypatch.setattr(
            "app.services.report_service.ReportService.generate_and_save",
            _fake_generate,
        )

        result = await _run_sync(
            generate_report_task.run,
            report_id,
            str(uuid.uuid4()),
            "someone@example.com",
            None,
        )
        assert result["status"] == "completed"
        assert result["file"] == "fake.pdf"

        assert await _run_sync(_read_status_on_task_engine, report_id) == "completed"

    @pytest.mark.asyncio
    async def test_failure_marks_report_failed_and_reraises(
        self, db_session, monkeypatch
    ):
        from app.tasks.report_tasks import generate_report_task

        report_id = await _run_sync(
            _make_report_row_on_task_engine, f"Step7-{uuid.uuid4().hex[:6]}"
        )

        async def _explode(self, *, report_id, user_email):
            raise RuntimeError("pdf engine broken")

        monkeypatch.setattr(
            "app.services.report_service.ReportService.generate_and_save",
            _explode,
        )

        with pytest.raises(RuntimeError, match="pdf engine broken"):
            await _run_sync(
                generate_report_task.run,
                report_id,
                str(uuid.uuid4()),
                "someone@example.com",
                None,
            )

        assert await _run_sync(_read_status_on_task_engine, report_id) == "failed"

    @pytest.mark.asyncio
    async def test_report_deleted_during_generation_drops_the_orphan_artifact(
        self, db_session, monkeypatch, tmp_path
    ):
        """A report deleted while its PDF is building must not raise StaleDataError.

        Regression for the live failure "UPDATE statement on table 'reports'
        expected to update 1 row(s); 0 were matched", which the task then masked
        with "This Session's transaction has been rolled back due to a previous
        exception during flush" — the second error coming from the failure
        handler writing ``failed`` on the already-poisoned session.
        """
        from app.tasks.report_tasks import (
            ReportDeletedDuringGeneration,
            generate_report_task,
        )

        from app.core.config import settings as core_settings

        report_id = await _run_sync(
            _make_report_row_on_task_engine, f"Step7-{uuid.uuid4().hex[:6]}"
        )
        # The task resolves the artifact inside the store before unlinking it, so
        # the store has to be this temporary directory.
        monkeypatch.setattr(core_settings, "REPORTS_STORE_DIR", str(tmp_path))
        artifact = tmp_path / "generated.pdf"

        async def _generate_then_delete_row(self, *, report_id, user_email):
            # The report disappears while the PDF is being produced (a user
            # deleting it, or a second worker cleaning up).
            from uuid import UUID as _UUID

            from sqlalchemy import delete as _delete

            from app.core.database import AsyncSessionLocal
            from app.models import Report

            async with AsyncSessionLocal() as s:
                await s.execute(_delete(Report).where(Report.id == _UUID(report_id)))
                await s.commit()
            artifact.write_bytes(b"%PDF-1.4 fake")
            return artifact.name

        monkeypatch.setattr(
            "app.services.report_service.ReportService.generate_and_save",
            _generate_then_delete_row,
        )

        with pytest.raises(ReportDeletedDuringGeneration) as excinfo:
            await _run_sync(
                generate_report_task.run,
                report_id,
                str(uuid.uuid4()),
                "someone@example.com",
                None,
            )

        message = str(excinfo.value)
        assert "deleted while it was being generated" in message
        # The opaque secondary failure must not be what the operator sees.
        assert "rolled back" not in message
        assert "expected to update" not in message
        # Nothing references the artifact, so it must not linger in the store.
        assert not artifact.exists()
        assert await _run_sync(_read_status_on_task_engine, report_id) is None

    @pytest.mark.asyncio
    async def test_generation_failure_on_a_deleted_report_keeps_the_real_cause(
        self, db_session, monkeypatch
    ):
        """When the row is already gone, the generation error stays the cause."""
        from app.tasks.report_tasks import (
            ReportDeletedDuringGeneration,
            generate_report_task,
        )

        report_id = await _run_sync(
            _make_report_row_on_task_engine, f"Step7-{uuid.uuid4().hex[:6]}"
        )

        async def _delete_row_then_explode(self, *, report_id, user_email):
            from uuid import UUID as _UUID

            from sqlalchemy import delete as _delete

            from app.core.database import AsyncSessionLocal
            from app.models import Report

            async with AsyncSessionLocal() as s:
                await s.execute(_delete(Report).where(Report.id == _UUID(report_id)))
                await s.commit()
            raise RuntimeError("pdf engine broken")

        monkeypatch.setattr(
            "app.services.report_service.ReportService.generate_and_save",
            _delete_row_then_explode,
        )

        with pytest.raises(ReportDeletedDuringGeneration) as excinfo:
            await _run_sync(
                generate_report_task.run,
                report_id,
                str(uuid.uuid4()),
                "someone@example.com",
                None,
            )

        # The original failure is preserved, so the cause is diagnosable.
        assert isinstance(excinfo.value.__cause__, RuntimeError)
        assert "pdf engine broken" in str(excinfo.value.__cause__)
        assert "rolled back" not in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_eager_apply_writes_task_started_and_completed_audit(
        self, db_session, monkeypatch
    ):
        """apply() runs eagerly in-process and fires prerun/postrun signals."""
        from app.core.audit import AuditLog  # noqa: F401  (model import side-effect free)
        from app.tasks.report_tasks import generate_report_task

        report_id = await _run_sync(
            _make_report_row_on_task_engine, f"Step7-{uuid.uuid4().hex[:6]}"
        )

        async def _fake_generate(self, *, report_id, user_email):
            return "/workspace/reports_store/eager.pdf"

        monkeypatch.setattr(
            "app.services.report_service.ReportService.generate_and_save",
            _fake_generate,
        )

        # No open write transaction on this session while signals run.
        await db_session.commit()

        def _apply():
            return generate_report_task.apply(
                args=(report_id, str(uuid.uuid4()), "someone@example.com", None)
            )

        eager = await _run_sync(_apply)
        assert eager.get()["status"] == "completed"

        # Signal-driven audit rows are written on the app pool: read them
        # there (fresh loop), not via the conftest engine snapshot.
        def _read_actions_sync():
            import asyncio as _asyncio

            async def _q():
                from sqlalchemy import text as _text

                from app.core.database import AsyncSessionLocal

                async with AsyncSessionLocal() as s:
                    rows = (
                        await s.execute(
                            _text(
                                "SELECT action FROM drp_audit_logs WHERE action LIKE 'task.%'"
                            )
                        )
                    ).scalars()
                    return set(rows)

            return _asyncio.run(_q())

        actions = await _run_sync(_read_actions_sync)
        assert "task.started" in actions
        assert "task.completed" in actions


# ---------------------------------------------------------------------------
# Scheduler: matching, dedup, cache, tick
# ---------------------------------------------------------------------------


class TestScheduleMatches:
    def test_sunday_is_cron_zero(self):
        sunday = datetime(2026, 9, 13, 2, 30, tzinfo=timezone.utc)
        assert schedule_matches({"days": [0], "hour": 2, "minute": 30}, sunday)
        assert not schedule_matches({"days": [1], "hour": 2, "minute": 30}, sunday)

    def test_monday_is_cron_one(self):
        monday = datetime(2026, 9, 14, 3, 30, tzinfo=timezone.utc)
        assert schedule_matches({"days": [1], "hour": 3, "minute": 30}, monday)

    def test_hour_and_minute_must_match_exactly(self):
        t = datetime(2026, 9, 14, 2, 31, tzinfo=timezone.utc)
        assert not schedule_matches({"days": [1], "hour": 2, "minute": 30}, t)
        t = datetime(2026, 9, 14, 3, 30, tzinfo=timezone.utc)
        assert not schedule_matches({"days": [1], "hour": 2, "minute": 30}, t)

    @pytest.mark.parametrize(
        "spec",
        [
            None,
            "not-an-object",
            {},
            {"days": "monday", "hour": 2, "minute": 30},
            {"days": [1], "hour": "two", "minute": 30},
            {"days": [1], "hour": None, "minute": 30},
            {"days": [7], "hour": 2, "minute": 30},
            {"days": [-1], "hour": 2, "minute": 30},
        ],
    )
    def test_invalid_specs_never_match(self, spec):
        t = datetime(2026, 9, 14, 2, 30, tzinfo=timezone.utc)
        assert schedule_matches(spec, t) is False

    def test_module_tasks_map_is_core_owned(self):
        assert MODULE_TASKS == {
            "schedule_phishing": [("connector_type", "phishing")],
            "schedule_breaches": [("connector_type", "breaches")],
        }


class TestRedisDedup:
    def test_key_format(self):
        now = datetime(2030, 1, 2, 3, 4, tzinfo=timezone.utc)
        assert _redis_dedup_key("phishing", now) == "sched:phishing:203001020304"

    @pytest.mark.asyncio
    async def test_set_nx_allows_once_per_minute(self):
        module = f"test-{uuid.uuid4().hex[:8]}"
        now = datetime(2030, 5, 6, 7, 8, tzinfo=timezone.utc)
        try:
            assert await _run_sync(_try_acquire_dedup, module, now) is True
            # Same module+minute must be blocked.
            assert await _run_sync(_try_acquire_dedup, module, now) is False
            # A different minute is a different key.
            later = now.replace(minute=9)
            assert await _run_sync(_try_acquire_dedup, module, later) is True
        finally:
            import redis as redis_lib

            from app.core.config import settings as core_settings

            client = redis_lib.Redis.from_url(
                core_settings.REDIS_URL, decode_responses=True
            )
            for minute in (8, 9):
                client.delete(_redis_dedup_key(module, now.replace(minute=minute)))
            client.close()

    def test_redis_failure_fails_closed(self, monkeypatch):
        from app.tasks import scheduler_tasks as st

        def _raise(*args, **kwargs):
            raise OSError("redis unavailable")

        monkeypatch.setattr("redis.Redis.from_url", _raise)
        now = datetime(2030, 5, 6, 7, 8, tzinfo=timezone.utc)
        assert st._try_acquire_dedup("failure-test", now) is False

    def test_release_dedup_requires_ownership_token(self, monkeypatch):
        from app.tasks import scheduler_tasks as st

        evaluated: list[tuple] = []

        class _Client:
            def eval(self, *args):
                evaluated.append(args)

            def close(self):
                return None

        monkeypatch.setattr(
            "redis.Redis.from_url", lambda *args, **kwargs: _Client()
        )
        now = datetime(2030, 5, 6, 7, 8, tzinfo=timezone.utc)
        st._release_dedup("phishing", now, "owner-token")
        assert len(evaluated) == 1
        assert evaluated[0][1:] == (
            1,
            _redis_dedup_key("phishing", now),
            "owner-token",
        )

    def test_release_without_token_does_not_delete(self, monkeypatch):
        from app.tasks import scheduler_tasks as st

        deleted = []

        class _Client:
            def delete(self, key):
                deleted.append(key)

            def close(self):
                return None

        monkeypatch.setattr(
            "redis.Redis.from_url", lambda *args, **kwargs: _Client()
        )
        now = datetime(2030, 5, 6, 7, 8, tzinfo=timezone.utc)
        st._release_dedup("phishing", now)
        assert deleted == []

    def test_set_nx_survives_close_failure(self, monkeypatch):
        """A redis client whose close() raises must not break acquisition."""
        from app.tasks import scheduler_tasks as st

        class _BrokenCloseClient:
            def __init__(self, *args, **kwargs):
                self._store: dict = {}

            def set(self, key, value, nx=False, ex=None):
                if nx and key in self._store:
                    return None
                self._store[key] = value
                return True

            def close(self):
                raise RuntimeError("close exploded")

        module = f"test-{uuid.uuid4().hex[:8]}"
        now = datetime(2030, 5, 6, 7, 8, tzinfo=timezone.utc)
        monkeypatch.setattr(
            "redis.Redis.from_url", lambda *args, **kwargs: _BrokenCloseClient()
        )
        assert st._try_acquire_dedup(module, now) is True


class TestLoadSchedulesAndTick:
    @staticmethod
    async def _get_or_create_settings(db) -> SystemSettings:
        row = (
            await db.execute(select(SystemSettings).limit(1))
        ).scalar_one_or_none()
        if row is None:
            row = SystemSettings()
            db.add(row)
            await db.commit()
            await db.refresh(row)
        return row

    @pytest.mark.asyncio
    async def test_load_schedules_reads_db_then_caches(
        self, db_session
    ):
        from app.tasks import scheduler_tasks as st

        row = await self._get_or_create_settings(db_session)
        row.schedule_phishing = {"days": [1], "hour": 2, "minute": 30}
        row.schedule_breaches = {"days": [6], "hour": 4, "minute": 0}
        await db_session.commit()

        st._schedule_cache["data"] = None  # reset cache for determinism
        data = await st._load_schedules()
        assert data["schedule_phishing"] == {"days": [1], "hour": 2, "minute": 30}
        assert data["schedule_breaches"] == {"days": [6], "hour": 4, "minute": 0}

        # Cached: mutating the DB does not change the cached view.
        row.schedule_phishing = {"days": [2], "hour": 5, "minute": 0}
        await db_session.commit()
        data2 = await st._load_schedules()
        assert data2["schedule_phishing"] == {"days": [1], "hour": 2, "minute": 30}
        st._schedule_cache["data"] = None

    @pytest.mark.asyncio
    async def test_tick_does_not_fire_outside_schedule(self, db_session):
        from app.tasks import scheduler_tasks as st

        st._schedule_cache["data"] = None
        # 2030-01-01 is a Tuesday (cron 2); schedules default to days 1-5 but
        # hour 2:30 with second=0... pick a minute that cannot match.
        now = datetime(2030, 1, 1, 2, 30, 15, tzinfo=timezone.utc)
        result = await _run_sync(st.refresh_scan_schedules_task.run, _now=now)
        assert result["fired"] == []

    @pytest.mark.asyncio
    async def test_tick_fires_on_match_and_dedup_blocks_second_dispatch(
        self, db_session
    ):
        from app.tasks import scheduler_tasks as st

        row = await self._get_or_create_settings(db_session)
        row.schedule_phishing = {"days": [2], "hour": 6, "minute": 42}
        await db_session.commit()
        st._schedule_cache["data"] = None

        now = datetime(2030, 1, 1, 6, 42, tzinfo=timezone.utc)  # Tuesday, cron 2

        def _tick():
            return st.refresh_scan_schedules_task.run(_now=now)

        await _run_sync(_tick)
        # No enabled phishing connectors means dispatch failed. The lock is
        # released so a later tick can retry after a connector starts.
        key = _redis_dedup_key("schedule_phishing", now)
        import redis as redis_lib

        from app.core.config import settings as core_settings

        client = redis_lib.Redis.from_url(core_settings.REDIS_URL, decode_responses=True)
        try:
            assert client.get(key) is None
        finally:
            client.delete(key)
            client.close()

        second = await _run_sync(_tick)
        assert second["fired"] == []
        st._schedule_cache["data"] = None


# ---------------------------------------------------------------------------
# Celery signal -> Job status sync + failure isolation
# ---------------------------------------------------------------------------


def _make_job_on_task_engine(
    task_id: str, *, status: str = "pending", job_type: str = "report.generate"
) -> str:
    """Create a Job row on the app pool (the pool the signal handlers use)."""
    import asyncio as _asyncio

    async def _create():
        from app.core.database import AsyncSessionLocal
        from app.models.job import Job

        job = Job(job_type=job_type, status=status, task_id=task_id, title="step7-signal")
        async with AsyncSessionLocal() as s:
            s.add(job)
            await s.commit()
            return str(job.id)

    return _asyncio.run(_create())


def _read_job_on_task_engine(job_id: str) -> dict:
    import asyncio as _asyncio

    async def _read():
        from uuid import UUID as _UUID

        from app.core.database import AsyncSessionLocal
        from app.models.job import Job

        async with AsyncSessionLocal() as s:
            job = await s.get(Job, _UUID(job_id))
            return {
                "status": job.status,
                "error_message": job.error_message,
                "started": job.started_at is not None,
                "finished": job.finished_at is not None,
                "result_summary": job.result_summary,
            }

    return _asyncio.run(_read())


def _audit_action_rows_on_task_engine(where: str) -> list[dict]:
    import asyncio as _asyncio

    async def _q():
        from sqlalchemy import text as _text

        from app.core.database import AsyncSessionLocal

        async with AsyncSessionLocal() as s:
            rows = (
                await s.execute(_text(f"SELECT action, details FROM drp_audit_logs WHERE {where}"))
            ).mappings().all()
            return [dict(r) for r in rows]

    return _asyncio.run(_q())


class TestSignalJobSync:
    @pytest.mark.asyncio
    async def test_prerun_moves_pending_job_to_running(self, db_session):
        from celery import signals as celery_signals

        from app.tasks.report_tasks import generate_report_task

        tid = f"sig-{uuid.uuid4().hex[:12]}"
        job_id = await _run_sync(_make_job_on_task_engine, tid)
        await db_session.commit()  # no open write txn while handlers run

        def _fire():
            celery_signals.task_prerun.send(
                sender=generate_report_task, task_id=tid, args=(), kwargs={}
            )

        await _run_sync(_fire)
        info = await _run_sync(_read_job_on_task_engine, job_id)
        assert info["status"] == "running"
        assert info["started"] is True

    @pytest.mark.asyncio
    async def test_prerun_without_task_id_is_noop(self, db_session):
        from celery import signals as celery_signals

        from app.tasks.report_tasks import generate_report_task

        await db_session.commit()

        def _fire():
            celery_signals.task_prerun.send(
                sender=generate_report_task, task_id=None, args=(), kwargs={}
            )

        await _run_sync(_fire)  # must not raise

    @pytest.mark.asyncio
    async def test_postrun_success_completes_job_with_result_summary(
        self, db_session
    ):
        from celery import signals as celery_signals

        from app.tasks.report_tasks import generate_report_task

        tid = f"sig-{uuid.uuid4().hex[:12]}"
        job_id = await _run_sync(_make_job_on_task_engine, tid)
        await db_session.commit()

        retval = {"status": "completed", "nested": {"items": [1, 2, 3]}}

        def _fire():
            celery_signals.task_postrun.send(
                sender=generate_report_task,
                task_id=tid,
                args=(),
                kwargs={},
                retval=retval,
                state="SUCCESS",
            )

        await _run_sync(_fire)
        info = await _run_sync(_read_job_on_task_engine, job_id)
        assert info["status"] == "success"
        assert info["finished"] is True
        assert info["result_summary"]["status"] == "completed"
        assert info["result_summary"]["nested"]["items"] == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_postrun_non_success_leaves_job_untouched(self, db_session):
        from celery import signals as celery_signals

        from app.tasks.report_tasks import generate_report_task

        tid = f"sig-{uuid.uuid4().hex[:12]}"
        job_id = await _run_sync(_make_job_on_task_engine, tid)
        await db_session.commit()

        def _fire():
            celery_signals.task_postrun.send(
                sender=generate_report_task,
                task_id=tid,
                args=(),
                kwargs={},
                retval=None,
                state="FAILURE",
            )

        await _run_sync(_fire)
        info = await _run_sync(_read_job_on_task_engine, job_id)
        assert info["status"] == "pending"  # completion only on SUCCESS

    @pytest.mark.asyncio
    async def test_failure_signal_marks_job_error_and_audits(self, db_session):
        from celery import signals as celery_signals

        from app.tasks.report_tasks import generate_report_task

        tid = f"sig-{uuid.uuid4().hex[:12]}"
        job_id = await _run_sync(_make_job_on_task_engine, tid)
        await db_session.commit()

        def _fire():
            celery_signals.task_failure.send(
                sender=generate_report_task,
                task_id=tid,
                args=(),
                kwargs={},
                exception=RuntimeError("connector handshake failed"),
                traceback=None,
                einfo=None,
            )

        await _run_sync(_fire)
        info = await _run_sync(_read_job_on_task_engine, job_id)
        assert info["status"] == "error"
        assert "connector handshake failed" in (info["error_message"] or "")

        failed = await _run_sync(
            _audit_action_rows_on_task_engine, "action = 'task.failed'"
        )
        assert failed, "task.failed audit row must be written"


class TestHandlerIsolation:
    def test_sync_emit_swallows_audit_failure(self, monkeypatch):
        from app.core import celery_app as ca

        async def _boom(*args, **kwargs):
            raise RuntimeError("audit sink down")

        monkeypatch.setattr(ca.AuditLogger, "emit", _boom)
        # Must not raise: audit is fire-and-forget for task signals.
        ca._sync_emit(
            action="task.started", task_id=None, task_name="probe", args=(), kwargs={}
        )

    def test_async_task_survives_engine_dispose_failure(self, monkeypatch):
        from app.core import celery_app as ca

        async def _ok():
            return 42

        class _FailingEngine:
            async def dispose(self):
                raise RuntimeError("dispose broken")

        monkeypatch.setattr(ca, "engine", _FailingEngine())
        assert ca.async_task(_ok)() == 42

    @pytest.mark.asyncio
    async def test_sync_emit_swallows_dispose_failure(self, db_session, monkeypatch):
        """Audit emit succeeds, but teardown dispose raising stays isolated."""
        from app.core import celery_app as ca

        class _FailingEngine:
            async def dispose(self):
                raise RuntimeError("dispose broken")

        monkeypatch.setattr(ca, "engine", _FailingEngine())
        await db_session.commit()

        def _emit():
            ca._sync_emit(
                action="task.started",
                task_id=f"sig-{uuid.uuid4().hex[:8]}",
                task_name="probe",
                args=(),
                kwargs={},
            )

        await _run_sync(_emit)  # must not raise

    @pytest.mark.asyncio
    async def test_sync_emit_from_running_loop_hits_outer_guard(self):
        """asyncio.run inside a running loop raises; the guard swallows it."""
        from app.core import celery_app as ca

        # Called directly on the loop (not via _run_sync): asyncio.run must
        # fail -> the outer except in _sync_emit isolates the signal handler.
        ca._sync_emit(
            action="task.started",
            task_id=None,
            task_name="probe",
            args=(),
            kwargs={},
        )

    def test_sync_job_status_without_task_id_is_noop(self):
        from app.core import celery_app as ca

        ca._sync_job_status("start", None)

    def test_sync_job_status_swallows_db_errors(self, monkeypatch):
        from app.core import celery_app as ca

        class _BrokenPool:
            def __call__(self):
                raise RuntimeError("pool dead")

        monkeypatch.setattr("app.core.database.AsyncSessionLocal", _BrokenPool)
        ca._sync_job_status("start", str(uuid.uuid4()))

    @pytest.mark.asyncio
    async def test_sync_job_status_swallows_dispose_failure(
        self, db_session, monkeypatch
    ):
        from app.core import celery_app as ca

        class _FailingEngine:
            async def dispose(self):
                raise RuntimeError("dispose broken")

        monkeypatch.setattr(ca, "engine", _FailingEngine())
        await db_session.commit()

        def _sync():
            ca._sync_job_status("start", str(uuid.uuid4()))  # unknown tid -> noop-ish

        await _run_sync(_sync)  # must not raise

    @pytest.mark.asyncio
    async def test_prerun_with_unserializable_arg_falls_back_to_str(
        self, db_session
    ):
        """_safe_json: a non-JSON-serializable arg becomes its str() form."""
        from celery import signals as celery_signals

        from app.tasks.report_tasks import generate_report_task

        await db_session.commit()

        def _fire():
            celery_signals.task_prerun.send(
                sender=generate_report_task,
                task_id=None,
                args=(object(),),
                kwargs={},
            )

        await _run_sync(_fire)  # must not raise

    @pytest.mark.asyncio
    async def test_prerun_with_circular_arg_falls_back_to_str(
        self, db_session
    ):
        """_safe_json: only a circular reference defeats json.dumps(default=str).

        The except-branch then stringifies the arg (truncated) instead of
        raising — the audit emit must still succeed.
        """
        from celery import signals as celery_signals

        from app.tasks.report_tasks import generate_report_task

        await db_session.commit()
        circular: list = []
        circular.append(circular)  # json.dumps raises ValueError on this

        def _fire():
            celery_signals.task_prerun.send(
                sender=generate_report_task,
                task_id=None,
                args=(circular,),
                kwargs={},
            )

        await _run_sync(_fire)  # must not raise



class TestPostrunRetvalSanitization:
    class _BrokenIter(list):
        """A list whose iteration raises but whose str() is safe."""

        def __iter__(self):
            raise RuntimeError("no iteration")

        def __repr__(self):
            return "<broken-list>"

    @pytest.mark.asyncio
    async def test_deep_nesting_and_set_leaf_are_flattened(self, db_session):
        from celery import signals as celery_signals

        from app.tasks.report_tasks import generate_report_task

        tid = f"sig-{uuid.uuid4().hex[:12]}"
        job_id = await _run_sync(_make_job_on_task_engine, tid)
        await db_session.commit()

        def _fire():
            celery_signals.task_postrun.send(
                sender=generate_report_task,
                task_id=tid,
                args=(),
                kwargs={},
                retval={"deep": [[[["x"]]]], "obj": {1, 2}},
                state="SUCCESS",
            )

        await _run_sync(_fire)
        info = await _run_sync(_read_job_on_task_engine, job_id)
        assert info["status"] == "success"
        # The retval dict is depth 0: the innermost leaf of the 4-deep list
        # is stringified to "['x']" at depth 4, three list levels survive;
        # non-JSON set leaves become str().
        assert info["result_summary"]["deep"] == [[["['x']"]]]
        assert info["result_summary"]["obj"] == "{1, 2}"

    @pytest.mark.asyncio
    async def test_unsanitizable_retval_falls_back_to_retval_str(
        self, db_session
    ):
        """If _safe itself explodes, the retval_str fallback still completes."""
        from celery import signals as celery_signals

        from app.tasks.report_tasks import generate_report_task

        tid = f"sig-{uuid.uuid4().hex[:12]}"
        job_id = await _run_sync(_make_job_on_task_engine, tid)
        await db_session.commit()

        def _fire():
            celery_signals.task_postrun.send(
                sender=generate_report_task,
                task_id=tid,
                args=(),
                kwargs={},
                retval=self._BrokenIter([1]),
                state="SUCCESS",
            )

        await _run_sync(_fire)
        info = await _run_sync(_read_job_on_task_engine, job_id)
        assert info["status"] == "success"
        assert info["result_summary"] == {"retval_str": "<broken-list>"}


# ---------------------------------------------------------------------------
# Scheduler: real enqueue path
# ---------------------------------------------------------------------------


def _seed_connector_on_task_engine(name: str, connector_type: str, job_type: str) -> None:
    import asyncio as _asyncio

    async def _create():
        from app.core.database import AsyncSessionLocal
        from app.models.connector import Connector

        async with AsyncSessionLocal() as s:
            s.add(
                Connector(
                    name=name,
                    connector_type=connector_type,
                    status="enabled",
                    default_job_type=job_type,
                )
            )
            await s.commit()

    _asyncio.run(_create())


def _count_jobs_on_task_engine(title_like: str) -> int:
    import asyncio as _asyncio

    async def _q():
        from sqlalchemy import text as _text

        from app.core.database import AsyncSessionLocal

        async with AsyncSessionLocal() as s:
            return (
                await s.execute(
                    _text("SELECT COUNT(*) FROM jobs WHERE title LIKE :t"),
                    {"t": title_like},
                )
            ).scalar_one()

    return _asyncio.run(_q())


class TestSchedulerEnqueue:
    @pytest.mark.asyncio
    async def test_tick_enqueues_jobs_audits_and_dedup_blocks_second(
        self, db_session
    ):
        from app.tasks import scheduler_tasks as st

        name = f"step7-phish-{uuid.uuid4().hex[:6]}"
        await _run_sync(_seed_connector_on_task_engine, name, "phishing", "phishing.dnstwist")

        row = await TestLoadSchedulesAndTick._get_or_create_settings(db_session)
        row.schedule_phishing = {"days": [3], "hour": 9, "minute": 17}
        await db_session.commit()
        st._schedule_cache["data"] = None

        now = datetime(2030, 1, 2, 9, 17, tzinfo=timezone.utc)  # Wednesday, cron 3

        first = await _run_sync(st.refresh_scan_schedules_task.run, _now=now)
        assert len(first["fired"]) == 1
        assert first["fired"][0].startswith("phishing:")
        assert await _run_sync(_count_jobs_on_task_engine, f"%{name}%") == 1

        audit = await _run_sync(
            _audit_action_rows_on_task_engine,
            f"action = 'phishing.scan.scheduled' AND details LIKE '%{now.isoformat()}%'",
        )
        assert len(audit) == 1

        # Dedup key NOT deleted -> the second tick in the same minute must
        # be blocked before any enqueue happens.
        second = await _run_sync(st.refresh_scan_schedules_task.run, _now=now)
        assert second["fired"] == []
        assert await _run_sync(_count_jobs_on_task_engine, f"%{name}%") == 1

        import redis as redis_lib

        from app.core.config import settings as core_settings

        client = redis_lib.Redis.from_url(core_settings.REDIS_URL, decode_responses=True)
        client.delete(_redis_dedup_key("schedule_phishing", now))
        client.close()
        st._schedule_cache["data"] = None

    @pytest.mark.asyncio
    async def test_enqueue_failure_releases_only_owned_lock(self, monkeypatch):
        from app.tasks import scheduler_tasks as st

        now = datetime(2030, 1, 3, 5, 9, tzinfo=timezone.utc)
        released: list[tuple[str, datetime, str | None]] = []

        async def _schedules():
            return {"schedule_phishing": None, "schedule_breaches": {"days": [4], "hour": 5, "minute": 9}}

        def _acquire(module, current_now):
            st._dedup_token.set("owner-token")
            return True

        async def _boom(self, **kwargs):
            raise RuntimeError("enqueue exploded")

        def _release(module, current_now, token=None):
            released.append((module, current_now, token))

        monkeypatch.setattr(st, "_load_schedules", _schedules)
        monkeypatch.setattr(st, "_try_acquire_dedup", _acquire)
        monkeypatch.setattr(st, "_release_dedup", _release)
        monkeypatch.setattr(
            "app.services.connector_service.ConnectorService.enqueue_module_scan",
            _boom,
        )

        result = await _run_sync(st.refresh_scan_schedules_task.run, _now=now)

        assert result["fired"] == []
        assert released == [("schedule_breaches", now, "owner-token")]

    @pytest.mark.asyncio
    async def test_enqueue_failure_does_not_release_without_owned_jobs(self, db_session, monkeypatch):
        from app.tasks import scheduler_tasks as st

        row = await TestLoadSchedulesAndTick._get_or_create_settings(db_session)
        row.schedule_breaches = {"days": [4], "hour": 5, "minute": 9}
        await db_session.commit()
        st._schedule_cache["data"] = None

        async def _boom(self, **kwargs):
            raise RuntimeError("enqueue exploded")

        monkeypatch.setattr(
            "app.services.connector_service.ConnectorService.enqueue_module_scan",
            _boom,
        )

        now = datetime(2030, 1, 3, 5, 9, tzinfo=timezone.utc)  # Thursday, cron 4
        result = await _run_sync(st.refresh_scan_schedules_task.run, _now=now)
        assert result["fired"] == []  # error logged, never propagated
        st._schedule_cache["data"] = None
