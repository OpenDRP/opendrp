import asyncio
from functools import wraps
import json
from typing import Any, Callable

from celery import Celery, signals
from celery.schedules import crontab

from app.core.audit import AuditLogger
from app.core.config import settings
from app.core.database import AsyncSessionLocal, engine
from app.core.logging_config import configure_logging
from app.core.request_context import (
    REQUEST_ID_HEADER,
    current_request_id,
    sanitize_request_id,
    set_request_id,
)

# Workers and beat are their own processes, and neither imports app.main. Task
# signal handlers write audit rows *and* audit lines, so the handler has to be
# installed here too, not only in the API container.
configure_logging()


def async_task(func: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        async def _coro():
            try:
                return await func(*args, **kwargs)
            finally:
                try:
                    await engine.dispose()
                except Exception:
                    pass

        return asyncio.run(_coro())

    return wrapper


_backend_url = settings.REDIS_URL.replace("/0", "/1", 1) if "/0" in settings.REDIS_URL else settings.REDIS_URL

celery_app = Celery(
    "opendrp",
    broker=settings.REDIS_URL,
    backend=_backend_url,
    include=[
        # Scan execution lives in connector containers. The core only
        # schedules connector jobs and processes normalized findings.
        "app.tasks.alert_tasks",
        "app.tasks.report_tasks",
        "app.tasks.retention_tasks",
        "app.tasks.scheduler_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        # Single lightweight tick: reads user-configured schedules from
        # system_settings and enqueues module scans when they match.
        "deliver-pending-alerts-every-15-seconds": {
            "task": "deliver_pending_alerts",
            "schedule": 15.0,
            "options": {"queue": "alerts"},
        },
        "refresh-scan-schedules-every-minute": {
            "task": "refresh_scan_schedules",
            "schedule": 60.0,
            "options": {"queue": "default"},
        },
        # 04:15 UTC, after both default scan slots (02:30 and 03:30) and after
        # the reports they generate have been written: a report created minutes
        # earlier must not be a candidate for deletion in the same night.
        "purge-expired-data-daily": {
            "task": "purge_expired_data",
            "schedule": crontab(hour=4, minute=15),
            "options": {"queue": "default"},
        },
        # 04:45 UTC, after the sweep: the verification has to run *after* the
        # retirement bookkeeping it depends on, or every night would report the
        # previous night's legitimate deletion as a break. Incremental, so the
        # cost is the night's new entries rather than the whole history.
        "verify-audit-chain-daily": {
            "task": "verify_audit_chain",
            "schedule": crontab(hour=4, minute=45),
            "options": {"queue": "default"},
        },
    },
    task_routes={
        # Only core-owned tasks are routed here. External data collection is not
        # a Celery task at all: connector containers claim module jobs through
        # the HTTP work-poll protocol.
        "deliver_pending_alerts": {"queue": "alerts"},
        "generate_report": {"queue": "reports"},
        "refresh_scan_schedules": {"queue": "default"},
        "purge_expired_data": {"queue": "default"},
        "verify_audit_chain": {"queue": "default"},
    },
)


async def _audit_task_emit(
    *, action: str, task_id: str | None, task_name: str, args: tuple, kwargs: dict, **extra
) -> None:
    try:
        def _safe_json(v: Any) -> Any:
            try:
                json.dumps(v, default=str)
                return v
            except Exception:
                return str(v)[:200]
        details: dict = {
            "task": task_name,
            "task_id": task_id,
            "args": [_safe_json(a) for a in list(args)[:10]],
            "kwargs": {str(k): _safe_json(v) for k, v in list(kwargs.items())[:10]},
            **{str(k): _safe_json(v) for k, v in list(extra.items())[:20]},
        }
        async with AsyncSessionLocal() as session:
            await AuditLogger.emit(
                session,
                action=action,
                ip_address="internal:celery",
                user_id=None,
                details=details,
            )
    except Exception:
        pass


def _sync_emit(action: str, task_id: str | None, task_name: str, args: tuple, kwargs: dict, **extra) -> None:
    try:
        async def _runner():
            try:
                await _audit_task_emit(
                    action=action,
                    task_id=task_id,
                    task_name=task_name,
                    args=args,
                    kwargs=kwargs,
                    **extra,
                )
            finally:
                try:
                    await engine.dispose()
                except Exception:
                    pass

        asyncio.run(_runner())
    except Exception:
        pass


def _sync_job_status(fn_name: str, task_id: str | None, **kwargs) -> None:
    if not task_id:
        return
    try:
        from datetime import datetime, timezone
        from sqlalchemy import select
        from app.core.database import AsyncSessionLocal
        from app.models.job import Job, JobStatus
        from app.services.job_service import JobService

        async def _runner():
            try:
                async with AsyncSessionLocal() as session:
                    svc = JobService(session)
                    if fn_name == "start":
                        stmt = select(Job).where(Job.task_id == task_id).limit(1)
                        job = (await session.execute(stmt)).scalar_one_or_none()
                        if job is not None and job.status == JobStatus.pending:
                            job.status = JobStatus.running
                            job.started_at = datetime.now(timezone.utc)
                            await session.commit()
                    elif fn_name == "complete":
                        result_summary = kwargs.get("result_summary")
                        updated = await svc.complete_by_task_id(task_id, result_summary=result_summary)
                        if updated is not None:
                            await session.commit()
                    elif fn_name == "fail":
                        err = kwargs.get("error") or ""
                        updated = await svc.fail_by_task_id(task_id, error_message=err)
                        if updated is not None:
                            await session.commit()
            finally:
                try:
                    await engine.dispose()
                except Exception:
                    pass

        asyncio.run(_runner())
    except Exception:
        pass


def _request_id_detail(request_id: str | None) -> dict:
    """``details`` fragment for a task audit event, empty when there is no id."""
    return {"request_id": request_id} if request_id else {}


def _task_request_id(sender) -> str | None:
    """The producing request's id, when it sent one.

    Read from the task headers, which is the channel that does not change any
    task signature. ``request_id_header()`` is the only producer and it sets
    ``REQUEST_ID_HEADER``, so that is the only spelling read: an id that arrived
    under another name is not this platform's id, and adopting it would join one
    request's log lines to another's task.
    """
    request = getattr(sender, "request", None)
    headers = getattr(request, "headers", None)
    if not headers:
        return None
    try:
        raw = headers.get(REQUEST_ID_HEADER)
    except AttributeError:
        return None
    return sanitize_request_id(raw)


@signals.task_prerun.connect
def _on_task_prerun(sender=None, task_id=None, args=None, kwargs=None, **_signal_kwargs):
    name = getattr(sender, "name", None) or str(sender)
    # Adopt the producer's id so the task's own log lines and audit rows join up
    # with the HTTP request that caused them.
    request_id = _task_request_id(sender)
    set_request_id(request_id)
    _sync_emit(
        action="task.started",
        task_id=task_id,
        task_name=name,
        args=tuple(args or ()),
        kwargs=dict(kwargs or {}),
        # Passed explicitly rather than relying on the context variable: the emit
        # runs in a fresh event loop, and the id must not depend on how a
        # contextvar happens to be copied into it. Omitted entirely when there is
        # none — a null in ``details`` would be a value someone has to filter out.
        **(_request_id_detail(request_id)),
    )
    _sync_job_status("start", task_id)


@signals.task_postrun.connect
def _on_task_postrun(sender=None, task_id=None, args=None, kwargs=None, retval=None, state=None, **_signal_kwargs):
    name = getattr(sender, "name", None) or str(sender)
    request_id = current_request_id()
    _sync_emit(
        action="task.completed",
        task_id=task_id,
        task_name=name,
        args=tuple(args or ()),
        kwargs=dict(kwargs or {}),
        state=state or "SUCCESS",
        **_request_id_detail(request_id),
    )
    # Cleared on the way out. The variable lives in the worker's context, so
    # without this the *next* task — which may carry no headers at all — would
    # inherit this one's identifier and be attributed to it.
    set_request_id(None)
    if (state or "SUCCESS") == "SUCCESS":
        result_summary = None
        try:
            import json

            def _safe(v, depth=0):
                if depth > 3:
                    return str(v)[:200]
                if v is None or isinstance(v, (bool, int, float, str)):
                    return v
                if isinstance(v, (list, tuple)):
                    return [_safe(x, depth + 1) for x in list(v)[:50]]
                if isinstance(v, dict):
                    return {str(k)[:100]: _safe(val, depth + 1) for k, val in list(v.items())[:50]}
                return str(v)[:200]

            json.dumps(_safe(retval), default=str)
            result_summary = _safe(retval)
        except Exception:
            result_summary = {"retval_str": str(retval)[:500]}
        _sync_job_status("complete", task_id, result_summary=result_summary)


@signals.task_failure.connect
def _on_task_failure(sender=None, task_id=None, args=None, kwargs=None, exception=None, traceback=None, einfo=None, **_signal_kwargs):
    name = getattr(sender, "name", None) or str(sender)
    err_msg = str(exception)[:2000] if exception is not None else "unknown celery task error"
    _sync_emit(
        action="task.failed",
        task_id=task_id,
        task_name=name,
        args=tuple(args or ()),
        kwargs=dict(kwargs or {}),
        error=err_msg,
        **_request_id_detail(current_request_id()),
    )
    set_request_id(None)
    _sync_job_status("fail", task_id, error=err_msg)
