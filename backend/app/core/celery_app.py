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


#: Tasks whose work can be executed a second time without a second effect, and
#: which are therefore acknowledged *after* they finish. A worker that is killed
#: mid-task (a deploy, an OOM kill, a lost broker connection) leaves the message
#: unacknowledged, so the broker hands it to the next worker that asks instead of
#: dropping it — which is the difference between work that is late and work that
#: never happened at all.
#:
#: The list is per task rather than a global ``task_acks_late``, because a repeat
#: is only safe where the task says so:
#:
#: * ``deliver_pending_alerts`` reclaims rows by lease and retries with bounded
#:   backoff (see ``alert_delivery_service``), so a second run either takes over an
#:   expired lease or finds nothing to do;
#: * ``refresh_scan_schedules`` dedups every occurrence twice — a Redis guard held
#:   for fifteen minutes and the durable ``schedule_occurrences`` key — so a
#:   redelivery re-checks the same minutes and dispatches nothing;
#: * ``purge_expired_data`` deletes rows past a cutoff in bounded batches: a
#:   repeated sweep removes what is still expired and nothing else;
#: * ``verify_audit_chain`` advances a cursor per chunk and resumes from it, so a
#:   second pass re-verifies a range rather than double-counting it.
#:
#: Two tasks are deliberately absent. ``process_enrichment_events`` and
#: ``check_dns_expiry_alerts`` write rows (an enrichment, a queued expiry alert)
#: whose repeat is a second row rather than the same one, and both run on a timer
#: that is far shorter than any outage — the next tick covers a killed run, so
#: early acknowledgement costs a delay instead of a duplicate.
_LATE_ACKNOWLEDGED_TASKS = (
    "deliver_pending_alerts",
    "refresh_scan_schedules",
    "purge_expired_data",
    "verify_audit_chain",
)

#: Alert delivery walks up to twenty groups (its own bound) at
#: ``ALERT_DELIVERY_TIMEOUT_SECONDS`` each, so its limit has to be looser than a
#: single attempt and tighter than the default for the rest of the platform.
_ALERT_TASK_TIME_LIMIT = 300
_ALERT_TASK_SOFT_TIME_LIMIT = 240

#: The default for a task that declares nothing. A bound that is generous is
#: still doing the job it exists for: without one, a task wedged inside a
#: library call holds its worker for the life of the container, and with a
#: single-task pool that is the whole background pipeline.
_TASK_TIME_LIMIT = 1860
_TASK_SOFT_TIME_LIMIT = 1800

#: The report task declares its own limits next to its code (see
#: ``app/tasks/report_tasks.py``) — the only place where the value of
#: ``REPORT_GENERATION_TIMEOUT_SECONDS`` means anything — and the broker has to
#: cover that class too, so the number is repeated here for the timeout below.
_REPORT_TASK_TIME_LIMIT = settings.REPORT_GENERATION_TIMEOUT_SECONDS + 30

#: How long the broker keeps an unacknowledged message before it offers it to
#: another worker. It must exceed the longest task limit, or the broker starts
#: redelivering work that is still running — the same message executed twice
#: concurrently, which is worse than either outcome alone. The margin is what
#: covers the time between the limit firing and the worker actually giving up.
_VISIBILITY_TIMEOUT = max(_TASK_TIME_LIMIT, _REPORT_TASK_TIME_LIMIT) + 150

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
        "app.tasks.user_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_prefetch_multiplier=1,
    broker_transport_options={"visibility_timeout": _VISIBILITY_TIMEOUT},
    # A limit for every task, whether or not it declares one, plus the alert
    # class's tighter pair and the late acknowledgement policy above. Expressed
    # as annotations rather than on each decorator so that the policy for the
    # whole platform is readable in one place and a new task cannot silently
    # arrive without a bound.
    task_soft_time_limit=_TASK_SOFT_TIME_LIMIT,
    task_time_limit=_TASK_TIME_LIMIT,
    task_annotations={
        **{
            name: {"acks_late": True, "reject_on_worker_lost": True}
            for name in _LATE_ACKNOWLEDGED_TASKS
            if name != "deliver_pending_alerts"
        },
        "deliver_pending_alerts": {
            "acks_late": True,
            "reject_on_worker_lost": True,
            "soft_time_limit": _ALERT_TASK_SOFT_TIME_LIMIT,
            "time_limit": _ALERT_TASK_TIME_LIMIT,
        },
        "check_dns_expiry_alerts": {
            "soft_time_limit": _ALERT_TASK_SOFT_TIME_LIMIT,
            "time_limit": _ALERT_TASK_TIME_LIMIT,
        },
        "send_phishing_digest": {
            "soft_time_limit": _ALERT_TASK_SOFT_TIME_LIMIT,
            "time_limit": _ALERT_TASK_TIME_LIMIT,
        },
        "send_breach_digest": {
            "soft_time_limit": _ALERT_TASK_SOFT_TIME_LIMIT,
            "time_limit": _ALERT_TASK_TIME_LIMIT,
        },
    },
    task_publish_retry=True,
    task_publish_retry_policy={
        "max_retries": settings.REPORT_ENQUEUE_MAX_RETRIES,
        "interval_start": 0.2,
        "interval_step": 0.5,
        "interval_max": 2.0,
    },
    beat_schedule={
        # Single lightweight tick: reads user-configured schedules from
        # system_settings and enqueues module scans when they match.
        "deliver-pending-alerts-every-15-seconds": {
            "task": "deliver_pending_alerts",
            "schedule": 15.0,
            "options": {"queue": "alerts"},
        },
        "process-enrichment-events": {
            "task": "process_enrichment_events", "schedule": 15.0,
            "options": {"queue": "default"},
        },
        "check-dns-expiry-alerts-daily": {
            "task": "check_dns_expiry_alerts",
            "schedule": crontab(hour=5, minute=30),
            "options": {"queue": "alerts"},
        },
        # The phishing digest (WI-10): the candidates the alert budget decided not
        # to interrupt anyone for, reported once. The entry ticks every hour and the
        # task decides whether this is the hour the operator asked for
        # (ALERT_PHISHING_DIGEST_HOUR_UTC, or the value saved in Settings), because a
        # schedule is built when the worker starts and an hour held here could only
        # change when a container was recreated. The quarter hour keeps the digest
        # behind the 05:30 DNS sweep that shares its delivery queue: the tick inside
        # a chosen hour is the only one that sends, so an hour of 6 means 06:15.
        "send-phishing-digest-hourly": {
            "task": "send_phishing_digest",
            "schedule": crontab(minute=15),
            "options": {"queue": "alerts"},
        },
        # The breach digest (WI-06): the scans whose size made them a backlog rather
        # than a report. Its own task on the same hourly tick and the same quarter
        # hour, because it answers the same question - what did the platform see that
        # was not worth interrupting anyone for? - and an installation should have one
        # summary hour, not two.
        "send-breach-digest-hourly": {
            "task": "send_breach_digest",
            "schedule": crontab(minute=15),
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
        # A bounded resumable full pass: one chunk per minute. Retirement
        # cannot delete the part an active cycle has not verified yet.
        "verify-audit-chain-daily": {
            "task": "verify_audit_chain",
            "schedule": 60.0,
            "options": {"queue": "default"},
        },
    },
    task_routes={
        # Only core-owned tasks are routed here. External data collection is not
        # a Celery task at all: connector containers claim module jobs through
        # the HTTP work-poll protocol.
        "deliver_pending_alerts": {"queue": "alerts"},
        "check_dns_expiry_alerts": {"queue": "alerts"},
        "send_phishing_digest": {"queue": "alerts"},
        "send_breach_digest": {"queue": "alerts"},
        "process_enrichment_events": {"queue": "default"},
        # An account notice is small and must not wait behind a batch of alert
        # deliveries, which is why it shares the default queue rather than
        # `alerts`; its own limit is the platform default (RWI-15).
        "send_user_notification": {"queue": "default"},
        "send_user_invitation": {"queue": "default"},
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
