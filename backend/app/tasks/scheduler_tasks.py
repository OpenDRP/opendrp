"""User-configurable scan scheduling.

A single lightweight beat entry runs every minute, reads the per-module
schedules from ``system_settings`` (cached briefly), and enqueues the module
scans when the current UTC time matches. A Redis dedup guard prevents
double-firing within the same minute (e.g. after a beat restart).
"""

import secrets
import asyncio
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone

import structlog

from app.core.celery_app import async_task, celery_app

log = structlog.get_logger()

# Maps schedule settings to the connector module they trigger. Each module
# fans out to every *enabled* connector of that type (core+connector arch).
MODULE_TASKS = {
    "schedule_phishing": [("connector_type", "phishing")],
    "schedule_breaches": [("connector_type", "breaches")],
    "schedule_dns_security": [("connector_type", "dns")],
    "schedule_exposure": [("connector_type", "exposure")],
}

_schedule_cache: dict = {"data": None, "ts": 0.0}
_SCHEDULE_TTL = 60.0
_dedup_token: ContextVar[str | None] = ContextVar(
    "scheduler_dedup_token", default=None
)


def schedule_matches(spec: dict, now: datetime) -> bool:
    """True when ``now`` matches the schedule spec.

    Spec: {"days": [0-6] (0=Sunday, cron-style), "hour": 0-23, "minute": 0-59} in UTC.
    """
    if not isinstance(spec, dict):
        return False
    days = spec.get("days")
    if not isinstance(days, list) or not days:
        return False
    raw_hour = spec.get("hour")
    raw_minute = spec.get("minute")
    if raw_hour is None or raw_minute is None:
        return False
    try:
        hour = int(raw_hour)
        minute = int(raw_minute)
    except (TypeError, ValueError):
        return False
    try:
        normalized_days = [int(day) for day in days]
    except (TypeError, ValueError):
        return False
    if any(day < 0 or day > 6 for day in normalized_days):
        return False
    # Python: Monday=0..Sunday=6 -> cron-style: Sunday=0..Saturday=6.
    cron_dow = (now.weekday() + 1) % 7
    return cron_dow in normalized_days and now.hour == hour and now.minute == minute


def _redis_dedup_key(module: str, now: datetime) -> str:
    return f"sched:{module}:{now.strftime('%Y%m%d%H%M')}"


def _acquire_dedup(module: str, now: datetime) -> str | None:
    """Acquire the per-minute guard and return its ownership token."""
    import redis as redis_lib

    from app.core.config import settings as core_settings

    client = None
    try:
        client = redis_lib.Redis.from_url(core_settings.REDIS_URL, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
        key = _redis_dedup_key(module, now)
        token = secrets.token_urlsafe(24)
        # SET with NX: only the first caller within this minute wins.
        acquired = client.set(key, token, nx=True, ex=900)
        return token if acquired else None
    except Exception as exc:
        # Fail closed when Redis is unavailable: do not dispatch a scan without
        # deduplication, because a beat restart or a second replica could
        # enqueue duplicate work. The next beat tick retries acquisition.
        log.warning("schedule_dedup_unavailable", error=str(exc)[:200])
        return None
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _try_acquire_dedup(module: str, now: datetime) -> bool:
    """Set a per-minute guard in Redis; returns False if already fired."""
    token = _acquire_dedup(module, now)
    _dedup_token.set(token)
    return token is not None


def _acquire_with_token(module: str, now: datetime) -> tuple[bool, str | None]:
    _dedup_token.set(None)
    acquired = _try_acquire_dedup(module, now)
    return acquired, _dedup_token.get()


def _release_dedup(module: str, now: datetime, token: str | None = None) -> None:
    """Release a guard only when this scheduler still owns it.

    The compare-and-delete Lua operation prevents a delayed enqueue failure
    from deleting a newer replica's lock after the original TTL expired.
    """
    import redis as redis_lib

    from app.core.config import settings as core_settings

    client = None
    try:
        client = redis_lib.Redis.from_url(core_settings.REDIS_URL, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
        key = _redis_dedup_key(module, now)
        if token is None:
            log.warning("schedule_dedup_release_without_token", module=module)
            return
        client.eval(
            "if redis.call('get', KEYS[1]) == ARGV[1] then "
            "return redis.call('del', KEYS[1]) else return 0 end",
            1,
            key,
            token,
        )
    except Exception as exc:
        log.warning("schedule_dedup_release_failed", error=str(exc)[:200])
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


async def _load_schedules() -> dict:
    import time

    now_ts = time.monotonic()
    if _schedule_cache["data"] is not None and now_ts - _schedule_cache["ts"] < _SCHEDULE_TTL:
        return _schedule_cache["data"]

    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.models.settings import SystemSettings

    async with AsyncSessionLocal() as db:
        row = (await db.execute(select(SystemSettings).limit(1))).scalar_one_or_none()
        from app.models import Module
        modules = set((await db.execute(select(Module.id).where(Module.enabled.is_(True)))).scalars().all())
        schedules = {module_id: spec for module_id, spec in (row.schedules or {}).items() if module_id in modules} if row else {}
        data = {
            "schedule_phishing": dict(row.schedule_phishing) if row and row.schedule_phishing else None,
            "schedule_breaches": dict(row.schedule_breaches) if row and row.schedule_breaches else None,
            "schedule_dns_security": dict(row.schedule_dns_security) if row and row.schedule_dns_security else None,
            "schedule_exposure": dict(row.schedule_exposure) if row and row.schedule_exposure else None,
            "schedules": schedules,
        }
        for module_id in modules - {"phishing", "breaches", "dns", "exposure"}:
            schedules.setdefault(module_id, None)
        for module_id, spec in schedules.items():
            data[f"schedule_module:{module_id}"] = spec
    _schedule_cache["data"] = data
    _schedule_cache["ts"] = now_ts
    return data


@celery_app.task(name="refresh_scan_schedules", ignore_result=True)
@async_task
async def refresh_scan_schedules_task(self=None, _now: datetime | None = None) -> dict:
    # _now is injectable for tests; production always uses real UTC time.
    now = _now or datetime.now(timezone.utc)
    schedules = await _load_schedules()
    fired: list[str] = []
    scheduled_modules = list(MODULE_TASKS.items())
    dynamic = schedules.get("schedules") or {}
    if isinstance(dynamic, dict):
        for module_id, spec in dynamic.items():
            module_key = f"schedule_module:{module_id}"
            scheduled_modules.append((module_key, [("connector_type", str(module_id))]))
            schedules[module_key] = spec
    occurrences = [(module, tasks, now.replace(second=0, microsecond=0) - timedelta(minutes=delay)) for module, tasks in scheduled_modules for delay in range(10)]
    for module, tasks, occurrence in occurrences:
        spec = schedules.get(module)
        if not spec or not schedule_matches(spec, occurrence):
            continue
        if module.startswith("schedule_module:") and schedules.get("schedules", {}).get(module.removeprefix("schedule_module:")) is None:
            continue
        _dedup_token.set(None)
        acquired, token = await asyncio.to_thread(_acquire_with_token, module, occurrence)
        if not acquired:
            log.info("schedule_already_fired", module=module, at=now.isoformat())
            continue
        connector_type = tasks[0][1]
        jobs: list = []
        try:
            from app.core.database import AsyncSessionLocal
            from app.services.connector_service import ConnectorService

            async with AsyncSessionLocal() as db:
                result = await ConnectorService(db).enqueue_ready_sources(
                    connector_type=connector_type,
                    created_by=None,
                    title=f"Scheduled {connector_type} scan",
                    params={"trigger": "scheduled", "scheduled_at": occurrence.isoformat()},
                )
                jobs = result["job_ids"]
                if not jobs:
                    await asyncio.to_thread(_release_dedup, module, occurrence, token)
                from app.core.audit import AuditLogger

                await AuditLogger.emit(
                    db,
                    action="source.scan.queued",
                    ip_address="internal:celery-beat",
                    user_id=None,
                    details={
                        "connector_type": connector_type,
                        "job_ids": jobs,
                        "sources": result["sources"],
                        "scheduled_at": occurrence.isoformat(),
                    },
                )
            fired.extend(f"{connector_type}:{job_id}" for job_id in jobs)
        except Exception as e:
            # The lock only means dispatch was attempted. If enqueue failed
            # before returning jobs, release it so a later beat tick can retry.
            # Once jobs were created, retain the lock even if a later audit
            # operation fails; releasing it would permit duplicate dispatch.
            if not jobs:
                await asyncio.to_thread(_release_dedup, module, occurrence, token)
            log.error("schedule_enqueue_failed", module=module, err=str(e)[:200])
        log.info("scheduled_scan_fired", module=module, tasks=fired)
    return {"fired": fired, "checked_at": now.isoformat()}
