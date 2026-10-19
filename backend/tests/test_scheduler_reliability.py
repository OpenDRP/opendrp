from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.models.job import Job
from app.services.connector_service import ConnectorService
from app.tasks import scheduler_tasks


@pytest.mark.asyncio
async def test_delayed_tick_uses_original_occurrence(monkeypatch):
    monkeypatch.setattr(scheduler_tasks, "_load_schedules", AsyncMock(return_value={"schedule_phishing": {"days": [1], "hour": 2, "minute": 30}}))
    monkeypatch.setattr(scheduler_tasks, "_acquire_with_token", lambda module, now: (True, "owner"))
    enqueue = AsyncMock(return_value={"job_ids": ["job"], "sources": []})
    monkeypatch.setattr(ConnectorService, "enqueue_ready_sources", enqueue)
    from app.core.audit import AuditLogger
    monkeypatch.setattr(AuditLogger, "emit", AsyncMock())
    await __import__("asyncio").to_thread(scheduler_tasks.refresh_scan_schedules_task.run, _now=datetime(2026, 10, 12, 2, 34, tzinfo=timezone.utc))
    assert enqueue.await_count == 1
    assert enqueue.await_args.kwargs["params"]["scheduled_at"] == "2026-10-12T02:30:00+00:00"


@pytest.mark.asyncio
async def test_same_scheduled_occurrence_returns_existing_job(db_session):
    service = ConnectorService(db_session)
    connector = await service.register(name="schedule-test", connector_type="phishing", api_version="1", default_job_type="phishing.schedule-test")
    params = {"trigger": "scheduled", "scheduled_at": "2026-10-12T02:30:00+00:00"}
    first = await service.enqueue_module_scan(connector_type="phishing", connector_name=connector.name, created_by=None, title="Scheduled", params=params)
    second = await service.enqueue_module_scan(connector_type="phishing", connector_name=connector.name, created_by=None, title="Scheduled", params=params)
    assert first[0].id == second[0].id
    assert len(list((await db_session.execute(select(Job).where(Job.schedule_key.is_not(None)))).scalars())) == 1
