from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, update

from app.core.audit import AuditLogger
from app.core.config import settings
from app.models.audit import AuditChain, AuditLog
from app.models.alert_delivery import AlertDelivery, AlertDeliveryStatus
from app.models.job import ScheduleOccurrence
from app.services.audit_verification import verify_full_chunk
from app.services.audit_archive import archive_prefix
from app.services.connector_service import ConnectorService
from app.tasks.retention_tasks import purge_terminal_alert_history


async def append(db, count):
    for i in range(count):
        await AuditLogger.emit(db, action="asset.view", ip_address="test", details={"i": i}, timestamp=datetime.now(timezone.utc) - timedelta(days=400), require_persistence=True)


@pytest.mark.asyncio
async def test_full_cursor_resumes_and_excludes_concurrent_append(db_session):
    await append(db_session, 5)
    first = await verify_full_chunk(db_session, max_rows=2)
    assert first.ok and first.truncated and first.through_seq == 2
    await append(db_session, 1)
    second = await verify_full_chunk(db_session, max_rows=2)
    assert second.through_seq == 4 and second.truncated
    last = await verify_full_chunk(db_session, max_rows=2)
    assert last.ok and not last.truncated and last.through_seq == 5
    state = await db_session.get(AuditChain, 1, populate_existing=True)
    assert state.last_full_verified_at and state.full_verify_upper_hash is None
    next_cycle = await verify_full_chunk(db_session, max_rows=10)
    assert next_cycle.checked == 6


@pytest.mark.asyncio
async def test_retention_cannot_delete_unverified_full_chunk(db_session, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "AUDIT_ARCHIVE_DIR", str(tmp_path))
    await append(db_session, 3)
    await verify_full_chunk(db_session, max_rows=1)
    result = await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10)
    assert result["deleted"] == 1
    result = await archive_prefix(db_session, cutoff=datetime.now(timezone.utc), limit=10)
    assert result["deleted"] == 0
    assert (await verify_full_chunk(db_session, max_rows=10)).ok


@pytest.mark.asyncio
async def test_failed_chunk_persists_failure_without_cursor_advance(db_session):
    await append(db_session, 3)
    await verify_full_chunk(db_session, max_rows=1)
    await db_session.execute(update(AuditLog).where(AuditLog.seq == 2).values(action="asset.delete"))
    await db_session.commit()
    assert not (await verify_full_chunk(db_session, max_rows=2)).ok
    state = await db_session.get(AuditChain, 1, populate_existing=True)
    assert state.full_verify_cursor == 1 and state.last_failure_seq == 2


@pytest.mark.asyncio
async def test_processed_cleanup_never_deletes_pending_or_ambiguous(db_session):
    old = datetime.now(timezone.utc) - timedelta(days=200)
    for status in (AlertDeliveryStatus.pending, AlertDeliveryStatus.delivering, AlertDeliveryStatus.ambiguous, AlertDeliveryStatus.sent, AlertDeliveryStatus.failed):
        db_session.add(AlertDelivery(channel="telegram", target="1234", threat_type="phishing", payload={}, status=status, created_at=old, updated_at=old))
    await db_session.commit()
    result = await purge_terminal_alert_history(db_session, now=datetime.now(timezone.utc))
    assert result["alert_deliveries"].deleted_rows == 2
    remaining = set((await db_session.execute(select(AlertDelivery.status))).scalars())
    assert remaining == {"pending", "delivering", "ambiguous"}


@pytest.mark.asyncio
async def test_schedule_occurrence_survives_job_deletion(db_session):
    service = ConnectorService(db_session)
    connector = await service.register(name="durable-sched", connector_type="phishing", api_version="1", default_job_type="phishing.durable-sched")
    params = {"scheduled_at": "2026-10-12T02:30:00+00:00", "trigger": "scheduled"}
    rows = await service.enqueue_module_scan(connector_type="phishing", connector_name=connector.name, created_by=None, title="Scheduled", params=params)
    job = rows[0]
    # SQLite test connections do not enforce FK actions; simulate SET NULL.
    await db_session.execute(update(ScheduleOccurrence).values(job_id=None))
    await db_session.delete(job)
    await db_session.commit()
    assert await service.enqueue_module_scan(connector_type="phishing", connector_name=connector.name, created_by=None, title="Scheduled", params=params) == []
    assert (await db_session.execute(select(ScheduleOccurrence))).scalar_one()
