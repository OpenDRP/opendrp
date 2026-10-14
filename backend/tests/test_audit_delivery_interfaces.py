import uuid
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.core.audit import AuditLogger
from app.models.ingestion_event import IngestionEvent
from app.services.ingestion_events import record_event, dispatch_notification_events


@pytest.mark.asyncio
async def test_typed_audit_filters_and_snapshot_identity(client, db_session, auth_headers_admin, test_admin):
    job_id = uuid.uuid4()
    await AuditLogger.emit(db_session, action="task.failed", ip_address="test", user_id=test_admin.id, details={"request_id": "req-exact", "job_id": str(job_id)}, require_persistence=True)
    response = await client.get("/api/v1/audit/logs", headers=auth_headers_admin, params={"request_id": "req-exact", "job_id": str(job_id), "outcome": "failure"})
    assert response.status_code == 200
    assert len(response.json()["items"]) == 1
    assert response.json()["items"][0]["actor_identity_source"] == "snapshot"
    assert (await client.get("/api/v1/audit/logs", headers=auth_headers_admin, params={"outcome": "unknown"})).status_code == 422
    assert (await client.get("/api/v1/audit/logs", headers=auth_headers_admin, params={"job_id": "invalid"})).status_code == 422


@pytest.mark.asyncio
async def test_operational_notification_survives_missing_channels(db_session):
    await record_event(db_session, kind="notification", module="module:operations", entity_id=uuid.uuid4(), payload={"title": "Audit broken"})
    await db_session.commit()
    assert await dispatch_notification_events(db_session) == 0
    row = (await db_session.execute(select(IngestionEvent))).scalar_one()
    assert row.processed_at is None and row.next_attempt_at and row.last_error == "no_delivery_channel"


@pytest.mark.asyncio
async def test_truncated_database_cli_is_not_success(db_session, monkeypatch):
    from app.core.audit_chain import ChainVerification
    from scripts import verify_audit_chain
    monkeypatch.setattr(verify_audit_chain, "verify", AsyncMock(return_value=ChainVerification(checked=1, through_seq=1, truncated=True)))
    code = await verify_audit_chain._verify_database(full=True, since=None, max_rows=1, as_json=True)
    assert code == 3
