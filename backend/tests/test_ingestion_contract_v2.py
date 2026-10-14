import pytest
from sqlalchemy import select
from unittest.mock import AsyncMock
from app.models import Connector, PhishingDomain, IngestionEvent, SourceObservation
from app.services.ingestion_service import ingest_findings
from app.services.ingestion_events import dispatch_notification_events


@pytest.mark.asyncio
async def test_replay_is_successful_and_outbox_survives_no_channels(
    db_session, monkeypatch
):
    c = Connector(
        name="test-phishing-default",
        connector_type="phishing",
        default_job_type="phishing.test",
        status="enabled",
    )
    db_session.add(c)
    await db_session.flush()
    findings = [{"phishing_domain": "evil.example.com", "matched_asset": "example.com"}]
    first = await ingest_findings(
        db_session, connector=c, job_id=None, findings=findings
    )
    assert first.payload()["created"] == 1 and first.rejected == 0
    await db_session.commit()
    again = await ingest_findings(
        db_session, connector=c, job_id=None, findings=findings
    )
    assert again.unchanged == 1 and again.accepted == 1 and again.rejected == 0
    # Latest evidence refresh is persisted on replay without creating a second alert.
    evidence = list((await db_session.execute(select(SourceObservation))).scalars())
    assert len(evidence) == 1 and evidence[0].last_seen_at >= evidence[0].first_seen_at
    await db_session.commit()
    assert len(list((await db_session.execute(select(IngestionEvent))).scalars())) == 2
    monkeypatch.setattr(
        "app.services.ingestion_events.AlertDeliveryService.enqueue",
        AsyncMock(return_value=None),
    )
    assert await dispatch_notification_events(db_session) == 0
    events = list((await db_session.execute(select(IngestionEvent))).scalars())
    notifications = [event for event in events if event.kind == "notification"]
    assert notifications and all(
        event.processed_at is not None and event.last_error == "no_delivery_channel"
        for event in notifications
    )
    assert any(event.kind == "whois" and event.processed_at is None for event in events)


@pytest.mark.asyncio
async def test_failure_rolls_back_finding_evidence_and_event(db_session, monkeypatch):
    c = Connector(
        name="test",
        connector_type="phishing",
        default_job_type="phishing.test",
        status="enabled",
    )
    db_session.add(c)
    await db_session.commit()
    monkeypatch.setattr(
        "app.services.ingestion_service.record_event",
        AsyncMock(side_effect=RuntimeError("outbox failure")),
    )
    with pytest.raises(RuntimeError, match="outbox failure"):
        await ingest_findings(
            db_session,
            connector=c,
            job_id=None,
            findings=[
                {"phishing_domain": "evil.example.com", "matched_asset": "example.com"}
            ],
        )
    await db_session.rollback()
    assert list((await db_session.execute(select(PhishingDomain))).scalars()) == []
    assert list((await db_session.execute(select(SourceObservation))).scalars()) == []
    assert list((await db_session.execute(select(IngestionEvent))).scalars()) == []


@pytest.mark.asyncio
async def test_invalid_item_is_separate_from_unchanged(db_session):
    c = Connector(
        name="test",
        connector_type="breaches",
        default_job_type="breaches.test",
        status="enabled",
    )
    db_session.add(c)
    await db_session.flush()
    f = {"breach_name": "Test", "matched_email": "user@example.com"}
    result = await ingest_findings(
        db_session, connector=c, job_id=None, findings=[f, f, {}]
    )
    assert (result.created, result.unchanged, result.rejected) == (1, 1, 1)
    assert result.errors == [
        {"index": 2, "code": "invalid_observation", "retryable": False}
    ]


@pytest.mark.asyncio
async def test_internal_batches_are_capped_to_protocol_prefix(db_session):
    c = Connector(
        name="test",
        connector_type="phishing",
        default_job_type="phishing.test",
        status="enabled",
    )
    db_session.add(c)
    await db_session.flush()
    findings = [
        {"phishing_domain": f"cap-{index}.example.com", "matched_asset": "example.com"}
        for index in range(505)
    ]
    result = await ingest_findings(
        db_session, connector=c, job_id=None, findings=findings
    )
    assert result.received == 505 and result.created == 500 and result.rejected == 0
    assert result.accepted == 500


@pytest.mark.asyncio
async def test_missing_connector_rejects_batch_without_dereference(db_session):
    result = await ingest_findings(
        db_session,
        connector=None,
        job_id=None,
        findings=[{"phishing_domain": "x.example.com"}],
    )
    assert result.accepted == 0 and result.rejected == 1
    assert result.errors[0]["code"] == "invalid_contract"
