import pytest
from sqlalchemy import select
from unittest.mock import AsyncMock
from app.models import Breach, Connector, PhishingDomain, IngestionEvent, SourceObservation
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
    # Changed by WI-07/WI-10 (W1.4), and the change is required rather than
    # convenient: this candidate must be one the alert budget *would* deliver, or
    # the budget — not the missing channel — is what stops the message, and F-03's
    # contract stops being the thing under test. A candidate found by a connector
    # alone scores 0 (nothing is corroborated and no registration is resolved yet),
    # which the budget routes to the list; the score below is what the same
    # candidate carries once its signals arrive, and the finding is delivered then.
    candidate = (await db_session.execute(select(PhishingDomain))).scalar_one()
    candidate.confidence = 80
    await db_session.commit()
    monkeypatch.setattr(
        "app.services.ingestion_events.AlertDeliveryService.enqueue",
        AsyncMock(return_value=None),
    )
    assert await dispatch_notification_events(db_session) == 0
    events = list((await db_session.execute(select(IngestionEvent))).scalars())
    notifications = [event for event in events if event.kind == "notification"]
    # Changed by WI-04, and the change is the point: this used to assert that the
    # notification was *consumed* along with the reason, which is the defect F-03
    # named — an operator who configured a channel a day after the scan never
    # received what the scan had found. The contract that survives is that a
    # channel-less drain loses nothing: the row is still there, and it carries the
    # reason it is late.
    assert notifications and all(
        event.processed_at is None
        and event.last_error == "no_delivery_channel"
        and event.next_attempt_at is not None
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
    # A finding carries the day the incident happened: an undated one is refused by the
    # core rather than stored with a date nobody stated (F-02), so the three-way outcome
    # this test is about is put on a finding that is otherwise valid.
    f = {"breach_name": "Test", "matched_email": "user@example.com", "breach_date": "2026-01-01"}
    result = await ingest_findings(
        db_session, connector=c, job_id=None, findings=[f, f, {}]
    )
    assert (result.created, result.unchanged, result.rejected) == (1, 1, 1)
    assert result.errors == [
        {"index": 2, "code": "invalid_observation", "retryable": False}
    ]


@pytest.mark.asyncio
async def test_an_undated_breach_finding_is_refused_not_stored(db_session):
    """The refusal F-02 introduced, asserted where the batch distinguishes outcomes.

    A row stored with no date used to be written as 1970-01-01 and read as a fact by the
    page, the report and an alert; a reporter whose data genuinely has no date says so
    itself, and only then is the observation day stored (``metadata_incomplete``).
    """
    c = Connector(
        name="test-undated",
        connector_type="breaches",
        default_job_type="breaches.test",
        status="enabled",
    )
    db_session.add(c)
    await db_session.flush()
    result = await ingest_findings(
        db_session,
        connector=c,
        job_id=None,
        findings=[
            {"breach_name": "NoDate", "matched_email": "user@example.com"},
            {
                "breach_name": "NoDateDeclared",
                "matched_email": "user@example.com",
                "attributes": {"metadata_incomplete": True},
            },
        ],
    )
    assert (result.created, result.rejected) == (1, 1)
    stored = list((await db_session.execute(select(Breach))).scalars())
    assert [row.breach_name for row in stored] == ["NoDateDeclared"]
    assert stored[0].metadata_incomplete is True
    assert result.errors == [
        {"index": 0, "code": "invalid_observation", "retryable": False}
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
