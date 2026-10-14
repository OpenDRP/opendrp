"""The outbox drains claim a row, drop its lock, and re-check the claim.

`app/services/ingestion_events.py` is what runs after ingestion has written the
finding and before anything is delivered: `dispatch_notification_events` turns a
notification row into a delivery, and `enrich_one_event` resolves the
registration facts a phishing finding arrived without. Both run on a schedule
with no caller to fail, which is exactly the shape that ships untested — the
coverage gate caught `enrich_one_event` executed by no test at all, because the
task that calls it is exercised with the import stubbed out.

What the drain can get wrong while the schedule stays green:

* it holds the row lock across a network call, so every worker waits on whichever
  one is talking to WHOIS (the code releases the lock first — pinned below);
* a second worker claims the same row while the first is waiting on WHOIS, and
  the stale result is written over the newer claim (the re-check pins that too);
* a failure is recorded as a terminal success, so an error leaves no retry;
* a row with no delivery channel is retried forever every five minutes, or a
  scheduled operations row is consumed as though it had been delivered.

Every test here runs against the real models and the real session the tasks use.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.core import database
from app.models import IngestionEvent, PhishingDomain
from app.services.ingestion_events import dispatch_notification_events, enrich_one_event


def _finding(**overrides) -> PhishingDomain:
    values: dict = {
        "phishing_domain": "evil.example.com",
        "matched_asset": "example.com",
        "detection_source": "test",
    }
    values.update(overrides)
    return PhishingDomain(**values)


def _due_whois_event(finding_id: uuid.UUID) -> IngestionEvent:
    return IngestionEvent(
        event_key=f"whois:phishing:{uuid.uuid4()}",
        kind="whois",
        module="phishing",
        entity_id=finding_id,
        payload={},
    )


def _utc(value: datetime) -> datetime:
    """SQLite stores a naive instant; the platform stores UTC."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


@pytest.mark.asyncio
async def test_a_drain_with_nothing_due_claims_nothing(db_session):
    assert await enrich_one_event(db_session) is False
    assert list((await db_session.execute(select(IngestionEvent))).scalars()) == []


@pytest.mark.asyncio
async def test_enrichment_fills_only_what_is_empty_and_completes_the_row(
    db_session, monkeypatch
):
    finding = _finding(whois_abuse_email="known@example.com")
    db_session.add(finding)
    await db_session.flush()
    event = _due_whois_event(finding.id)
    db_session.add(event)
    await db_session.commit()
    created = datetime(2019, 4, 2, 3, 4, 5, tzinfo=timezone.utc)

    async def fake_enrich(self, threat):
        threat.whois_registrar = "Example Registrar"
        threat.whois_abuse_email = "provider-says-someone-else@example.com"
        threat.domain_created_at = created

    monkeypatch.setattr(
        "app.services.phishing.whois_service.WhoisService.enrich", fake_enrich
    )

    assert await enrich_one_event(db_session) is True

    assert event.attempts == 1
    assert event.processed_at is not None
    assert event.last_error is None
    assert event.next_attempt_at is not None
    assert finding.whois_registrar == "Example Registrar"
    # The provider does not overwrite a fact the finding already carries.
    assert finding.whois_abuse_email == "known@example.com"
    assert _utc(finding.domain_created_at) == created


@pytest.mark.asyncio
async def test_a_failed_enrichment_is_recorded_with_a_bounded_retry(
    db_session, monkeypatch
):
    finding = _finding()
    db_session.add(finding)
    await db_session.flush()
    event = _due_whois_event(finding.id)
    db_session.add(event)
    await db_session.commit()

    async def failing_enrich(self, threat):
        threat.whois_registrar = "Never Stored"
        raise ValueError("whois call failed")

    monkeypatch.setattr(
        "app.services.phishing.whois_service.WhoisService.enrich", failing_enrich
    )
    before = datetime.now(timezone.utc)

    assert await enrich_one_event(db_session) is True

    assert event.processed_at is None
    assert event.last_error == "ValueError"
    assert event.attempts == 1
    # 30 * 2**1, bounded by the cap the drain applies.
    delta = (_utc(event.next_attempt_at) - before).total_seconds()
    assert 30 <= delta <= 150
    assert finding.whois_registrar is None


@pytest.mark.asyncio
async def test_a_newer_claim_fences_the_result_of_the_older_one(db_session, monkeypatch):
    finding = _finding()
    db_session.add(finding)
    await db_session.flush()
    event = _due_whois_event(finding.id)
    db_session.add(event)
    await db_session.commit()

    async def enrich_while_another_worker_claims(self, threat):
        threat.whois_registrar = "Stale Registrar"
        # Another worker takes the row over while this one waits on the network:
        # the drain released its lock before the call, which is the point.
        async with database.AsyncSessionLocal() as other:
            row = (
                await other.execute(
                    select(IngestionEvent)
                    .where(IngestionEvent.id == event.id)
                    .with_for_update()
                )
            ).scalar_one()
            row.attempts += 1
            await other.commit()

    monkeypatch.setattr(
        "app.services.phishing.whois_service.WhoisService.enrich",
        enrich_while_another_worker_claims,
    )

    assert await enrich_one_event(db_session) is True

    # The discarded result rolled this session back, which expires what it holds;
    # re-reading is what proves nothing of the stale claim survived it.
    await db_session.refresh(event)
    await db_session.refresh(finding)
    assert event.attempts == 2
    assert event.processed_at is None
    assert finding.whois_registrar is None


@pytest.mark.asyncio
async def test_a_queued_notification_is_marked_processed_and_counted(db_session, monkeypatch):
    monkeypatch.setattr(
        "app.services.ingestion_events.AlertDeliveryService.enqueue",
        AsyncMock(return_value=object()),
    )
    event = IngestionEvent(
        event_key=f"notification:phishing:{uuid.uuid4()}",
        kind="notification",
        module="phishing",
        entity_id=uuid.uuid4(),
        payload={},
    )
    db_session.add(event)
    await db_session.commit()

    assert await dispatch_notification_events(db_session) == 1

    await db_session.refresh(event)
    assert event.processed_at is not None
    assert event.last_error is None


@pytest.mark.asyncio
async def test_an_operations_row_retries_without_a_channel_where_a_finding_row_does_not(
    db_session, monkeypatch
):
    monkeypatch.setattr(
        "app.services.ingestion_events.AlertDeliveryService.enqueue",
        AsyncMock(return_value=None),
    )
    operations = IngestionEvent(
        event_key=f"notification:module:operations:{uuid.uuid4()}",
        kind="notification",
        module="module:operations",
        entity_id=uuid.uuid4(),
        payload={},
    )
    finding_row = IngestionEvent(
        event_key=f"notification:phishing:{uuid.uuid4()}",
        kind="notification",
        module="phishing",
        entity_id=uuid.uuid4(),
        payload={},
    )
    db_session.add_all([operations, finding_row])
    await db_session.commit()

    assert await dispatch_notification_events(db_session) == 0

    assert operations.processed_at is None
    assert operations.last_error == "no_delivery_channel"
    assert operations.next_attempt_at is not None
    # A delivery notification is terminal for a deployment with no channel; the
    # row reports why instead of being retried every five minutes forever.
    assert finding_row.processed_at is not None
    assert finding_row.last_error == "no_delivery_channel"
