from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.core.config import settings
from app.models.alert_delivery import AlertDelivery, AlertDeliveryStatus
from app.models.job import Job, JobStatus
from app.models.settings import SystemSettings
from app.services.alert_delivery_service import AlertDeliveryService


@pytest_asyncio.fixture()
async def alerts_configured(db_session) -> SystemSettings:
    """One configured destination, because a finding is queued per destination.

    Nothing is queued for an installation with no channel: the finding is
    already durable, and a row no destination can satisfy would be retried into
    a permanent failure. These tests are about what happens *after* a row exists,
    so they start from a configured channel.
    """
    config = SystemSettings(
        email_alerts_enabled=False,
        telegram_alerts_enabled=True,
        alert_email_user_ids=[],
        telegram_chat_ids=["-1001234"],
    )
    config.telegram_bot_token_decrypted = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
    db_session.add(config)
    await db_session.commit()
    return config


async def _job(db, status=JobStatus.success):
    row = Job(job_type="phishing.dnstwist", status=status.value, created_by=None, title="scan")
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


@pytest.mark.asyncio
async def test_enqueue_is_durable_and_delayed(db_session, alerts_configured):
    job = await _job(db_session)
    row = await AlertDeliveryService(db_session).enqueue(
        job_id=job.id,
        threat_type="phishing",
        details={"phishing_domain": "evil.example"},
    )
    await db_session.commit()
    stored = await db_session.get(AlertDelivery, row.id)
    assert stored is not None
    assert stored.status == AlertDeliveryStatus.pending
    assert stored.payload["phishing_domain"] == "evil.example"
    assert stored.next_attempt_at is not None


@pytest.mark.asyncio
async def test_running_job_is_not_flushed_until_terminal(db_session):
    job = await _job(db_session, JobStatus.running)
    await AlertDeliveryService(db_session).enqueue(
        job_id=job.id, threat_type="phishing", details={"phishing_domain": "x.example"}
    )
    await db_session.commit()
    service = AlertDeliveryService(db_session)
    result = await service.claim_group()
    assert result == []


@pytest.mark.asyncio
async def test_claim_groups_findings_from_one_job(db_session, alerts_configured, monkeypatch):
    job = await _job(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    service = AlertDeliveryService(db_session)
    for index in range(3):
        await service.enqueue(
            job_id=job.id,
            threat_type="phishing",
            details={"phishing_domain": f"{index}.example"},
        )
    await db_session.commit()
    rows = await service.claim_group()
    assert len(rows) == 3
    assert {row.status for row in rows} == {AlertDeliveryStatus.delivering}
    assert {row.payload["phishing_domain"] for row in rows} == {
        "0.example", "1.example", "2.example"
    }


@pytest.mark.asyncio
async def test_backlog_is_drained_in_bounded_groups_without_duplicates(
    db_session, alerts_configured, monkeypatch
):
    """A large job remains pending after one bounded claim and drains safely."""
    job = await _job(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    service = AlertDeliveryService(db_session)
    for index in range(5):
        await service.enqueue(
            job_id=job.id,
            threat_type="phishing",
            details={"phishing_domain": f"backlog-{index}.example"},
        )
    await db_session.commit()

    first = await service.claim_group(limit=2)
    assert len(first) == 2
    first_ids = {row.id for row in first}
    await service.mark_sent(first)

    second = await service.claim_group(limit=2)
    assert len(second) == 2
    second_ids = {row.id for row in second}
    assert first_ids.isdisjoint(second_ids)
    await service.mark_sent(second)

    third = await service.claim_group(limit=2)
    assert len(third) == 1
    assert third[0].id not in first_ids | second_ids
    await service.mark_sent(third)
    assert await service.claim_group(limit=2) == []


@pytest.mark.asyncio
async def test_failed_delivery_is_rescheduled_and_sanitized(
    db_session, alerts_configured, monkeypatch
):
    job = await _job(db_session)
    service = AlertDeliveryService(db_session)
    row = await service.enqueue(
        job_id=job.id, threat_type="breach", details={"matched_email": "a@example.com"}
    )
    await db_session.commit()
    row.status = AlertDeliveryStatus.delivering
    row.attempts = 1
    await db_session.commit()
    await service.mark_failed(
        [row], "https://provider.example/?api_key=super-secret", max_attempts=3
    )
    stored = await db_session.get(AlertDelivery, row.id)
    assert stored.status == AlertDeliveryStatus.pending
    assert stored.next_attempt_at is not None
    assert "super-secret" not in (stored.last_error or "")
    assert "REDACTED" in (stored.last_error or "")


@pytest.mark.asyncio
async def test_due_retry_is_not_claimed_before_next_attempt(db_session, alerts_configured):
    job = await _job(db_session)
    service = AlertDeliveryService(db_session)
    row = await service.enqueue(
        job_id=job.id, threat_type="phishing", details={"phishing_domain": "early.example"}
    )
    row.next_attempt_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    await db_session.commit()

    assert await service.claim_group() == []
    stored = await db_session.get(AlertDelivery, row.id)
    assert stored.status == AlertDeliveryStatus.pending


@pytest.mark.asyncio
async def test_stale_delivery_lock_is_reclaimed(db_session, alerts_configured):
    job = await _job(db_session)
    service = AlertDeliveryService(db_session)
    row = await service.enqueue(
        job_id=job.id, threat_type="phishing", details={"phishing_domain": "stale.example"}
    )
    row.status = AlertDeliveryStatus.delivering
    row.locked_at = datetime.now(timezone.utc) - timedelta(minutes=16)
    row.next_attempt_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db_session.commit()

    claimed = await service.claim_group()
    assert [item.id for item in claimed] == [row.id]
    stored = await db_session.get(AlertDelivery, row.id)
    assert stored.status == AlertDeliveryStatus.delivering
    assert stored.attempts == 1


@pytest.mark.asyncio
async def test_enqueue_creates_independent_channel_rows(db_session, monkeypatch):
    job = await _job(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    config = SystemSettings(
        email_alerts_enabled=True,
        telegram_alerts_enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        alert_email_user_ids=[],
        telegram_chat_ids=["-1001234"],
    )
    config.alert_recipient_email_decrypted = "soc@example.com"
    config.telegram_bot_token_decrypted = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
    db_session.add(config)
    await db_session.commit()

    await AlertDeliveryService(db_session).enqueue(
        job_id=job.id,
        threat_type="phishing",
        details={"phishing_domain": "channel.example"},
    )
    rows = (
        await db_session.execute(
            select(AlertDelivery).where(AlertDelivery.job_id == job.id)
        )
    ).scalars().all()
    assert {(row.channel, row.target) for row in rows} == {
        ("email", "soc@example.com"),
        ("telegram", "-1001234"),
    }
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_max_attempts_marks_delivery_failed(db_session, alerts_configured):
    job = await _job(db_session)
    service = AlertDeliveryService(db_session)
    row = await service.enqueue(
        job_id=job.id, threat_type="phishing", details={"phishing_domain": "x.example"}
    )
    await db_session.commit()
    row.status = AlertDeliveryStatus.delivering
    row.attempts = 3
    await db_session.commit()
    await service.mark_failed([row], "smtp timeout", max_attempts=3)
    stored = await db_session.get(AlertDelivery, row.id)
    assert stored.status == AlertDeliveryStatus.failed
    assert stored.next_attempt_at is None
