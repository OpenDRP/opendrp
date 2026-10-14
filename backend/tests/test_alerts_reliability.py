from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select, update

from app.core.config import settings
from app.models.alert_delivery import AlertDelivery, AlertDeliveryStatus
from app.models.settings import SystemSettings
from app.services.alert_delivery_service import AlertDeliveryService
from app.services.alert_service import AlertDeliveryAmbiguousError, AlertDeliveryPermanentError, AlertDeliveryTransientError, AlertService


async def configured(db):
    row = SystemSettings(telegram_alerts_enabled=True, telegram_chat_ids=["-1001234"])
    row.telegram_bot_token_decrypted = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
    db.add(row)
    await db.commit()
    return row


@pytest.mark.asyncio
async def test_removed_destination_is_cancelled(db_session, monkeypatch):
    config = await configured(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    queue = AlertDeliveryService(db_session)
    await queue.enqueue(threat_type="phishing", details={"phishing_domain": "x.example"})
    config.telegram_chat_ids = []
    await db_session.commit()
    sender = AsyncMock()
    monkeypatch.setattr(AlertService, "_send_telegram", sender)
    result = await queue.process_one_group(max_attempts=3)
    assert result["status"] == "cancelled"
    sender.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("error, terminal", [(AlertDeliveryPermanentError("rejected"), True), (AlertDeliveryTransientError("429", retry_after=1200), False)])
async def test_queue_owns_retry_classification(db_session, monkeypatch, error, terminal):
    await configured(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    queue = AlertDeliveryService(db_session)
    await queue.enqueue(threat_type="phishing", details={"phishing_domain": "x.example"})
    await db_session.commit()
    sender = AsyncMock(side_effect=error)
    monkeypatch.setattr(AlertService, "_send_telegram", sender)
    before = datetime.now(timezone.utc)
    result = await queue.process_one_group(max_attempts=3)
    assert result["status"] == ("failed" if terminal else "retry")
    assert sender.await_count == 1
    row = (await db_session.execute(select(AlertDelivery))).scalar_one()
    if not terminal:
        assert row.next_attempt_at.replace(tzinfo=timezone.utc) >= before + timedelta(seconds=1200)


@pytest.mark.asyncio
async def test_all_telegram_parts_persist_acknowledgements(db_session, monkeypatch):
    await configured(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    monkeypatch.setattr(settings, "ALERT_MAX_TELEGRAM_MESSAGE_LENGTH", 700)
    monkeypatch.setattr(settings, "ALERT_RECIPIENT_INTERVAL_SECONDS", 0)
    queue = AlertDeliveryService(db_session)
    for i in range(20):
        await queue.enqueue(threat_type="phishing", details={"phishing_domain": f"host-{i}.example", "evidence": {"title": "x" * 300, "password": "do-not-send"}})
    await db_session.commit()
    sent = []
    async def send(self, text, **kwargs):
        assert not db_session.in_transaction()
        sent.append(text)
        if len(sent) == 2:
            raise AlertDeliveryTransientError("offline")
        return True
    monkeypatch.setattr(AlertService, "_send_telegram", send)
    assert (await queue.process_one_group(max_attempts=3))["status"] == "retry"
    first = sent[0]
    from app.models.alert_delivery import AlertRecipientState
    due = datetime.now(timezone.utc) - timedelta(seconds=1)
    await db_session.execute(update(AlertDelivery).values(next_attempt_at=due))
    await db_session.execute(update(AlertRecipientState).values(next_send_at=due))
    await db_session.commit()
    assert (await queue.process_one_group(max_attempts=3))["status"] == "sent"
    assert sent.count(first) == 1
    assert all(len(part) <= 700 for part in sent)
    assert "host-19.example" in "\n".join(sent)
    assert "do-not-send" not in "\n".join(sent)


@pytest.mark.asyncio
async def test_ambiguous_delivery_holds_its_recipient_only_for_the_configured_window(db_session, monkeypatch):
    """The hold has an end. Its absence silenced a recipient for good.

    A timed-out SMTP thread may still have delivered, so the uncertain send must
    not be repeated immediately — but it must not silence the recipient forever
    either, which is what the queue did before: one ambiguous delivery set a
    recipient that only SQL could free.
    """
    from app.models.alert_delivery import AlertRecipientState

    await configured(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    monkeypatch.setattr(settings, "ALERT_RECIPIENT_HOLD_SECONDS", 60)
    queue = AlertDeliveryService(db_session)
    await queue.enqueue(threat_type="phishing", details={"phishing_domain": "one.example"})
    await db_session.commit()
    rows = await queue.claim_group()
    await queue.mark_failed(rows, AlertDeliveryAmbiguousError("acceptance unknown"), max_attempts=3)
    await queue.enqueue(threat_type="phishing", details={"phishing_domain": "two.example"})
    await db_session.commit()

    assert await queue.claim_group() == []
    await db_session.refresh(rows[0])
    assert rows[0].status == AlertDeliveryStatus.ambiguous

    recipient = (await db_session.execute(select(AlertRecipientState))).scalar_one()
    # A hold, not a lease: nothing is sending any more, the recipient is simply
    # not due. That is what makes the timer able to end it.
    assert recipient.lease_token is None
    held_until = recipient.next_send_at
    assert held_until is not None
    if held_until.tzinfo is None:
        held_until = held_until.replace(tzinfo=timezone.utc)
    assert held_until > datetime.now(timezone.utc)

    await db_session.execute(
        update(AlertRecipientState).values(next_send_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    await db_session.commit()
    assert await queue.claim_group() != []


@pytest.mark.asyncio
async def test_a_worker_that_died_mid_send_holds_its_recipient_for_the_window(
    db_session, monkeypatch
):
    """The sweep's hold ends the same way an ambiguous send's does.

    A worker that dies holding a lease may already have delivered the message,
    so the recipient is held rather than retried at once — but the hold is a
    window, and the queue has to resume by itself when it passes. A window that
    nothing acted on left that deployment's recipient silent until an operator
    edited the database.
    """
    from app.models.alert_delivery import AlertRecipientState

    await configured(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    monkeypatch.setattr(settings, "ALERT_RECIPIENT_HOLD_SECONDS", 60)
    queue = AlertDeliveryService(db_session)
    await queue.enqueue(threat_type="phishing", details={"phishing_domain": "one.example"})
    await db_session.commit()
    rows = await queue.claim_group()
    assert rows, "the worker claimed the delivery and then died holding it"

    # Older than the delivery timeout the sweep looks for.
    await db_session.execute(
        update(AlertDelivery).values(
            locked_at=datetime.now(timezone.utc) - timedelta(minutes=30)
        )
    )
    await db_session.commit()
    await queue.enqueue(threat_type="phishing", details={"phishing_domain": "two.example"})
    await db_session.commit()

    assert await queue.claim_group() == []
    await db_session.refresh(rows[0])
    assert rows[0].status == AlertDeliveryStatus.ambiguous

    recipient = (await db_session.execute(select(AlertRecipientState))).scalar_one()
    assert recipient.next_send_at is not None, "the sweep holds the recipient"

    await db_session.execute(
        update(AlertRecipientState).values(
            next_send_at=datetime.now(timezone.utc) - timedelta(seconds=1)
        )
    )
    await db_session.commit()

    assert await queue.claim_group() != [], "the window ends it; the queue resumes"


@pytest.mark.asyncio
async def test_releasing_a_hold_requeues_the_ambiguous_delivery(db_session, monkeypatch):
    """An operator can end a hold, and the deliveries go back in the queue."""
    await configured(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    queue = AlertDeliveryService(db_session)
    await queue.enqueue(threat_type="phishing", details={"phishing_domain": "one.example"})
    await db_session.commit()
    rows = await queue.claim_group()
    await queue.mark_failed(rows, AlertDeliveryAmbiguousError("acceptance unknown"), max_attempts=3)
    key = AlertDeliveryService.recipient_key("telegram", "-1001234")

    listed = await queue.held_recipients()
    assert [item["key"] for item in listed] == [key]
    assert listed[0]["state"] == "ambiguous"
    assert listed[0]["releasable"] is True
    assert listed[0]["ambiguous_deliveries"] == 1
    assert listed[0]["last_error"]

    result = await queue.release_recipient(key=key)
    assert result["released"] is True
    assert result["requeued_deliveries"] == 1
    await db_session.refresh(rows[0])
    assert rows[0].status == AlertDeliveryStatus.pending
    assert await queue.held_recipients() == []
    assert await queue.claim_group() != []


@pytest.mark.asyncio
async def test_a_live_lease_is_reported_and_not_releasable(db_session, monkeypatch):
    """Breaking a live lease would start a second send of the same message."""
    await configured(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    queue = AlertDeliveryService(db_session)
    await queue.enqueue(threat_type="phishing", details={})
    await db_session.commit()
    rows = await queue.claim_group()
    key = AlertDeliveryService.recipient_key("telegram", "-1001234")

    listed = await queue.held_recipients()
    assert listed[0]["state"] == "delivering"
    assert listed[0]["releasable"] is False

    result = await queue.release_recipient(key=key)
    assert result["released"] is False
    assert result["reason"] == "lease_live"
    await db_session.refresh(rows[0])
    assert rows[0].status == AlertDeliveryStatus.delivering


@pytest.mark.asyncio
async def test_the_recipient_endpoints_show_and_release_a_hold(
    db_session, client, test_admin, auth_headers_admin, auth_headers_viewer, monkeypatch
):
    """The operator path, end to end: see the hold, end it, and be on record."""
    from app.models.audit import AuditLog

    await configured(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    queue = AlertDeliveryService(db_session)
    await queue.enqueue(threat_type="phishing", details={"phishing_domain": "one.example"})
    await db_session.commit()
    rows = await queue.claim_group()
    await queue.mark_failed(rows, AlertDeliveryAmbiguousError("acceptance unknown"), max_attempts=3)
    key = AlertDeliveryService.recipient_key("telegram", "-1001234")

    refused = await client.get("/api/v1/alerts/recipients", headers=auth_headers_viewer)
    assert refused.status_code == 403, refused.text

    listed = await client.get("/api/v1/alerts/recipients", headers=auth_headers_admin)
    assert listed.status_code == 200, listed.text
    item = next(row for row in listed.json()["items"] if row["key"] == key)
    assert item["state"] == "ambiguous"
    assert item["ambiguous_deliveries"] == 1

    released = await client.post(
        f"/api/v1/alerts/recipients/{key}/release", headers=auth_headers_admin
    )
    assert released.status_code == 200, released.text
    assert released.json()["requeued_deliveries"] == 1

    # A second release has nothing to release: the hold it addressed is gone.
    again = await client.post(
        f"/api/v1/alerts/recipients/{key}/release", headers=auth_headers_admin
    )
    assert again.status_code == 404, again.text

    audit = list(
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "alerts.recipient.released")
            )
        ).scalars()
    )
    assert len(audit) == 1
    assert audit[0].user_id == test_admin.id
    assert audit[0].details["recipient_key"] == key
    assert audit[0].details["requeued_deliveries"] == 1


@pytest.mark.asyncio
async def test_stale_ack_cannot_complete_new_claim(db_session, monkeypatch):
    await configured(db_session)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    queue = AlertDeliveryService(db_session)
    await queue.enqueue(threat_type="phishing", details={})
    await db_session.commit()
    rows = await queue.claim_group()
    old_token = rows[0].lease_token
    await db_session.execute(update(AlertDelivery).values(lease_token="new-owner"))
    await db_session.commit()
    await queue.mark_sent(rows, token=old_token)
    await db_session.refresh(rows[0])
    assert rows[0].status == AlertDeliveryStatus.delivering
