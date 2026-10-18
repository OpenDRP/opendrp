"""Delivery counters beside the channel probe, and the degraded rule they drive.

A probe answers whether the installation can reach the provider. It cannot answer
whether the messages are leaving: a green channel with a stuck queue is exactly
the case this test file exists for. The aggregates are numbers only — no target,
batch id or recipient digest — because the same response is served to viewers.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.api.v1.routers import alerts
from app.models.alert_delivery import AlertDelivery, AlertRecipientState
from app.services.alert_delivery_service import AlertDeliveryService


def _delivery(
    *,
    channel: str = "email",
    status: str = "pending",
    age_seconds: int = 0,
    now: datetime,
    next_attempt_at: datetime | None = None,
) -> AlertDelivery:
    return AlertDelivery(
        threat_type="phishing",
        channel=channel,
        payload={},
        status=status,
        created_at=now - timedelta(seconds=age_seconds),
        next_attempt_at=next_attempt_at,
    )


@pytest.mark.asyncio
async def test_counts_by_status_and_the_oldest_unresolved_delivery(db_session):
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            _delivery(status="sent", age_seconds=5, now=now),
            _delivery(status="pending", age_seconds=600, now=now),
            _delivery(status="failed", age_seconds=240, now=now),
            _delivery(
                channel="telegram",
                status="pending",
                age_seconds=60,
                now=now,
                next_attempt_at=now + timedelta(seconds=300),
            ),
        ]
    )
    await db_session.commit()

    by_channel, waiting = await AlertDeliveryService(db_session).channel_delivery_summary(
        stuck_after_seconds=900
    )

    email = by_channel["email"]
    assert email["counts"]["sent"] == 1
    assert email["counts"]["pending"] == 1
    assert email["counts"]["failed"] == 1
    assert email["counts"]["delivering"] == 0
    # Only unresolved rows decide the age: a sent delivery is not a wait.
    assert 590 <= email["oldest_unresolved_age_seconds"] <= 600
    assert email["oldest_unresolved_at"] is not None
    # Ten and four minutes are younger than the hold window, so nothing is stuck.
    assert email["stuck"] == 0
    assert email["degraded_reason"] is None
    # A retry window is counted separately from rows that are due now.
    assert email["retrying"] == 0
    assert by_channel["telegram"]["counts"]["pending"] == 1
    assert by_channel["telegram"]["retrying"] == 1
    assert waiting == 0


@pytest.mark.asyncio
async def test_an_old_ambiguous_or_failed_delivery_is_stuck(db_session):
    """The queue cannot resolve these by itself once the hold window has passed."""
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            _delivery(status="ambiguous", age_seconds=1800, now=now),
            _delivery(status="failed", age_seconds=1800, now=now),
            _delivery(status="pending", age_seconds=1800, now=now),
            _delivery(channel="telegram", status="failed", age_seconds=120, now=now),
        ]
    )
    await db_session.commit()

    by_channel, _waiting = await AlertDeliveryService(db_session).channel_delivery_summary(
        stuck_after_seconds=900
    )

    assert by_channel["email"]["stuck"] == 2
    assert by_channel["email"]["retrying"] == 0
    assert by_channel["email"]["degraded_reason"] == "delivery_stuck"
    # A failed delivery younger than the window is still being retried.
    assert by_channel["telegram"]["stuck"] == 0
    assert by_channel["telegram"]["degraded_reason"] is None


@pytest.mark.asyncio
async def test_a_waiting_recipient_is_counted_once_for_the_installation(db_session):
    now = datetime.now(timezone.utc)
    db_session.add(
        AlertRecipientState(
            key=AlertDeliveryService.recipient_key("email", "person@example.test"),
            next_send_at=now + timedelta(minutes=10),
        )
    )
    await db_session.commit()

    _by_channel, waiting = await AlertDeliveryService(db_session).channel_delivery_summary(
        stuck_after_seconds=900
    )

    assert waiting == 1


def _alert_settings(**overrides) -> SimpleNamespace:
    base = {
        "smtp_host": "smtp.example",
        "smtp_port": 587,
        "smtp_security_mode": "starttls",
        "smtp_from_email_decrypted": "a@b.example",
        "smtp_user": None,
        "smtp_password_decrypted": None,
        "email_alerts_enabled": True,
        "telegram_bot_token_decrypted": None,
        "telegram_chat_ids": None,
        "telegram_alerts_enabled": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _install_settings(monkeypatch, settings_obj) -> None:
    class _Service:
        def __init__(self, _db):
            pass

        async def get_singleton(self):
            return settings_obj

    monkeypatch.setattr(alerts, "SettingsService", _Service)


@pytest.mark.asyncio
async def test_the_endpoint_publishes_queue_numbers_and_degrades_a_stuck_channel(
    client, auth_headers_viewer, db_session, monkeypatch
):
    now = datetime.now(timezone.utc)
    db_session.add_all(
        [
            _delivery(status="ambiguous", age_seconds=1800, now=now),
            _delivery(
                status="pending",
                age_seconds=60,
                now=now,
                next_attempt_at=now + timedelta(seconds=120),
            ),
            _delivery(channel="telegram", status="sent", age_seconds=30, now=now),
        ]
    )
    db_session.add(
        AlertRecipientState(
            key=AlertDeliveryService.recipient_key("email", "person@example.test"),
            next_send_at=now + timedelta(minutes=10),
        )
    )
    await db_session.commit()
    _install_settings(monkeypatch, _alert_settings())

    async def _healthy(_s, _timeout):
        return alerts.ProbeResult("healthy", "SMTP connection is available", 9)

    monkeypatch.setattr(alerts, "_bounded_smtp_probe", _healthy)

    response = await client.get("/api/v1/alerts/health", headers=auth_headers_viewer)

    assert response.status_code == 200
    body = response.json()
    items = {item["channel"]: item for item in body["items"]}
    email = items["email"]
    assert email["health"] == "degraded"
    assert email["delivery"]["degraded_reason"] == "delivery_stuck"
    assert email["delivery"]["stuck"] == 1
    assert email["delivery"]["counts"]["ambiguous"] == 1
    assert email["delivery"]["counts"]["pending"] == 1
    assert email["delivery"]["retrying"] == 1
    # Telegram has no queue here, but the shape is the same.
    assert items["telegram"]["delivery"]["counts"]["sent"] == 1
    assert items["telegram"]["delivery"]["degraded_reason"] is None
    assert body["delivery_queue"]["waiting_recipients"] == 1
    # Numbers only: the queue row identifies a recipient and a batch, and neither
    # may travel to a viewer.
    serialized = json.dumps(body)
    assert "person@example.test" not in serialized
    assert AlertDeliveryService.recipient_key("email", "person@example.test") not in serialized
    assert "batch_id" not in serialized
    assert '"target"' not in serialized


@pytest.mark.asyncio
async def test_a_failed_probe_stays_the_more_severe_answer(
    client, auth_headers_viewer, db_session, monkeypatch
):
    now = datetime.now(timezone.utc)
    db_session.add(_delivery(status="ambiguous", age_seconds=1800, now=now))
    await db_session.commit()
    _install_settings(monkeypatch, _alert_settings())

    async def _failed(_s, _timeout):
        return alerts.ProbeResult("failed", "SMTP check failed: OSError", 4)

    monkeypatch.setattr(alerts, "_bounded_smtp_probe", _failed)

    response = await client.get("/api/v1/alerts/health", headers=auth_headers_viewer)
    item = {row["channel"]: row for row in response.json()["items"]}["email"]

    assert item["health"] == "failed"
    # The queue problem is still reported, it just does not overwrite a failure.
    assert item["delivery"]["degraded_reason"] == "delivery_stuck"
