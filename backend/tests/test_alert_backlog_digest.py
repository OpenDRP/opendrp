"""What an installation does with findings it cannot deliver yet (WI-04).

`dispatch_notification_events` used to consume a notification when no channel was
configured, recording `no_delivery_channel` as it went. The finding is durable —
it is in the UI — but the section then has no "first delivery" story: an operator
who installs, runs the weekday scan and points SMTP at their mail server a day
later never hears about what the scan found, and the same trap waits for an
installation whose provider was down for a week (F-03).

Two halves hold that story together, and each covers a failure the other cannot:

* the outbox row is *deferred* rather than consumed, so a channel configured
  later still has something to report, and the drain does not wake up for it on
  every pass (`test_ingestion_outbox_drains.py` pins the timing);
* the save that makes an installation able to deliver claims the held rows and
  reports them as a single operations digest — not as the per-job stream the
  window exists to prevent, and not twice when two administrators save at once.

The digest is what makes the deferral useful rather than merely patient: without
it the backlog waits out the window before anything is said about it at all, and
the operator who just configured a channel is told nothing for a day.

Every test here runs the real outbox and the real settings service; only the
delivery service's queueing is replaced, because what is under test is what the
platform does *before* a message exists.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.models import IngestionEvent
from app.schemas.settings import SystemSettingsUpdate
from app.services.ingestion_events import dispatch_notification_events, record_event
from app.services.settings_service import SettingsService


def _utc(value: datetime) -> datetime:
    """SQLite stores a naive instant; the platform stores UTC."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def _scan_without_a_channel(db, monkeypatch, modules=("phishing", "phishing", "phishing", "dns")):
    """Ingest as an installation with no channel configured does.

    The scan writes its notifications, and the drain runs and cannot hand any of
    them to a destination. `enqueue` returning `None` is what the delivery service
    answers when nothing is configured — stubbed rather than simulated because the
    real SMTP/Telegram destinations are what the W0.4 tests are not about.
    """
    monkeypatch.setattr(
        "app.services.ingestion_events.AlertDeliveryService.enqueue",
        AsyncMock(return_value=None),
    )
    for module in modules:
        await record_event(
            db,
            kind="notification",
            module=module,
            entity_id=uuid.uuid4(),
            payload={"title": f"{module} arrival"},
        )
    await db.commit()
    assert await dispatch_notification_events(db) == 0
    return list(modules)


async def _notifications(db) -> list[IngestionEvent]:
    """Every notification row, re-read: the settings save committed behind them."""
    return list(
        (
            await db.execute(
                select(IngestionEvent)
                .where(IngestionEvent.kind == "notification")
                .order_by(IngestionEvent.created_at, IngestionEvent.id)
                .execution_options(populate_existing=True)
            )
        ).scalars()
    )


async def _configure_email_channel(db, **overrides) -> None:
    """The first successful configuration of a channel, through the real service."""
    values = {
        "email_alerts_enabled": True,
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "alert_recipient_email": "soc@example.com",
    }
    values.update(overrides)
    settings_row = await SettingsService(db).get_singleton()
    await SettingsService(db).update_settings(settings_row, SystemSettingsUpdate(**values))


@pytest.mark.asyncio
async def test_a_scan_without_a_channel_is_held_rather_than_consumed(db_session, monkeypatch):
    """The defect itself: the rows are still there to be delivered later."""
    await _scan_without_a_channel(db_session, monkeypatch)

    held = await _notifications(db_session)

    assert len(held) == 4
    assert all(row.processed_at is None for row in held), (
        "a finding that arrived while no channel existed was consumed, so the "
        "channel configured later never hears about it"
    )
    assert all(row.last_error == "no_delivery_channel" for row in held)
    assert all(row.next_attempt_at is not None for row in held)


@pytest.mark.asyncio
async def test_the_held_backlog_leaves_as_one_digest_when_a_channel_is_configured(
    db_session, monkeypatch
):
    """One message, not one per held finding — and it says what it covers."""
    await _scan_without_a_channel(db_session, monkeypatch)

    await _configure_email_channel(db_session)

    rows = await _notifications(db_session)
    assert len(rows) == 5, (
        "the backlog is summarised, not replayed: exactly one notification joins "
        f"the four held rows, got {len(rows) - 4}"
    )
    digest = [row for row in rows if row.module == "module:operations"]
    assert len(digest) == 1
    payload = digest[0].payload
    assert "4" in payload["title"] and "channel" in payload["title"]
    assert payload["fields"]["Held findings"] == 4
    assert payload["fields"]["By module"] == "dns × 1, phishing × 3"
    # A date rather than an instant: an operator reads how stale the backlog is,
    # and a naive SQLite timestamp cannot be mistaken for a local wall clock.
    assert payload["fields"]["Held since"] == _utc(digest[0].created_at).date().isoformat()

    covered = [row for row in rows if row.module != "module:operations"]
    assert all(row.processed_at is not None for row in covered), (
        "the digest reports these rows, so the drain must not also replay them"
    )
    # The digest is itself an outbox row: with no destination this early it waits
    # for the drain like everything else rather than being delivered unasked.
    assert digest[0].processed_at is None


@pytest.mark.asyncio
async def test_a_second_save_does_not_report_the_same_backlog_again(db_session, monkeypatch):
    """The digest is one-off: editing an existing channel is not a first setup."""
    await _scan_without_a_channel(db_session, monkeypatch)
    await _configure_email_channel(db_session)
    before = await _notifications(db_session)

    settings_row = await SettingsService(db_session).get_singleton()
    await SettingsService(db_session).update_settings(
        settings_row, SystemSettingsUpdate(alert_recipient_email="soc2@example.com")
    )

    after = await _notifications(db_session)
    assert len(after) == len(before) == 5
    assert len([row for row in after if row.module == "module:operations"]) == 1


@pytest.mark.asyncio
async def test_a_single_held_finding_is_reported_in_the_singular(db_session, monkeypatch):
    """A human reads the count, so the one-finding backlog is not "1 findings"."""
    await _scan_without_a_channel(db_session, monkeypatch, modules=("phishing",))

    await _configure_email_channel(db_session)

    rows = await _notifications(db_session)
    digest = [row for row in rows if row.module == "module:operations"]
    assert len(digest) == 1
    assert digest[0].payload["title"] == (
        "Alert backlog: 1 finding arrived while no channel was configured"
    )
    assert digest[0].payload["fields"]["By module"] == "phishing × 1"


@pytest.mark.asyncio
async def test_an_installation_with_nothing_held_reports_no_backlog(db_session):
    """Every installation configures its first channel; most have no backlog.

    The digest is not a message about the channel being new — it is a report of
    findings that were waiting — so a first save with nothing held queues nothing
    at all. No queueing is stubbed out here: the whole path runs.
    """
    await _configure_email_channel(db_session)

    assert await _notifications(db_session) == []


@pytest.mark.asyncio
async def test_a_save_that_leaves_the_installation_unable_to_deliver_reports_nothing(
    db_session, monkeypatch
):
    """Half a channel is not a channel: the backlog keeps waiting, unreported."""
    await _scan_without_a_channel(db_session, monkeypatch)

    settings_row = await SettingsService(db_session).get_singleton()
    await SettingsService(db_session).update_settings(
        settings_row,
        SystemSettingsUpdate(
            smtp_host="smtp.example.com",
            smtp_port=587,
            alert_recipient_email="soc@example.com",
        ),
    )

    rows = await _notifications(db_session)
    assert len(rows) == 4
    assert all(row.processed_at is None for row in rows), (
        "email is still disabled, so this save delivers nothing and must not "
        "claim the backlog the next save is supposed to report"
    )
