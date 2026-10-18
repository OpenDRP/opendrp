"""The DNS section says when a control went quiet, not only when a date comes due (F-16).

Before this, a source that stopped running, a disabled connector and a deactivated
domain were all indistinguishable from a healthy quiet domain: the monitor aged and
the page showed ``stale`` to whoever happened to open it. These tests pin the
sweep's contract - one warning per staleness episode, on the ordinary aggregated
delivery path, carrying a severity so the message itself says how urgent it is -
and the two properties that keep it from being noise: a healthy control is silent,
and a control that is checked successfully again may warn again the next time it
goes quiet.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import Module
from app.models.asset import Asset, AssetType
from app.models.dns_expiry_monitor import DNSExpiryMonitor
from app.services.dns_expiry_service import queue_stale_monitor_alerts
from app.services.dns_security_service import ingest_dns_observations

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
#: One freshness window: the ordinary gap between two checks of a control.
WINDOW = timedelta(hours=settings.DNS_EXPIRY_MAX_AGE_HOURS)


async def control(db, *, windows_quiet: float = 2.5, subject: str = "example.com") -> DNSExpiryMonitor:
    """One registration control whose last check is ``windows_quiet`` windows old."""
    db.add(Asset(asset_type=AssetType.domain, asset_value=subject, normalized_value=subject, is_active=True))
    await db.commit()
    await ingest_dns_observations(
        db,
        source="rdap",
        findings=[{
            "observation_type": "rdap",
            "subject": subject,
            "expires_at": (NOW + timedelta(days=200)).isoformat(),
            "metadata": {},
        }],
    )
    row = (await db.execute(select(DNSExpiryMonitor))).scalar_one()
    quiet = NOW - timedelta(hours=settings.DNS_EXPIRY_MAX_AGE_HOURS * windows_quiet)
    row.checked_at = quiet
    row.successful_at = quiet
    await db.commit()
    return row


def enqueue(monkeypatch, returning=object()):
    mock = AsyncMock(return_value=returning)
    monkeypatch.setattr("app.services.dns_expiry_service.AlertDeliveryService.enqueue", mock)
    return mock


@pytest.mark.asyncio
async def test_a_control_checked_for_a_healthy_check_is_silent(db_session, monkeypatch):
    """One missed window is the ordinary gap between two daily scans, not news."""
    await control(db_session, windows_quiet=1)
    mock = enqueue(monkeypatch)
    assert await queue_stale_monitor_alerts(db_session, now=NOW) == 0
    mock.assert_not_called()


@pytest.mark.asyncio
async def test_a_quiet_control_warns_once_with_its_severity(db_session, monkeypatch):
    row = await control(db_session)
    mock = enqueue(monkeypatch)
    assert await queue_stale_monitor_alerts(db_session, now=NOW) == 1
    details = mock.await_args.kwargs["details"]
    assert mock.await_args.kwargs["threat_type"] == "dns"
    assert details["severity"] == "warning"
    assert "96 hours" in details["title"]
    assert details["fields"]["Subject"] == "example.com"
    assert details["fields"]["Last successful check (UTC)"] == row.successful_at.replace(tzinfo=timezone.utc).isoformat()
    # The second sweep of the same quiet control is silence, not a second warning.
    assert await queue_stale_monitor_alerts(db_session, now=NOW) == 0
    assert mock.await_count == 1


@pytest.mark.asyncio
async def test_a_successful_check_reopens_the_staleness_episode(db_session, monkeypatch):
    from app.services.dns_expiry_monitor_service import update_monitor
    from app.models.dns_observation import DNSObservation

    row = await control(db_session)
    enqueue(monkeypatch)
    assert await queue_stale_monitor_alerts(db_session, now=NOW) == 1
    observation = await db_session.get(DNSObservation, row.observation_id)
    observation.expires_at = NOW + timedelta(days=201)
    await update_monitor(db_session, observation, now=NOW)
    await db_session.commit()
    assert row.stale_alerted_at is None
    # A control that went quiet again is owed a fresh warning.
    row.checked_at = row.successful_at = NOW - 3 * WINDOW
    await db_session.commit()
    assert await queue_stale_monitor_alerts(db_session, now=NOW) == 1


@pytest.mark.asyncio
async def test_no_channel_keeps_the_warning_owed(db_session, monkeypatch):
    """Without a destination nothing is queued, so nothing was told to anybody."""
    row = await control(db_session)
    mock = enqueue(monkeypatch, returning=None)
    assert await queue_stale_monitor_alerts(db_session, now=NOW) == 0
    assert row.stale_alerted_at is None
    mock.return_value = object()
    assert await queue_stale_monitor_alerts(db_session, now=NOW) == 1


@pytest.mark.asyncio
async def test_a_retired_or_disabled_control_is_not_noise(db_session, monkeypatch):
    row = await control(db_session)
    mock = enqueue(monkeypatch)
    (await db_session.get(Asset, row.asset_id)).is_active = False
    await db_session.commit()
    assert await queue_stale_monitor_alerts(db_session, now=NOW) == 0
    (await db_session.get(Asset, row.asset_id)).is_active = True
    (await db_session.get(Module, "dns")).enabled = False
    await db_session.commit()
    assert await queue_stale_monitor_alerts(db_session, now=NOW) == 0
    mock.assert_not_called()
