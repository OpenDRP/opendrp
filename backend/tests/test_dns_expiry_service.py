from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from app.models.asset import Asset, AssetType
from app.models.module import Module
from app.models.dns_expiry_monitor import DNSExpiryMonitor
from app.services.dns_security_service import ingest_dns_observations
from app.services.dns_expiry_monitor_service import update_monitor
from app.models.dns_observation import DNSObservation
from app.services.dns_expiry_service import due_threshold, queue_expiry_alerts

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


async def control(db, days=10, kind="registration"):
    db.add(Asset(asset_type=AssetType.domain, asset_value="example.com", normalized_value="example.com", is_active=True))
    await db.commit()
    payload = {"observation_type": "rdap" if kind == "registration" else "certificate_check", "subject": "example.com", "expires_at": (NOW + timedelta(days=days)).isoformat(), "metadata": {} if kind == "registration" else {"check_state": "verified", "certificate_id": "cert-a", "not_before": (NOW - timedelta(days=30)).isoformat()}}
    await ingest_dns_observations(db, source="rdap" if kind == "registration" else "ctlogs", findings=[payload])
    row = (await db.execute(select(DNSExpiryMonitor))).scalar_one()
    row.checked_at = row.successful_at = NOW
    await db.commit()
    return row


@pytest.mark.parametrize("days,threshold", [(31,None),(30,30),(14.01,30),(14,14),(7,7),(3,3),(1,1),(0,0),(-1,0)])
def test_threshold_boundaries(days, threshold):
    assert due_threshold(NOW + timedelta(days=days), NOW) == threshold


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["registration", "certificate"])
async def test_nearest_threshold_dedup_and_truthful_title(db_session, monkeypatch, kind):
    row = await control(db_session, kind=kind)
    enqueue = AsyncMock(return_value=object())
    monkeypatch.setattr("app.services.dns_expiry_service.AlertDeliveryService.enqueue", enqueue)
    assert await queue_expiry_alerts(db_session, now=NOW) == 1
    assert row.alerted_thresholds == [14]
    assert "10 day" in enqueue.call_args.kwargs["details"]["title"]
    assert await queue_expiry_alerts(db_session, now=NOW) == 0


@pytest.mark.asyncio
async def test_no_channel_does_not_consume_threshold(db_session, monkeypatch):
    row = await control(db_session)
    enqueue = AsyncMock(return_value=None)
    monkeypatch.setattr("app.services.dns_expiry_service.AlertDeliveryService.enqueue", enqueue)
    assert await queue_expiry_alerts(db_session, now=NOW) == 0
    assert row.alerted_thresholds == []
    enqueue.return_value = object()
    assert await queue_expiry_alerts(db_session, now=NOW) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["inactive", "stale", "failed", "disabled", "deleted_evidence"])
async def test_non_alertable_state_is_excluded(db_session, monkeypatch, reason):
    row = await control(db_session)
    if reason == "inactive":
        (await db_session.get(Asset, row.asset_id)).is_active = False
    elif reason == "stale":
        row.successful_at = NOW - timedelta(hours=49)
    elif reason == "failed":
        row.state = "failed"
    elif reason == "disabled":
        (await db_session.get(Module,"dns")).enabled = False
    else:
        row.observation_id = None
    await db_session.commit()
    enqueue = AsyncMock(return_value=object())
    monkeypatch.setattr("app.services.dns_expiry_service.AlertDeliveryService.enqueue", enqueue)
    assert await queue_expiry_alerts(db_session, now=NOW) == 0
    enqueue.assert_not_called()


@pytest.mark.asyncio
async def test_expired_is_once_and_registration_renewal_resets_cycle(db_session, monkeypatch):
    row = await control(db_session, days=-1)
    monkeypatch.setattr("app.services.dns_expiry_service.AlertDeliveryService.enqueue", AsyncMock(return_value=object()))
    assert await queue_expiry_alerts(db_session, now=NOW) == 1
    assert row.alerted_thresholds == [0]
    assert await queue_expiry_alerts(db_session, now=NOW) == 0
    observation = await db_session.get(DNSObservation, row.observation_id)
    observation.expires_at = NOW + timedelta(days=3)
    await update_monitor(db_session, observation, now=NOW)
    await db_session.commit()
    assert row.alerted_thresholds == []
    assert await queue_expiry_alerts(db_session, now=NOW) == 1
    assert row.alerted_thresholds == [3]


@pytest.mark.asyncio
async def test_certificate_replacement_failed_check_and_future_rejection(db_session):
    row = await control(db_session, kind="certificate")
    row.alerted_thresholds = [14]
    observation = await db_session.get(DNSObservation,row.observation_id)
    observation.metadata_json = {**observation.metadata_json,"check_state":"failed"}
    await update_monitor(db_session,observation,now=NOW)
    assert row.state == "failed" and row.alerted_thresholds == [14]
    observation.metadata_json = {"check_state":"verified","certificate_id":"cert-b","not_before":(NOW-timedelta(days=1)).isoformat()}
    await update_monitor(db_session,observation,now=NOW)
    assert row.certificate_id == "cert-b" and row.alerted_thresholds == []
    observation.metadata_json = {**observation.metadata_json,"not_before":(NOW+timedelta(days=1)).isoformat()}
    with pytest.raises(ValueError,match="invalid selected"):
        await update_monitor(db_session,observation,now=NOW)


@pytest.mark.asyncio
async def test_enqueue_failure_rolls_back_delivery_and_threshold(db_session, monkeypatch):
    from app.models.alert_delivery import AlertDelivery
    row = await control(db_session)
    async def fail(self, **kwargs):
        self.db.add(AlertDelivery(threat_type="dns_security", channel="smtp", target="test@example.com", payload=kwargs["details"], status="pending"))
        await self.db.flush()
        raise RuntimeError("queue write failed")
    monkeypatch.setattr("app.services.dns_expiry_service.AlertDeliveryService.enqueue",fail)
    with pytest.raises(RuntimeError,match="queue write failed"):
        await queue_expiry_alerts(db_session,now=NOW)
    await db_session.rollback()
    await db_session.refresh(row)
    assert row.alerted_thresholds == []
    assert list((await db_session.execute(select(AlertDelivery))).scalars()) == []


@pytest.mark.asyncio
async def test_ttl_and_discovery_do_not_create_monitors(db_session):
    db_session.add(Asset(asset_type=AssetType.domain,asset_value="example.com",normalized_value="example.com"))
    await db_session.commit()
    await ingest_dns_observations(db_session,source="resolver",findings=[{"subject":"example.com","observation_type":"dns_record","expires_at":NOW.isoformat()}])
    await ingest_dns_observations(db_session,source="ctlogs",findings=[{"subject":"example.com","observation_type":"certificate","expires_at":NOW.isoformat(),"metadata":{"id":"historical"}}])
    assert list((await db_session.execute(select(DNSExpiryMonitor))).scalars()) == []
