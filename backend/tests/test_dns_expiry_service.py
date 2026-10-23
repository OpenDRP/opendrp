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


def tls_probe(port: int, days: float, certificate: str, *, host: str = "example.com") -> dict:
    """The active probe's control row, for one host and one port."""
    return {
        "observation_type": "tls_probe",
        "subject": host,
        "record_type": "TLS" if port == 443 else f"TLS:{port}",
        "expires_at": (NOW + timedelta(days=days)).isoformat(),
        "metadata": {
            "check_state": "verified",
            "checked_at": NOW.isoformat(),
            "certificate_id": certificate,
            "not_before": (NOW - timedelta(days=30)).isoformat(),
            "probe_ip": "203.0.113.10",
            "port": port,
        },
    }


async def control(db, days=10, kind="registration"):
    db.add(Asset(asset_type=AssetType.domain, asset_value="example.com", normalized_value="example.com", is_active=True))
    await db.commit()
    payload = {"observation_type": "rdap" if kind == "registration" else "certificate_check", "subject": "example.com", "expires_at": (NOW + timedelta(days=days)).isoformat(), "metadata": {} if kind == "registration" else {"check_state": "verified", "certificate_id": "cert-a", "not_before": (NOW - timedelta(days=30)).isoformat()}}
    await ingest_dns_observations(db, source="rdap" if kind == "registration" else "ctlogs", findings=[payload])
    row = (await db.execute(select(DNSExpiryMonitor))).scalar_one()
    row.checked_at = row.successful_at = NOW
    await db.commit()
    return row


@pytest.mark.asyncio
async def test_two_ports_keep_two_controls_with_their_own_reminder_history(db_session):
    """AUD-036: the control is keyed by asset *and port*.

    Every probe row became `kind="tls"`, and the unique key is (asset, kind), so
    the second port overwrote the first control and reset the thresholds it had
    already sent. Two verified ports are two controls, each with its own history.
    """
    db_session.add(Asset(asset_type=AssetType.domain, asset_value="example.com", normalized_value="example.com", is_active=True))
    await db_session.commit()
    await ingest_dns_observations(db_session, source="tlsprobe", findings=[tls_probe(443, 10, "cert-a")])
    first = (await db_session.execute(select(DNSExpiryMonitor).where(DNSExpiryMonitor.kind == "tls:443"))).scalar_one()
    first.checked_at = first.successful_at = NOW
    first.alerted_thresholds = [14]
    await db_session.commit()

    await ingest_dns_observations(db_session, source="tlsprobe", findings=[tls_probe(8443, 3, "cert-b")])

    rows = list((await db_session.execute(select(DNSExpiryMonitor).order_by(DNSExpiryMonitor.kind))).scalars())
    assert [row.kind for row in rows] == ["tls:443", "tls:8443"]
    assert [row.certificate_id for row in rows] == ["cert-a", "cert-b"]
    # The first port's reminder was not re-queued by the second port's control.
    assert rows[0].alerted_thresholds == [14]
    assert rows[1].alerted_thresholds == []


@pytest.mark.asyncio
async def test_a_control_from_before_the_port_dimension_is_adopted_once(db_session):
    """AUD-036's backfill: the legacy row is renamed, not duplicated or discarded."""
    db_session.add(Asset(asset_type=AssetType.domain, asset_value="example.com", normalized_value="example.com", is_active=True))
    await db_session.commit()
    await ingest_dns_observations(db_session, source="tlsprobe", findings=[tls_probe(8443, 10, "cert-a")])
    row = (await db_session.execute(select(DNSExpiryMonitor))).scalar_one()
    # The shape an installation built before this change holds.
    row.kind = "tls"
    row.alerted_thresholds = [30]
    await db_session.commit()

    for _ in range(2):
        await ingest_dns_observations(db_session, source="tlsprobe", findings=[tls_probe(8443, 10, "cert-a")])

    rows = list((await db_session.execute(select(DNSExpiryMonitor))).scalars())
    assert [(item.kind, item.certificate_id, item.alerted_thresholds) for item in rows] == [
        ("tls:8443", "cert-a", [30])
    ]


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
async def test_one_refused_control_row_does_not_cost_the_batch(db_session):
    """A control the monitor refuses must not take the scan's evidence with it.

    The refusal itself is right: a `verified` handshake whose certificate is not valid
    yet is a row the platform cannot trust, and the worker has its own `future_only`
    state for that fact. What was wrong was where the refusal landed — the ValueError
    escaped `update_monitor` into `ingest_dns_observations`, which is the one call that
    stores the whole scan, so a single row whose `not_before` sits minutes ahead of the
    core's clock (a worker that runs ahead of the platform) cost every observation of
    that scan and failed the connector's job.
    """
    real_now = datetime.now(timezone.utc)
    db_session.add(Asset(asset_type=AssetType.domain, asset_value="example.com", normalized_value="example.com", is_active=True))
    await db_session.commit()
    good = {
        "observation_type": "tls_probe",
        "subject": "example.com",
        "record_type": "TLS",
        "expires_at": (real_now + timedelta(days=10)).isoformat(),
        "metadata": {
            "check_state": "verified",
            "certificate_id": "cert-a",
            "not_before": (real_now - timedelta(days=5)).isoformat(),
            "checked_at": real_now.isoformat(),
            "port": 443,
        },
    }
    ahead = {
        "observation_type": "tls_probe",
        "subject": "example.com",
        "record_type": "TLS:8443",
        "expires_at": (real_now + timedelta(days=400)).isoformat(),
        "metadata": {
            **good["metadata"],
            "certificate_id": "cert-b",
            "not_before": (real_now + timedelta(hours=1)).isoformat(),
            "port": 8443,
        },
    }

    await ingest_dns_observations(db_session, source="tlsprobe", findings=[good, ahead])

    stored = list((await db_session.execute(select(DNSObservation))).scalars())
    assert {row.record_type for row in stored} == {"TLS", "TLS:8443"}
    monitor = (await db_session.execute(select(DNSExpiryMonitor))).scalar_one()
    assert monitor.state == "verified"
    assert monitor.expires_at is not None


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
