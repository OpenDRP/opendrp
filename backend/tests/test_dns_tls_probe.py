"""The active TLS probe as the core sees it: its own control kind and its wording.

The probe answers a different question than Certificate Transparency does - what a
service serves now, rather than what was issued - so it drives a monitor of its own
(`kind="tls"`), its reminders say so, and a failed or impossible handshake must
never become an alert. These are the properties an operator's trust in the
reminders rests on, and the ones a later edit is most likely to blur: a probe that
reuses the CT cycle would let a renewal restart the wrong countdown, and a probe
that alerts on `failed` would report "your certificate" for a host that was simply
unreachable.

`observation_key` is checked here too: the probe's control row is a *current fact*
(it must overwrite itself) while every certificate it reads is a separate identity
keyed by fingerprint, which is what makes "this is a new certificate for this host"
visible at all.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.models.asset import Asset, AssetType
from app.models.dns_expiry_monitor import DNSExpiryMonitor
from app.models.dns_observation import DNSObservation
from app.services.dns_expiry_monitor_service import utc
from app.services.dns_expiry_service import queue_expiry_alerts
from app.services.dns_security_service import ingest_dns_observations, observation_key

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def probe_row(*, days: float, check_state: str = "verified", certificate_id: str = "fp-a", port: int = 443) -> dict:
    metadata = {
        "check_state": check_state,
        "checked_at": NOW.isoformat(),
        "probe_ip": "203.0.113.9",
        "port": port,
        "verification": check_state if check_state != "verified" else "verified",
        "evidence": "active_tls_probe",
        "source_domain": "example.com",
        "lookup": "active_probe",
    }
    if check_state in {"verified", "expired"}:
        metadata.update({"certificate_id": certificate_id, "not_before": (NOW - timedelta(days=30)).isoformat()})
    return {
        "observation_type": "tls_probe",
        "subject": "example.com",
        "record_type": "TLS" if port == 443 else f"TLS:{port}",
        "expires_at": (NOW + timedelta(days=days)).isoformat(),
        "status": "current" if check_state == "verified" else "unknown",
        "metadata": metadata,
    }


async def ingest_probe(db, row: dict, *, source: str = "tlsprobe") -> DNSObservation:
    db.add(Asset(asset_type=AssetType.domain, asset_value="example.com", normalized_value="example.com", is_active=True))
    await db.commit()
    await ingest_dns_observations(db, source=source, findings=[row])
    return (await db.execute(select(DNSExpiryMonitor))).scalar_one()


@pytest.mark.asyncio
async def test_a_verified_probe_drives_its_own_monitor_kind(db_session):
    monitor = await ingest_probe(db_session, probe_row(days=10))
    assert monitor.kind == "tls"
    assert monitor.state == "verified"
    assert monitor.certificate_id == "fp-a"
    assert utc(monitor.expires_at) == NOW + timedelta(days=10)


@pytest.mark.asyncio
async def test_a_failed_probe_preserves_the_evidence_it_could_not_refresh(db_session):
    monitor = await ingest_probe(db_session, probe_row(days=10))
    before = (monitor.expires_at, monitor.certificate_id, monitor.cycle, list(monitor.alerted_thresholds))
    await ingest_dns_observations(db_session, source="tlsprobe", findings=[probe_row(days=10, check_state="failed")])
    assert monitor.state == "failed"
    # A handshake that failed says nothing about the certificate, so the cycle the
    # reminders count against must survive it.
    assert (monitor.expires_at, monitor.certificate_id, monitor.cycle, list(monitor.alerted_thresholds)) == before


@pytest.mark.asyncio
async def test_a_host_without_a_public_address_is_not_an_alert_base(db_session, monkeypatch):
    monitor = await ingest_probe(db_session, probe_row(days=5, check_state="skipped_no_public_address"))
    assert monitor.state == "skipped_no_public_address"
    enqueue = AsyncMock(return_value=object())
    monkeypatch.setattr("app.services.dns_expiry_service.AlertDeliveryService.enqueue", enqueue)
    assert await queue_expiry_alerts(db_session, now=NOW) == 0
    enqueue.assert_not_called()


@pytest.mark.asyncio
async def test_an_expired_handshake_alerts_at_threshold_zero_with_live_wording(db_session, monkeypatch):
    monitor = await ingest_probe(db_session, probe_row(days=-1, check_state="expired"))
    assert monitor.state == "expired"
    enqueue = AsyncMock(return_value=object())
    monkeypatch.setattr("app.services.dns_expiry_service.AlertDeliveryService.enqueue", enqueue)
    assert await queue_expiry_alerts(db_session, now=NOW) == 1
    details = enqueue.call_args.kwargs["details"]
    fields = details["fields"]
    assert details["module_label"] == "Live TLS certificate expiry"
    assert "live tls certificate" in details["title"]
    assert fields["Evidence"] == "Active TLS probe of the service (verified handshake)"
    assert fields["Probed address"] == "203.0.113.9"
    assert fields["Probed port"] == "443"
    assert fields["Certificate ID"] == "fp-a"
    assert monitor.alerted_thresholds == [0]


@pytest.mark.asyncio
async def test_a_certificate_transparency_reminder_still_says_it_is_passive(db_session, monkeypatch):
    """The two kinds must stay distinguishable in the message a recipient reads."""
    db_session.add(Asset(asset_type=AssetType.domain, asset_value="example.com", normalized_value="example.com", is_active=True))
    await db_session.commit()
    await ingest_dns_observations(db_session, source="ctlogs", findings=[{
        "observation_type": "certificate_check", "subject": "example.com",
        "expires_at": (NOW + timedelta(days=5)).isoformat(),
        "metadata": {"check_state": "verified", "checked_at": NOW.isoformat(), "certificate_id": "cert-a", "not_before": (NOW - timedelta(days=30)).isoformat()},
    }])
    enqueue = AsyncMock(return_value=object())
    monkeypatch.setattr("app.services.dns_expiry_service.AlertDeliveryService.enqueue", enqueue)
    assert await queue_expiry_alerts(db_session, now=NOW) == 1
    fields = enqueue.call_args.kwargs["details"]["fields"]
    assert fields["Evidence"] == "Passive CT evidence; deployment on the service is not verified"
    assert "Probed address" not in fields


def test_the_probe_control_row_is_a_current_fact_and_its_ports_are_identities():
    base = probe_row(days=10)
    key = observation_key("tlsprobe", base)
    changed_value = {**base, "value": "example.com:443", "expires_at": (NOW + timedelta(days=11)).isoformat()}
    assert observation_key("tlsprobe", changed_value) == key, "a re-probe must update its own row"
    other_port = {**base, "record_type": "TLS:8443"}
    assert observation_key("tlsprobe", other_port) != key, "443 and 8443 are different services"


def test_every_served_certificate_keeps_its_own_identity():
    base = {
        "observation_type": "tls_certificate", "subject": "example.com", "value": "example.com",
        "metadata": {"id": "fp-a", "fingerprint_sha256": "fp-a"},
    }
    assert observation_key("tlsprobe", base) != observation_key("tlsprobe", {**base, "metadata": {"id": "fp-b", "fingerprint_sha256": "fp-b"}})
