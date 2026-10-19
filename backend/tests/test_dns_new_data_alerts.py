"""Alerts on DNS *arrivals*, not only on expiry dates (F-01 in the DNS & TLS audit).

The section used to have exactly one alert source - the expiry sweep - so a
certificate that appeared for a monitored name, a served certificate that changed
and a record set that changed were visible only to an analyst who happened to open
the page. These tests pin the three arrival rules, the property that matters most
about them (a change is reported exactly once, and a re-observation of the same fact
is silence), and the fact that they travel the ordinary outbox path: an operator
sees them in the same aggregated message as everything else this installation sends.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.models import Connector, IngestionEvent
from app.services.ingestion_events import dispatch_notification_events
from app.services.ingestion_service import ingest_findings

NOW = datetime.now(timezone.utc)


def certificate(fingerprint: str = "fp-a") -> dict:
    return {
        "observation_type": "tls_certificate",
        "subject": "example.com",
        "value": "example.com",
        "expires_at": (NOW + timedelta(days=90)).isoformat(),
        "status": "current",
        "metadata": {
            "id": fingerprint,
            "fingerprint_sha256": fingerprint,
            "not_before": (NOW - timedelta(days=1)).isoformat(),
            "evidence": "active_tls_probe",
        },
    }


def probe(fingerprint: str = "fp-a") -> dict:
    return {
        "observation_type": "tls_probe",
        "subject": "example.com",
        "record_type": "TLS",
        "expires_at": (NOW + timedelta(days=10)).isoformat(),
        "status": "current",
        "metadata": {
            "check_state": "verified",
            "checked_at": NOW.isoformat(),
            "certificate_id": fingerprint,
            "not_before": (NOW - timedelta(days=30)).isoformat(),
            "probe_ip": "203.0.113.9",
            "port": 443,
        },
    }


def registration(statuses=None, secure_dns=None) -> dict:
    metadata = {"provider": "rdap"}
    if statuses is not None:
        metadata["epp_status"] = statuses
    if secure_dns is not None:
        metadata["secure_dns"] = secure_dns
    return {
        "observation_type": "rdap",
        "subject": "example.com",
        "record_type": "RDAP",
        "value": "example.com",
        "expires_at": (NOW + timedelta(days=200)).isoformat(),
        "metadata": metadata,
    }


def record(address: str) -> dict:
    return {
        "observation_type": "dns_record",
        "subject": "example.com",
        "record_type": "A",
        "value": address,
        "metadata": {"record_values": [address], "ttl": 60, "source_domain": "example.com"},
    }


async def dns_connector(db, name: str = "dns-tlsprobe", aliases=None) -> Connector:
    connector = Connector(
        name=name,
        connector_type="dns",
        default_job_type="dns.tlsprobe",
        status="enabled",
        aliases=aliases or [name, name.replace("dns-", "") + "-dns-security-default"],
    )
    db.add(connector)
    await db.flush()
    return connector


async def feed(db, connector, finding: dict):
    result = await ingest_findings(db, connector=connector, job_id=None, findings=[finding])
    await db.commit()
    return result


async def notifications(db) -> list[IngestionEvent]:
    events = list((await db.execute(select(IngestionEvent))).scalars())
    return [event for event in events if event.kind == "notification"]


@pytest.mark.asyncio
async def test_a_new_certificate_is_one_arrival_and_a_replay_is_none(db_session):
    connector = await dns_connector(db_session)
    await feed(db_session, connector, certificate("fp-a"))
    first = await notifications(db_session)
    assert len(first) == 1
    assert first[0].payload["rule"] == "dns.certificate.new"
    assert first[0].payload["severity"] == "info"
    assert first[0].payload["Certificate ID"] == "fp-a"

    # The same certificate seen again (a rescan) is not an arrival.
    await feed(db_session, connector, certificate("fp-a"))
    assert len(await notifications(db_session)) == 1

    # A different certificate for the same name is.
    await feed(db_session, connector, certificate("fp-b"))
    assert len(await notifications(db_session)) == 2


@pytest.mark.asyncio
async def test_a_changed_served_certificate_carries_the_old_and_the_new_identity(db_session):
    connector = await dns_connector(db_session)
    await feed(db_session, connector, probe("fp-a"))
    assert await notifications(db_session) == []
    await feed(db_session, connector, probe("fp-b"))
    events = await notifications(db_session)
    assert len(events) == 1
    assert events[0].payload["rule"] == "dns.certificate.changed"
    assert events[0].payload["Previous certificate"] == "fp-a"
    assert events[0].payload["Current certificate"] == "fp-b"
    await feed(db_session, connector, probe("fp-b"))
    assert len(await notifications(db_session)) == 1, "a re-probe of the same certificate is silence"


@pytest.mark.asyncio
async def test_a_changed_record_reports_both_sets_of_values(db_session):
    connector = await dns_connector(db_session, name="dns-resolver", aliases=["dns-resolver", "resolver-dns-security-default"])
    await feed(db_session, connector, record("203.0.113.1"))
    assert await notifications(db_session) == []
    await feed(db_session, connector, record("203.0.113.2"))
    events = await notifications(db_session)
    assert len(events) == 1
    assert events[0].payload["rule"] == "dns.record.changed"
    assert events[0].payload["Previous values"] == "203.0.113.1"
    assert events[0].payload["Current values"] == "203.0.113.2"
    await feed(db_session, connector, record("203.0.113.2"))
    assert len(await notifications(db_session)) == 1


@pytest.mark.asyncio
async def test_a_weakened_dmarc_policy_is_an_arrival(db_session):
    """The mail posture is a record like any other, under the name that carries it (F-08)."""
    connector = await dns_connector(
        db_session, name="dns-resolver", aliases=["dns-resolver", "resolver-dns-security-default"]
    )

    def dmarc(policy: str) -> dict:
        return {
            "observation_type": "dns_record",
            "subject": "_dmarc.example.com",
            "record_type": "TXT",
            "value": policy,
            "metadata": {"record_values": [policy], "ttl": 300, "source_domain": "example.com"},
        }

    await feed(db_session, connector, dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@example.com"))
    assert await notifications(db_session) == [], "the first policy is a baseline"
    await feed(db_session, connector, dmarc("v=DMARC1; p=none"))
    events = await notifications(db_session)
    assert len(events) == 1
    assert events[0].payload["rule"] == "dns.record.changed"
    assert events[0].payload["host"] == "_dmarc.example.com"
    assert events[0].payload["Record"] == "TXT"
    assert "p=reject" in events[0].payload["Previous values"]
    assert events[0].payload["Current values"] == "v=DMARC1; p=none"


@pytest.mark.asyncio
async def test_a_registration_hold_is_a_high_arrival_and_a_removed_lock_is_informational(db_session):
    """R5: the registration source is read as a registration, not only as a date (F-07)."""
    connector = await dns_connector(
        db_session, name="dns-rdap", aliases=["dns-rdap", "rdap-dns-security-default"]
    )
    await feed(db_session, connector, registration(["client transfer prohibited"], secure_dns=False))
    assert await notifications(db_session) == [], "the first answer is a baseline, not a transition"

    await feed(db_session, connector, registration(["client transfer prohibited", "client hold"], secure_dns=False))
    held = await notifications(db_session)
    assert len(held) == 1
    assert held[0].payload["rule"] == "dns.registration.status"
    assert held[0].payload["severity"] == "high"
    assert "clienthold" in held[0].payload["Status added"]
    assert held[0].payload["Registration status"].startswith("clienthold; ")

    # Losing the transfer lock is what makes a hijack possible, and it is quieter.
    await feed(db_session, connector, registration(["client hold"], secure_dns=False))
    quiet = [event for event in await notifications(db_session) if event.id != held[0].id]
    assert len(quiet) == 1
    assert quiet[0].payload["severity"] == "info"
    assert "lock removed" in quiet[0].payload["title"]
    assert quiet[0].payload["Status removed"] == "clienttransferprohibited"

    # The same answer again is not a second transition.
    await feed(db_session, connector, registration(["client hold"], secure_dns=False))
    assert len(await notifications(db_session)) == 2


@pytest.mark.asyncio
async def test_a_dnssec_change_is_informational_and_a_silent_registry_is_silence(db_session):
    connector = await dns_connector(
        db_session, name="dns-rdap", aliases=["dns-rdap", "rdap-dns-security-default"]
    )
    await feed(db_session, connector, registration(["client transfer prohibited"], secure_dns=True))
    await feed(db_session, connector, registration(["client transfer prohibited"], secure_dns=False))
    events = await notifications(db_session)
    assert len(events) == 1
    assert events[0].payload["severity"] == "info"
    assert events[0].payload["DNSSEC delegation signed"] == "no"
    assert "DNSSEC" in events[0].payload["title"]

    # A registry that answers without `status`/`secureDNS` says nothing about the
    # registration, and an absent answer must not be read as a removal.
    silent = registration()
    silent["expires_at"] = (NOW + timedelta(days=201)).isoformat()
    await feed(db_session, connector, silent)
    assert len(await notifications(db_session)) == 1


@pytest.mark.asyncio
async def test_an_arrival_reaches_the_alert_queue_as_a_dns_notification(db_session, monkeypatch):
    """The whole point of an outbox row: it becomes a delivery without a second path."""
    connector = await dns_connector(db_session)
    await feed(db_session, connector, certificate("fp-a"))
    enqueue = AsyncMock(return_value=object())
    monkeypatch.setattr("app.services.ingestion_events.AlertDeliveryService.enqueue", enqueue)
    assert await dispatch_notification_events(db_session) == 1
    assert enqueue.await_args.kwargs["threat_type"] == "dns"
    details = enqueue.await_args.kwargs["details"]
    assert details["rule"] == "dns.certificate.new" and details["severity"] == "info"


def test_the_subject_says_how_urgent_a_batch_is_when_the_module_grades_it():
    from app.services.alert_service import _highest_severity

    assert _highest_severity([{"severity": "info"}, {"severity": "high"}]) == "high"
    assert _highest_severity([{"severity": "warning"}]) == "warning"
    assert _highest_severity([{"severity": "unheard-of"}]) is None
    # A module that reports no severity keeps the subject it always had.
    assert _highest_severity([{"phishing_domain": "evil.example"}]) is None
