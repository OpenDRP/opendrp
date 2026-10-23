from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.models.dns_observation import DNSObservation
from app.schemas.connector import DNSObservationPayload
from app.services.dns_expiry_service import queue_expiry_alerts
from app.services.dns_security_service import ingest_dns_observations, observation_key


def test_dns_observation_payload_normalizes_idna_and_rejects_bad_hostnames():
    payload = DNSObservationPayload.model_validate(
        {
            "observation_type": "dns_record",
            "subject": "WWW.Example.COM.",
            "record_type": "a",
            "value": "203.0.113.4",
        }
    )
    assert payload.subject == "www.example.com"
    assert payload.record_type == "A"
    with pytest.raises(ValidationError):
        DNSObservationPayload.model_validate(
            {"observation_type": "dns_record", "subject": "https://example.com/path"}
        )
    with pytest.raises(ValidationError):
        DNSObservationPayload.model_validate(
            {"observation_type": "dns_record", "subject": "singlelabel"}
        )
    # RFC 8552 service labels address records that are not hostnames - the DMARC
    # policy, a DKIM selector, an ACME challenge - so they are names, while an
    # underscore anywhere else is still refused.
    assert DNSObservationPayload.model_validate(
        {"observation_type": "dns_record", "subject": "_DMARC.Example.COM.", "record_type": "TXT"}
    ).subject == "_dmarc.example.com"
    for rejected in ("_dmarc", "example._dmarc", "a_b.example.com", "_dmarc._tcp"):
        with pytest.raises(ValidationError):
            DNSObservationPayload.model_validate(
                {"observation_type": "dns_record", "subject": rejected}
            )


@pytest.mark.asyncio
async def test_vt_domain_reputation_refreshes_in_place_and_keeps_the_flag(db_session):
    """F-09: the provider's reputation is a current fact, not one row per scan."""
    def observation(reputation: int, malicious: int) -> dict:
        return {
            "observation_type": "vt_domain",
            "subject": "example.com",
            "value": "example.com",
            "status": "current",
            "metadata": {
                "evidence": "virustotal_domain_reputation",
                "source_domain": "example.com",
                "reputation": reputation,
                "analysis_malicious": malicious,
                "analysis_suspicious": 0,
                "analysis_harmless": 70,
                "categories": ["Sophos: government"],
                "certificate_fingerprint_sha256": "ab" * 32,
            },
        }

    async def stored() -> list[DNSObservation]:
        # The upsert is a Core statement, so the read asks for the stored row rather
        # than the identity map's copy of it.
        return list((await db_session.execute(select(DNSObservation).execution_options(populate_existing=True))).scalars())

    assert await ingest_dns_observations(db_session, source="virustotal", findings=[observation(0, 0)]) == 1
    rows = await stored()
    assert len(rows) == 1 and rows[0].metadata_json["reputation"] == 0
    assert rows[0].metadata_json["certificate_fingerprint_sha256"] == "ab" * 32

    assert await ingest_dns_observations(db_session, source="virustotal", findings=[observation(-40, 4)]) == 1
    rows = await stored()
    assert len(rows) == 1, "a re-scan refreshes the reputation row instead of accumulating one per scan"
    assert rows[0].metadata_json["reputation"] == -40
    assert rows[0].metadata_json["analysis_malicious"] == 4


@pytest.mark.asyncio
async def test_observation_refresh_preserves_first_seen_and_updates_source_state(
    db_session,
):
    initial = {
        "observation_type": "dns_record",
        "subject": "www.example.com",
        "record_type": "A",
        "value": "203.0.113.10",
        "metadata": {"ttl": 60},
    }
    assert (
        await ingest_dns_observations(db_session, source="resolver", findings=[initial])
        == 1
    )
    first = (await db_session.execute(select(DNSObservation))).scalar_one()
    first_seen = first.first_seen_at
    assert first.metadata_json == {"ttl": 60}

    updated = {**initial, "metadata": {"ttl": 120}}
    assert (
        await ingest_dns_observations(db_session, source="resolver", findings=[updated])
        == 1
    )
    refreshed = (await db_session.execute(select(DNSObservation))).scalar_one()
    await db_session.refresh(refreshed)
    assert refreshed.first_seen_at == first_seen
    assert refreshed.last_seen_at >= first_seen
    assert refreshed.metadata_json == {"ttl": 120}
    assert refreshed.value == "203.0.113.10"
    assert refreshed.source == "resolver"

    changed = {**updated, "value": "203.0.113.11"}
    await ingest_dns_observations(db_session, source="resolver", findings=[changed])
    rows = list((await db_session.execute(select(DNSObservation))).scalars().all())
    assert len(rows) == 1
    await db_session.refresh(rows[0])
    assert rows[0].value == "203.0.113.11"
    assert rows[0].first_seen_at == first_seen


@pytest.mark.asyncio
async def test_refresh_leaves_the_registration_controls_history_alone(
    db_session,
):
    """The history belongs to the control, and a refresh does not erase it.

    This used to read a second copy on the observation, which nothing in the
    platform ever wrote: the only list that is ever appended is the monitor's
    (AUD-038). The guarantee is the same one; the row that owns it moved.
    """
    from app.models.asset import Asset, AssetType
    from app.models.dns_expiry_monitor import DNSExpiryMonitor

    db_session.add(
        Asset(
            asset_type=AssetType.domain,
            asset_value="example.com",
            normalized_value="example.com",
            is_active=True,
        )
    )
    await db_session.commit()
    payload = {
        "observation_type": "rdap",
        "subject": "example.com",
        "record_type": "RDAP",
        "value": "example.com",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=10)).isoformat(),
    }
    await ingest_dns_observations(db_session, source="rdap", findings=[payload])
    monitor = (await db_session.execute(select(DNSExpiryMonitor))).scalar_one()
    monitor.alerted_thresholds = [30]
    await db_session.commit()

    await ingest_dns_observations(db_session, source="rdap", findings=[payload])
    assert monitor.alerted_thresholds == [30]

    changed_expiry = {
        **payload,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=20)).isoformat(),
    }
    await ingest_dns_observations(db_session, source="rdap", findings=[changed_expiry])
    await db_session.refresh(monitor)
    assert monitor.alerted_thresholds == []


@pytest.mark.asyncio
async def test_expiry_alerts_use_rdap_expiry_and_only_mark_successfully_queued(
    db_session, monkeypatch
):
    from app.services import dns_expiry_service

    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rdap = DNSObservation(
        observation_key="a" * 64,
        observation_type="rdap",
        subject="example.com",
        record_type="RDAP",
        value="example.com",
        source="rdap",
        first_seen_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(days=10),
        status="current",
        metadata_json={},
    )
    dns = DNSObservation(
        observation_key="b" * 64,
        observation_type="dns_record",
        subject="example.com",
        record_type="A",
        value="192.0.2.1",
        source="resolver",
        first_seen_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(seconds=60),
        status="current",
        metadata_json={},
    )
    db_session.add_all([rdap, dns])
    await db_session.commit()

    from app.models.asset import Asset, AssetType
    from app.services.dns_expiry_monitor_service import update_monitor

    db_session.add(
        Asset(
            asset_type=AssetType.domain,
            asset_value="example.com",
            normalized_value="example.com",
        )
    )
    await db_session.commit()
    await update_monitor(db_session, rdap, now=now)
    await db_session.commit()
    calls = []

    async def no_channel(self, **kwargs):
        calls.append(kwargs)
        return None

    monkeypatch.setattr(dns_expiry_service.AlertDeliveryService, "enqueue", no_channel)
    assert await queue_expiry_alerts(db_session, now=now) == 0
    assert len(calls) == 1
    assert "domain registration expires in 10 day" in calls[0]["details"]["title"]
    from app.models.dns_expiry_monitor import DNSExpiryMonitor

    control = (await db_session.execute(select(DNSExpiryMonitor))).scalar_one()
    assert control.alerted_thresholds == []


@pytest.mark.asyncio
async def test_same_fact_from_independent_sources_is_not_overwritten(db_session):
    observation = {
        "observation_type": "dns_record",
        "subject": "example.com",
        "record_type": "A",
        "value": "203.0.113.10",
        "metadata": {},
    }
    await ingest_dns_observations(db_session, source="resolver", findings=[observation])
    await ingest_dns_observations(db_session, source="ctlogs", findings=[observation])
    rows = list((await db_session.execute(select(DNSObservation))).scalars().all())
    assert {row.source for row in rows} == {"resolver", "ctlogs"}


@pytest.mark.asyncio
async def test_duplicate_mutable_facts_in_one_batch_are_upserted_once(db_session):
    payload = {
        "observation_type": "rdap",
        "subject": "example.com",
        "value": "example.com",
        "metadata": {"registrar": "old"},
    }
    updated = {**payload, "metadata": {"registrar": "new"}}
    assert (
        await ingest_dns_observations(
            db_session, source="rdap", findings=[payload, updated]
        )
        == 1
    )
    row = (await db_session.execute(select(DNSObservation))).scalar_one()
    assert row.metadata_json["registrar"] == "new"


def test_ct_identity_uses_certificate_id_and_wildcard_scope_not_serial_alone():
    payload = {
        "observation_type": "certificate",
        "subject": "prod.egov.kz",
        "value": "egov.kz",
        "metadata": {"id": "cert-a", "serial_hex": "same", "wildcard": True},
    }
    another_cert = {**payload, "metadata": {**payload["metadata"], "id": "cert-b"}}
    concrete = {**payload, "metadata": {**payload["metadata"], "wildcard": False}}
    assert (
        len(
            {
                observation_key("ctlogs", row)
                for row in [payload, another_cert, concrete]
            }
        )
        == 3
    )


@pytest.mark.asyncio
async def test_passive_dns_same_ip_retains_independent_origin_domains(db_session):
    rows = [
        {
            "observation_type": "vt_resolution",
            "subject": "203.0.113.1",
            "value": domain,
            "status": "historical",
            "metadata": {"source_domain": domain},
        }
        for domain in ("one.test", "two.test")
    ]
    assert (
        await ingest_dns_observations(db_session, source="virustotal", findings=rows)
        == 2
    )
    persisted = list((await db_session.execute(select(DNSObservation))).scalars())
    assert {row.metadata_json["source_domain"] for row in persisted} == {
        "one.test",
        "two.test",
    }
    assert len(persisted) == 2


def test_passive_dns_distinct_resolution_dates_remain_distinct():
    payload = {
        "observation_type": "vt_resolution",
        "subject": "203.0.113.1",
        "value": "egov.kz",
        "metadata": {
            "source_domain": "egov.kz",
            "host_name": "egov.kz",
            "resolution_date": "100",
        },
    }
    other = {**payload, "metadata": {**payload["metadata"], "resolution_date": "200"}}
    assert observation_key("virustotal", payload) != observation_key(
        "virustotal", other
    )


def test_two_addresses_serving_one_certificate_stay_two_observations():
    """Where an endpoint was seen is part of the observation's identity.

    A provider asked "where else is this certificate served" names the same host at
    several addresses (a CDN name, a load balancer). Collapsing those rows would leave
    the projection with one sighting and hide the other address from the deployment
    rules, which score one address at a time.
    """
    payload = {
        "observation_type": "certificate_response",
        "subject": "edge.example.net",
        "record_type": "TLS",
        "value": "https://edge.example.net:443",
        "metadata": {"ip": "198.51.100.7", "port": 443, "fingerprint_sha256": "a" * 64},
    }
    other = {**payload, "metadata": {**payload["metadata"], "ip": "198.51.100.8"}}
    assert observation_key("shodan", payload) != observation_key("shodan", other)
    # A re-scan of the same endpoint is the same observation, not a second one.
    assert observation_key("shodan", payload) == observation_key(
        "shodan", {**payload, "status": "current"}
    )
    # A value the platform does not recognise as an address cannot split the identity
    # either: it is dropped, not used.
    bare = {**payload, "metadata": {k: v for k, v in payload["metadata"].items() if k != "ip"}}
    junk = {**payload, "metadata": {**payload["metadata"], "ip": "not-an-ip"}}
    assert observation_key("shodan", bare) == observation_key("shodan", junk)


def test_passive_dns_bounds_are_scoped_by_observation_window():
    first = {
        "observation_type": "passive_dns",
        "subject": "example.com",
        "record_type": "A",
        "value": "192.0.2.1",
        "metadata": {
            "source_domain": "example.com",
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-02T00:00:00Z",
        },
    }
    later = {
        **first,
        "metadata": {**first["metadata"], "last_seen": "2026-02-02T00:00:00Z"},
    }
    assert observation_key("netlas", first) != observation_key("netlas", later)


def test_existing_resolver_observation_identity_is_compatible():
    import hashlib
    import json

    payload = {
        "observation_type": "dns_record",
        "subject": "egov.kz",
        "record_type": "A",
        "value": "203.0.113.1",
    }
    legacy = {
        "source": "resolver",
        "type": "dns_record",
        "subject": "egov.kz",
        "record_type": "A",
        "value": None,
        "identity": None,
    }
    expected = hashlib.sha256(
        json.dumps(
            legacy, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
    ).hexdigest()
    assert observation_key("resolver", payload) == expected
