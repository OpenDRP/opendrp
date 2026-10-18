"""Design B: a certificate of ours, served somewhere that is not ours (WI-18, WI-21).

The scenario is a copied VM: the web server *and its private key* were deployed
elsewhere. The evidence is that the same certificate is served from a foreign address,
and the platform has to say so once, name the address and the signals, and stay quiet
after a human has judged it. These tests pin the projection from evidence to identity
and sighting, the three rules that can fire without a live provider key (R1 foreign
deployment, R2 key reuse, R3 issuance we did not make), the suppression paths
(exception, shared infrastructure, an existing verdict), and the requirement that
nothing is sent to the foreign host to confirm any of it.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import Connector, IngestionEvent
from app.models.asset import Asset, AssetType
from app.models.tls_certificate import (
    CertificateScopeException,
    TLSCertificateIdentity,
    TLSCertificateSighting,
)
from app.services.ingestion_service import ingest_findings
from app.services.tls_identity_service import (
    add_exception,
    evaluate_identities,
    identities_payload,
    project_observations,
    record_verdict,
    run_certificate_sweep,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

OUR_FINGERPRINT = "a" * 64
OUR_SPKI = "b" * 64
OUR_SERIAL = "0a1b2c"
OUR_IP = "203.0.113.10"


def probe_observation(host: str = "shop.example.com", when: datetime = NOW) -> dict:
    return {
        "observation_type": "tls_probe",
        "subject": host,
        "record_type": "TLS",
        "expires_at": (when + timedelta(days=60)).isoformat(),
        "metadata": {
            "check_state": "verified",
            "checked_at": when.isoformat(),
            "certificate_id": OUR_FINGERPRINT,
            "not_before": (when - timedelta(days=30)).isoformat(),
            "probe_ip": OUR_IP,
            "port": 443,
        },
    }


def certificate_observation(host: str = "shop.example.com", when: datetime = NOW) -> dict:
    """The chain member our own handshake read, which is where SPKI comes from."""
    return {
        "observation_type": "tls_certificate",
        "subject": host,
        "record_type": "TLS",
        "value": f"https://{host}",
        "expires_at": (when + timedelta(days=60)).isoformat(),
        "metadata": {
            "id": OUR_FINGERPRINT,
            "fingerprint_sha256": OUR_FINGERPRINT,
            "spki_sha256": OUR_SPKI,
            "serial_hex": OUR_SERIAL,
            "not_before": (when - timedelta(days=30)).isoformat(),
            "san_dns": [host],
            "issuer_dn": "CN=Example CA",
            "evidence": "active_tls_probe",
        },
    }


def provider_observation(
    *,
    source: str,
    fingerprint: str,
    ip: str,
    port: int | None = 443,
    when: datetime = NOW,
    signals: dict | None = None,
    subject: str | None = None,
    source_domain: str = "shop.example.com",
) -> dict:
    """A provider row: where an index says this certificate was seen.

    The subject is the host the provider reported (its hostname, or the address when it
    names none), and ``source_domain`` stays the asset the search was run for, which is
    what keeps the row attached to a monitored domain instead of looking orphaned.
    """
    host = subject or f"edge-{ip.replace('.', '-')}.example.com"
    metadata = {
        "ip": ip,
        "port": port,
        "fingerprint_sha256": fingerprint,
        "source_domain": source_domain,
        "not_before": (when - timedelta(days=30)).isoformat(),
        **(signals or {}),
    }
    return {
        "observation_type": "tls_certificate" if source == "netlas" else "hostname",
        "subject": host,
        "record_type": "TLS",
        "value": f"https://{host}",
        "status": "historical",
        "metadata": metadata,
    }


async def source(db, *, name: str, source: str) -> Connector:
    connector = Connector(
        name=name,
        connector_type="dns",
        default_job_type=f"dns.{source}",
        status="enabled",
        aliases=[name, f"{source}-dns-security-default"],
    )
    db.add(connector)
    await db.flush()
    return connector


async def feed(db, connector, findings):
    # ``hostname`` is a declared observation type of the generic DNS adapter path: it
    # arrives through the same ingestion route a provider worker uses.
    result = await ingest_findings(db, connector=connector, job_id=None, findings=findings)
    await db.commit()
    return result


async def project(db):
    await project_observations(db)
    await db.commit()


async def notifications(db) -> list[IngestionEvent]:
    """Design B's own alerts.

    Ingesting evidence also runs the module's arrival rules, so a "new certificate"
    event ((F-01)) is expected here and is not what these tests are about; the
    certificate-identity rules all report a `tls.` rule.
    """
    events = list((await db.execute(select(IngestionEvent))).scalars())
    return [
        event
        for event in events
        if event.kind == "notification" and str(event.payload.get("rule", "")).startswith("tls.")
    ]


@pytest.mark.asyncio
async def test_our_probe_projectes_one_identity_and_one_owned_sighting(db_session):
    probe = await source(db_session, name="dns-tlsprobe", source="tlsprobe")
    await feed(db_session, probe, [probe_observation(), certificate_observation()])
    await project(db_session)

    identities = list((await db_session.execute(select(TLSCertificateIdentity))).scalars())
    assert len(identities) == 1
    identity = identities[0]
    assert identity.fingerprint_sha256 == OUR_FINGERPRINT
    assert identity.spki_sha256 == OUR_SPKI
    assert identity.serial_hex == OUR_SERIAL
    assert identity.origin == "our_probe"
    assert identity.san_dns == ["shop.example.com"]

    sightings = list((await db_session.execute(select(TLSCertificateSighting))).scalars())
    assert len(sightings) == 1
    assert sightings[0].is_ours is True
    assert sightings[0].ip == OUR_IP
    assert sightings[0].port == 443
    # The same evidence projected twice refreshes rather than duplicates.
    await project(db_session)
    assert len(list((await db_session.execute(select(TLSCertificateSighting))).scalars())) == 1


@pytest.mark.asyncio
async def test_a_foreign_deployment_alerts_once_with_the_address_and_the_signals(db_session):
    probe = await source(db_session, name="dns-tlsprobe", source="tlsprobe")
    await feed(db_session, probe, [probe_observation(), certificate_observation()])
    shodan = await source(db_session, name="dns-shodan", source="shodan")
    await feed(
        db_session,
        shodan,
        [
            provider_observation(
                source="shodan",
                fingerprint=OUR_FINGERPRINT,
                ip="198.51.100.7",
                signals={"org": "Example Hosting LLC", "asn": 64500, "host_lookup_confirmed": True},
            )
        ],
    )
    netlas = await source(db_session, name="dns-netlas", source="netlas")
    await feed(
        db_session,
        netlas,
        [
            provider_observation(
                source="netlas", fingerprint=OUR_FINGERPRINT, ip="198.51.100.7", subject="shop.example.com"
            )
        ],
    )
    await project(db_session)
    result = await evaluate_identities(db_session, now=NOW)
    await db_session.commit()

    assert result["queued"]["R1"] == 1
    events = await notifications(db_session)
    assert len(events) == 1
    payload = events[0].payload
    assert events[0].module == "dns"
    assert payload["rule"] == "tls.certificate.foreign"
    assert payload["severity"] == "high"
    assert payload["Foreign address"] == "198.51.100.7"
    assert payload["Certificate fingerprint (SHA-256)"] == OUR_FINGERPRINT
    assert payload["Organisation"] == "Example Hosting LLC"
    # Two independent sources plus the confirming host lookup.
    assert payload["Confidence"] == "3"
    assert payload["Sources"] == "netlas, shodan"
    # Both provider rows are the same deployment, so both carry the group's verdict
    # and confidence rather than one of them alerting on its own.
    group = list(
        (
            await db_session.execute(
                select(TLSCertificateSighting).where(TLSCertificateSighting.ip == "198.51.100.7")
            )
        ).scalars()
    )
    assert {item.source for item in group} == {"shodan", "netlas"}
    assert all(item.verdict == "candidate" and item.confidence == 3 for item in group)
    assert all(item.signals["rules"] == ["R1"] for item in group)

    # A second sweep over unchanged evidence is silence: the outbox row is keyed by
    # what fired, not by when the sweep ran.
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R1"] == 0
    await db_session.commit()
    assert len(await notifications(db_session)) == 1


@pytest.mark.asyncio
async def test_an_address_we_own_is_not_foreign_and_a_reviewed_sighting_stays_quiet(db_session):
    db_session.add(Asset(asset_type=AssetType.ip_address, asset_value="198.51.100.7", normalized_value="198.51.100.7", is_active=True))
    probe = await source(db_session, name="dns-tlsprobe", source="tlsprobe")
    await feed(db_session, probe, [probe_observation(), certificate_observation()])
    shodan = await source(db_session, name="dns-shodan", source="shodan")
    await feed(
        db_session,
        shodan,
        [provider_observation(source="shodan", fingerprint=OUR_FINGERPRINT, ip="198.51.100.7")],
    )
    await project(db_session)
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R1"] == 0
    await db_session.commit()
    assert await notifications(db_session) == []
    sighting = (await db_session.execute(select(TLSCertificateSighting))).scalars().all()
    assert all(item.is_ours for item in sighting)

    # A foreign address a human has judged is not re-alerted either.
    netlas = await source(db_session, name="dns-netlas", source="netlas")
    await feed(
        db_session,
        netlas,
        [provider_observation(source="netlas", fingerprint=OUR_FINGERPRINT, ip="198.51.100.8")],
    )
    await project(db_session)
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R1"] == 1
    await db_session.commit()
    foreign = (
        await db_session.execute(
            select(TLSCertificateSighting).where(TLSCertificateSighting.ip == "198.51.100.8")
        )
    ).scalar_one()
    await record_verdict(db_session, sighting_id=foreign.id, verdict="expected", note="Customer CDN edge")
    await db_session.commit()
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R1"] == 0
    await db_session.commit()
    assert len(await notifications(db_session)) == 1


@pytest.mark.asyncio
async def test_a_scope_exception_and_shared_infrastructure_suppress_the_rule(db_session):
    probe = await source(db_session, name="dns-tlsprobe", source="tlsprobe")
    await feed(db_session, probe, [probe_observation(), certificate_observation()])
    netlas = await source(db_session, name="dns-netlas", source="netlas")
    netlas_findings = [
        provider_observation(
            source="netlas",
            fingerprint=OUR_FINGERPRINT,
            ip=f"198.51.100.{8 + index}",
            signals={"org": "Cloudflare, Inc.", "asn": 13335},
        )
        for index in range(5)
    ]
    await feed(db_session, netlas, netlas_findings)
    await project(db_session)

    # Five foreign addresses behind a CDN organisation are shared infrastructure, as
    # the plan's scoring says, and produce nothing.
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R1"] == 0
    await db_session.commit()
    verdicts = {item.verdict for item in (await db_session.execute(select(TLSCertificateSighting))).scalars()}
    assert verdicts == {"candidate", "shared_infrastructure"}
    assert await notifications(db_session) == []

    # An exception on the fingerprint keeps a genuine foreign deployment quiet, and a
    # person can see why.
    await add_exception(db_session, match_kind="fingerprint", match_value=OUR_FINGERPRINT, reason="Partner appliance")
    await db_session.commit()
    fresh = TLSCertificateSighting(
        identity_id=(await db_session.execute(select(TLSCertificateIdentity.id))).scalar_one(),
        subject="shop.example.com",
        ip="198.51.100.77",  # a host that is nobody's CDN

        port=443,
        source="shodan",
        observed_at=NOW,
        first_seen_at=NOW,
        last_seen_at=NOW,
        is_ours=False,
        signals={},
        verdict="candidate",
    )
    db_session.add(fresh)
    await db_session.commit()
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R1"] == 0
    await db_session.commit()
    assert await notifications(db_session) == []
    assert fresh.verdict == "expected"
    assert fresh.signals["exception"] == "fingerprint"
    assert (await db_session.execute(select(CertificateScopeException))).scalar_one().match_kind == "fingerprint"


@pytest.mark.asyncio
async def test_key_reuse_and_unexpected_issuance_are_their_own_findings(db_session):
    probe = await source(db_session, name="dns-tlsprobe", source="tlsprobe")
    await feed(db_session, probe, [probe_observation(), certificate_observation()])
    # A CT record for our name, issued after our own certificate, with the same SPKI
    # (the key was reused) and an issuer we have never seen for this name.
    ct = await source(db_session, name="dns-ctlogs", source="ctlogs")
    await feed(
        db_session,
        ct,
        [
            {
                "observation_type": "certificate",
                "subject": "shop.example.com",
                "value": "shop.example.com",
                "status": "historical",
                "metadata": {
                    "id": "c" * 64,
                    "fingerprint_sha256": "c" * 64,
                    "spki_sha256": OUR_SPKI,
                    "issuer": "CN=Other CA",
                    "not_before": (NOW + timedelta(days=1)).isoformat(),
                    "source_domain": "shop.example.com",
                    "lookup": "exact",
                },
            }
        ],
    )
    await project(db_session)
    result = await evaluate_identities(db_session, now=NOW)
    await db_session.commit()

    assert result["queued"]["R2"] == 1 and result["queued"]["R3"] == 1
    payloads = {event.payload["rule"]: event.payload for event in await notifications(db_session)}
    assert payloads["tls.key.reuse"]["severity"] == "high"
    assert payloads["tls.key.reuse"]["Key (SPKI SHA-256)"] == OUR_SPKI
    assert "c" * 64 in payloads["tls.key.reuse"]["Certificates"]
    assert payloads["tls.certificate.unexpected"]["severity"] == "medium"
    assert payloads["tls.certificate.unexpected"]["Issuer"] == "CN=Other CA"
    assert payloads["tls.certificate.unexpected"]["Issuer known for this name"] == "no"
    assert "tls.sighting.confirmed_foreign" not in payloads

    # A certificate issued *before* the one we serve is history, not an incident.
    ct_late = TLSCertificateIdentity(
        fingerprint_sha256="d" * 64,
        origin="ct",
        # Issued before the certificate we serve: history, not an incident.
        not_before=NOW - timedelta(days=40),
        first_seen_at=NOW,
        last_seen_at=NOW,
        san_dns=[],
    )
    db_session.add(ct_late)
    await db_session.flush()
    db_session.add(
        TLSCertificateSighting(
            identity_id=ct_late.id,
            subject="shop.example.com",
            source="ctlogs",
            observed_at=NOW,
            first_seen_at=NOW,
            last_seen_at=NOW,
            is_ours=False,
            signals={},
            verdict="candidate",
        )
    )
    await db_session.commit()
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R3"] == 0


@pytest.mark.asyncio
async def test_the_sweep_and_the_triage_view_read_the_same_rows(db_session):
    probe = await source(db_session, name="dns-tlsprobe", source="tlsprobe")
    await feed(db_session, probe, [probe_observation(), certificate_observation()])
    shodan = await source(db_session, name="dns-shodan", source="shodan")
    await feed(
        db_session,
        shodan,
        [
            provider_observation(
                source="shodan",
                fingerprint=OUR_FINGERPRINT,
                ip="198.51.100.7",
                signals={"org": "Example Hosting LLC", "jarm": "29d29d00029d", "title": "Shop"},
            )
        ],
    )
    summary = await run_certificate_sweep(db_session, now=NOW)
    assert summary["identities"] == 1 and summary["sightings"] == 2
    assert summary["queued"]["R1"] == 1

    items, total = await identities_payload(db_session)
    assert total == 1 and len(items) == 1
    assert items[0]["fingerprint_sha256"] == OUR_FINGERPRINT
    assert items[0]["foreign_sightings"] == 1
    foreign = [item for item in items[0]["sightings"] if not item["is_ours"]]
    assert len(foreign) == 1
    assert foreign[0]["signals"]["jarm"] == "29d29d00029d"
    # The filters are the query's, so the total matches what was asked for.
    assert await identities_payload(db_session, foreign_only=True) == (items, 1)
    assert await identities_payload(db_session, verdict="expected") == ([], 0)


def host_lookup_observation(
    *, address: str = "203.0.113.25", fingerprint: str = OUR_FINGERPRINT, when: datetime = NOW
) -> dict:
    """A row in the shape the Shodan host lookup writes (WI-19).

    The keys are the ones the worker's own suite pins against this module's
    ``SIGNAL_KEYS``, so a rename on either side fails there rather than leaving a rule
    that reads a signal nothing writes.
    """
    return {
        "observation_type": "host_lookup",
        "subject": "shop.example.com",
        "record_type": "TLS:443",
        "value": address,
        "status": "historical",
        "metadata": {
            "evidence": "shodan_host_lookup",
            "lookup": "host_lookup",
            "source_domain": "shop.example.com",
            "ip": address,
            "port": 443,
            "host_lookup_confirmed": True,
            "org": "Example Hosting LLC",
            "asn": 64500,
            "jarm": "29d3fd00029d29d00042d43d00041d8f924f5255cbc229bc55efa16391da",
            "title": "Example Shop",
            "http_title": "Example Shop",
            "favicon_hash": 12345,
            "http_favicon_hash": 12345,
            "fingerprint_sha256": fingerprint,
            "not_before": (when - timedelta(days=30)).isoformat(),
            "not_after": (when + timedelta(days=60)).isoformat(),
        },
    }


def certificate_response_observation(
    *,
    address: str,
    port: int = 443,
    host: str = "edge.example.net",
    fingerprint: str = OUR_FINGERPRINT,
    confirmed: bool = True,
    when: datetime = NOW,
) -> dict:
    """A row in the shape the Shodan fingerprint search writes (WI-19)."""
    metadata = {
        "evidence": "shodan_certificate_response",
        "lookup": "certificate_search",
        "source_domain": "shop.example.com",
        "wildcard": False,
        "ip": address,
        "port": port,
        "fingerprint_sha256": fingerprint,
        "org": "Example Clone Hosting",
        "asn": 64501,
        "jarm": "29d3fd00029d29d00042d43d00041d8f924f5255cbc229bc55efa16391da",
        "matched_by": "searched_fingerprint",
        "not_before": (when - timedelta(days=30)).isoformat(),
    }
    if confirmed:
        metadata["host_lookup_confirmed"] = True
    return {
        "observation_type": "certificate_response",
        "subject": host,
        "record_type": "TLS",
        "value": f"https://{host}:{port}",
        "status": "historical",
        "metadata": metadata,
    }


@pytest.mark.asyncio
async def test_a_host_lookup_makes_a_certificate_ours_without_a_probe(db_session):
    """WI-19: the free provider read is the confirmation the rules were missing.

    Nothing here is an ``ip_address`` asset and no handshake has verified the address,
    so the only reason this evidence counts as ours is that the worker asks about
    addresses the platform itself names.
    """
    shodan = await source(db_session, name="dns-shodan", source="shodan")
    await feed(db_session, shodan, [host_lookup_observation()])
    await project(db_session)

    sighting = (await db_session.execute(select(TLSCertificateSighting))).scalar_one()
    assert sighting.is_ours is True
    assert sighting.ip == "203.0.113.25"
    assert sighting.signals["host_lookup_confirmed"] is True
    assert sighting.signals["jarm"].startswith("29d3fd")
    # A confirmation is not an alert: nothing is foreign yet.
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R1"] == 0
    await db_session.commit()
    assert await notifications(db_session) == []

    # The reverse answer: the same certificate is served from an address that is
    # nobody's asset, our own DNS does not name it, and no probe has reached it.
    await feed(db_session, shodan, [certificate_response_observation(address="198.51.100.7")])
    await project(db_session)
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R1"] == 1
    await db_session.commit()

    payloads = [event.payload for event in await notifications(db_session)]
    assert [payload["rule"] for payload in payloads] == ["tls.certificate.foreign"]
    payload = payloads[0]
    assert payload["Foreign address"] == "198.51.100.7"
    # One source, plus the confirmation the free lookup earned.
    assert payload["Confidence"] == "2"
    assert payload["Sources"] == "shodan"
    assert payload["Organisation"] == "Example Clone Hosting"


@pytest.mark.asyncio
async def test_only_a_confirmed_row_earns_the_confidence_bonus(db_session):
    """The bonus is a confirmation, not a source count.

    Two foreign addresses with the same number of observing sources, and the only
    difference between them is whether the index that reported the address stated which
    certificate it serves. Reporting an address must not read as confirming it.
    """
    shodan = await source(db_session, name="dns-shodan", source="shodan")
    await feed(db_session, shodan, [host_lookup_observation()])
    netlas = await source(db_session, name="dns-netlas", source="netlas")
    await feed(
        db_session,
        netlas,
        [
            provider_observation(source="netlas", fingerprint=OUR_FINGERPRINT, ip="198.51.100.9"),
            provider_observation(source="netlas", fingerprint=OUR_FINGERPRINT, ip="198.51.100.10"),
        ],
    )
    await feed(
        db_session,
        shodan,
        [certificate_response_observation(address="198.51.100.10")],
    )
    await project(db_session)
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R1"] == 2
    await db_session.commit()

    payloads = {payload["Foreign address"]: payload for payload in (event.payload for event in await notifications(db_session))}
    assert set(payloads) == {"198.51.100.9", "198.51.100.10"}
    # One source, no confirmation.
    assert payloads["198.51.100.9"]["Confidence"] == "1"
    assert payloads["198.51.100.9"]["Sources"] == "netlas"
    # Two sources, and the host lookup's confirmation on top of them.
    assert payloads["198.51.100.10"]["Confidence"] == "3"
    assert payloads["198.51.100.10"]["Sources"] == "netlas, shodan"
