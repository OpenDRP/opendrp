"""The parts of Design B a sweep-level test cannot reach on its own.

``test_tls_identities.py`` pins the scenarios an operator would recognise: a
certificate served from a foreign address, key reuse, an issuance we did not make.
This file covers the branches those scenarios depend on but do not visit: which
addresses the platform is allowed to call its own, which spellings of a fingerprint a
provider row may carry, the guard that keeps a provider-only certificate out of R1,
and the validation that decides whether a scope exception can ever apply.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.models import Connector, IngestionEvent
from app.models.dns_observation import DNSObservation
from app.models.tls_certificate import (
    CertificateScopeException,
    TLSCertificateIdentity,
    TLSCertificateSighting,
)
from app.services.tls_identity_service import (
    _as_list,
    _parse_moment,
    _text,
    _utc,
    add_exception,
    evaluate_identities,
    exceptions_payload,
    fingerprint_of,
    identities_payload,
    probed_addresses,
    project_observations,
    record_verdict,
    resolved_addresses,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
OUR_IP = "203.0.113.10"


def aware(value: datetime) -> datetime:
    """A stored moment, as UTC: SQLite hands back naive columns, PostgreSQL aware ones."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def observation(
    *,
    source: str,
    observation_type: str,
    subject: str,
    key: str | None = None,
    records: dict | None = None,
    value: str | None = None,
    record_type: str | None = None,
    expires_at: datetime | None = None,
) -> DNSObservation:
    return DNSObservation(
        observation_key=key or f"{uuid4().hex}{uuid4().hex}"[:64],
        observation_type=observation_type,
        subject=subject,
        record_type=record_type,
        value=value,
        source=source,
        first_seen_at=NOW - timedelta(days=1),
        last_seen_at=NOW,
        expires_at=expires_at,
        status="current",
        metadata_json=records or {},
    )


def identity(fingerprint: str, **kwargs) -> TLSCertificateIdentity:
    values = {
        "fingerprint_sha256": fingerprint,
        "origin": "our_probe",
        "first_seen_at": NOW - timedelta(days=30),
        "last_seen_at": NOW,
        "san_dns": ["shop.example.com"],
        "not_before": NOW - timedelta(days=30),
    }
    values.update(kwargs)
    return TLSCertificateIdentity(**values)


def sighting(row: TLSCertificateIdentity, **kwargs) -> TLSCertificateSighting:
    values = {
        "identity_id": row.id,
        "subject": "shop.example.com",
        "source": "shodan",
        "observed_at": NOW,
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "is_ours": False,
        "signals": {},
        "verdict": "candidate",
        "confidence": 0,
    }
    values.update(kwargs)
    return TLSCertificateSighting(**values)


def tls_notifications(events) -> list[IngestionEvent]:
    return [
        event
        for event in events
        if event.kind == "notification" and str(event.payload.get("rule", "")).startswith("tls.")
    ]


async def notifications(db) -> list[IngestionEvent]:
    return tls_notifications(list((await db.execute(select(IngestionEvent))).scalars()))


# ---------------------------------------------------------------------------
# The normalisation helpers, whose whole contract is what they answer for junk
# ---------------------------------------------------------------------------


def test_the_normalisation_helpers_state_their_fallbacks():
    """Each helper's answer for a missing or malformed value is the contract.

    They sit under every rule, so an exception here is a sweep that dies on a
    provider row rather than one that skips it: a naive datetime is read as UTC, an
    unparseable moment is *not* a moment, and a non-list of SANs is no SANs.
    """
    fallback = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert _utc(None, fallback) is fallback
    naive = datetime(2026, 1, 1, 12, 0)
    assert _utc(naive, fallback).tzinfo is timezone.utc and _utc(naive, fallback).hour == 12
    offset = timezone(timedelta(hours=5))
    assert _utc(datetime(2026, 1, 1, 12, 0, tzinfo=offset), fallback).hour == 7

    assert _text(None, 10) is None
    assert _text("  two   words  ", 20) == "two words"
    assert _text("   ", 20) is None

    assert _as_list({"not": "a list"}) == []
    assert _as_list(["  shop.example.com ", None, 3, ""]) == ["shop.example.com", "3"]

    assert _parse_moment(fallback) is fallback
    assert _parse_moment("2026-01-01T00:00:00Z") == fallback
    assert _parse_moment("2026-13-45T00:00:00Z") is None
    assert _parse_moment("x" * 70) is None
    assert _parse_moment(1700000000) is None

    assert fingerprint_of({}) is None
    assert fingerprint_of({"fingerprint": "  " + "A" * 64 + " "}) == "a" * 64
    assert fingerprint_of({"fingerprint_sha1": "a" * 40}) is None
    assert fingerprint_of({"fingerprint": "not-a-fingerprint"}) is None
    # `id` is the spelling the CT worker's historical rows carry, and the one the
    # storage identity is keyed by (`observation_key`); a projector that does not read
    # it drops every one of those rows (AUD-035).
    assert fingerprint_of({"id": "C" * 64}) == "c" * 64
    assert fingerprint_of({"id": "cert-1"}) is None


# ---------------------------------------------------------------------------
# Projection: every spelling a provider uses, and the rows it must skip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_projection_reads_every_fingerprint_spelling_and_merges_sparse_facts(db_session):
    """Two rows about one handshake produce one certificate with the union of facts.

    Our own probe writes the control row (address, port, expiry) and the chain row
    (SPKI, serial, SANs, issuer); providers use their own key names. The identity has
    to be keyed by whichever spelling arrives first, take the missing facts from the
    next row, and never become a second certificate or a second, address-less
    sighting of the same handshake.
    """
    db_session.add(
        observation(
            source="tlsprobe",
            observation_type="tls_probe",
            subject="shop.example.com",
            records={
                "check_state": "verified",
                "certificate_id": "C" * 64,
                "probe_ip": OUR_IP,
                "port": 443,
            },
            expires_at=NOW + timedelta(days=60),
        )
    )
    db_session.add(
        observation(
            source="tlsprobe",
            observation_type="tls_certificate",
            subject="shop.example.com",
            records={
                "certificate_fingerprint_sha256": "c" * 64,
                "fingerprint_sha1": "D" * 40,
                "spki_sha256": "B" * 64,
                "serial_hex": "0A1B2C",
                "subject_dn": "CN=shop.example.com",
                "issuer": "CN=Example CA",
                "not_before": "2025-12-01T00:00:00Z",
                "san_dns": ["shop.example.com"],
                "key_algo": "RSA",
            },
        )
    )
    await db_session.commit()

    summary = await project_observations(db_session)
    await db_session.commit()

    assert summary == {"identities": 1, "sightings": 1, "scanned": 2}
    stored = (await db_session.execute(select(TLSCertificateIdentity))).scalar_one()
    assert stored.fingerprint_sha256 == "c" * 64
    assert stored.origin == "our_probe"
    assert stored.fingerprint_sha1 == "d" * 40
    assert stored.spki_sha256 == "b" * 64
    assert stored.serial_hex == "0a1b2c"
    assert stored.subject_dn == "CN=shop.example.com"
    assert stored.issuer_dn == "CN=Example CA"
    assert stored.key_algo == "RSA"
    assert stored.san_dns == ["shop.example.com"]
    # The control row carries no not_after, so the identity takes the row's expiry.
    assert aware(stored.not_after) == NOW + timedelta(days=60)

    seen = (await db_session.execute(select(TLSCertificateSighting))).scalar_one()
    # The chain row has no address of its own, so it adds facts rather than a
    # second sighting of the same handshake.
    assert seen.ip == OUR_IP and seen.is_ours is True


@pytest.mark.asyncio
async def test_a_resolution_row_names_its_own_address_and_keeps_the_host_it_resolved(db_session):
    """``vt_resolution`` rows put the address in the subject, not in the metadata.

    A passive-DNS answer names the address as its subject and the hostname it was
    resolved for as a signal. Reading the address from the metadata alone would
    project an address-less sighting, and a port some provider wrote as a string is
    not a port.
    """
    db_session.add(
        observation(
            source="virustotal",
            observation_type="vt_resolution",
            subject="198.51.100.44",
            records={
                "fingerprint_sha256": "e" * 64,
                "host_name": "shop.example.com",
                "port": "443",
                "not_before": "2025-12-01T00:00:00Z",
            },
        )
    )
    # A row that names no certificate is not evidence about any certificate.
    db_session.add(
        observation(
            source="netlas",
            observation_type="hostname",
            subject="edge.example.net",
            records={"ip": "198.51.100.45"},
        )
    )
    await db_session.commit()

    summary = await project_observations(db_session)
    await db_session.commit()

    assert summary["identities"] == 1
    seen = (await db_session.execute(select(TLSCertificateSighting))).scalar_one()
    assert seen.ip == "198.51.100.44"
    assert seen.port is None
    assert seen.is_ours is False
    assert seen.signals["host_name"] == "shop.example.com"


# ---------------------------------------------------------------------------
# What the platform is allowed to call its own
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_our_own_dns_answers_and_verified_handshakes_are_our_addresses(db_session):
    """Three declarations make an address ours, and a broken handshake is not one.

    A provider asked where a certificate is served answers with every endpoint it
    indexed - our own CDN edge included. The resolver's own answers for the monitored
    inventory are ours, an address our probe *verified* is ours, and a failed
    handshake says nothing about who owns the address it could not speak to.
    """
    edge = "203.0.113.55"
    record = "203.0.113.56"
    ipv6 = "2001:db8::5"
    broken = "198.51.100.90"

    db_session.add_all(
        [
            observation(
                source="resolver",
                observation_type="dns_record",
                subject="shop.example.com",
                record_type="AAAA",
                records={"record_values": [edge, "not-an-address", 42]},
            ),
            observation(
                source="resolver",
                observation_type="dns_record",
                subject="shop.example.com",
                record_type="A",
                value=record,
                records={},
            ),
            # Not an address record: its value must not be read as one.
            observation(
                source="resolver",
                observation_type="dns_record",
                subject="shop.example.com",
                record_type="MX",
                value="10 mail.example.com",
                records={},
            ),
            observation(
                source="tlsprobe",
                observation_type="tls_probe",
                subject="shop.example.com",
                records={"check_state": "failed", "probe_ip": broken},
            ),
            observation(
                source="tlsprobe",
                observation_type="tls_probe",
                subject="shop.example.com",
                records={"check_state": "verified", "probe_ip": "2001:0db8::5"},
            ),
            # Malformed probe rows are skipped, not fatal.
            observation(
                source="tlsprobe",
                observation_type="tls_probe",
                subject="shop.example.com",
                records={"check_state": "verified", "probe_ip": "not-an-address"},
            ),
            observation(
                source="tlsprobe",
                observation_type="tls_probe",
                subject="shop.example.com",
                records={"check_state": "verified", "probe_ip": 15},
            ),
        ]
    )
    await db_session.commit()

    # Only the resolver's own answers are "ours by DNS"; the verified handshake is a
    # separate declaration and the MX record's value is not an address.
    assert await resolved_addresses(db_session) == {edge, record}
    assert await probed_addresses(db_session) == {ipv6}


@pytest.mark.asyncio
async def test_a_certificate_served_only_from_addresses_we_do_not_hold_is_foreign(db_session):
    """R1 compares against the platform's own declarations, not a provider's opinion."""
    our = identity("a" * 64)
    db_session.add(our)
    await db_session.flush()
    db_session.add(
        sighting(our, ip=OUR_IP, source="tlsprobe", is_ours=True)
    )
    db_session.add(sighting(our, ip="198.51.100.7", source="shodan"))
    await db_session.commit()

    result = await evaluate_identities(db_session, now=NOW)
    await db_session.commit()

    assert result["queued"]["R1"] == 1
    assert len(await notifications(db_session)) == 1


@pytest.mark.asyncio
async def test_a_provider_only_certificate_is_not_a_foreign_deployment(db_session):
    """R1 asks about *our* certificate somewhere else, not about a stranger's.

    Without an owned sighting the certificate was never ours to lose, and alerting
    would turn every certificate a provider indexed into an incident.
    """
    stranger = identity("f" * 64, origin="provider")
    db_session.add(stranger)
    await db_session.flush()
    # No sighting of this certificate is ours, so there is nothing of ours to find
    # somewhere else - and it is not a CT issuance, so R3 does not apply either.
    db_session.add(sighting(stranger, ip="198.51.100.7"))
    await db_session.commit()

    result = await evaluate_identities(db_session, now=NOW)
    await db_session.commit()

    assert result["queued"]["R1"] == 0
    assert await notifications(db_session) == []


# ---------------------------------------------------------------------------
# Key reuse: a certificate of ours, and the exception that silences it
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_key_reuse_needs_a_certificate_of_ours_and_honours_an_spki_exception(db_session):
    """Two provider certificates sharing a key are not our key being reused.

    R2 asks whether *our* private key ended up in a second certificate, so a key
    group with no owned certificate is somebody else's problem - and once one is ours,
    an SPKI exception is what keeps a partner re-issue quiet.
    """
    spki = "9" * 64
    one = identity("1" * 64, origin="provider", spki_sha256=spki, san_dns=[])
    two = identity("2" * 64, origin="provider", spki_sha256=spki, san_dns=[])
    db_session.add_all([one, two])
    await db_session.flush()
    db_session.add_all([sighting(one, ip=None, source="netlas"), sighting(two, ip=None, source="netlas")])
    await db_session.commit()

    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R2"] == 0
    assert await notifications(db_session) == []

    db_session.add(sighting(one, ip=OUR_IP, source="tlsprobe", is_ours=True, subject=None))
    await db_session.commit()
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R2"] == 1
    await db_session.commit()
    assert [event.payload["rule"] for event in await notifications(db_session)] == ["tls.key.reuse"]

    await add_exception(db_session, match_kind="spki", match_value=spki.upper(), reason="Partner re-issue")
    await db_session.commit()
    result = await evaluate_identities(db_session, now=NOW)
    await db_session.commit()
    assert result["queued"]["R2"] == 0
    assert result["suppressed"] >= 1


# ---------------------------------------------------------------------------
# Scope exceptions: what makes one apply, and what makes it stop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_issuer_exception_applies_only_to_that_issuers_certificates(db_session):
    """An issuer exception is a statement about one CA, not about the whole feature."""
    our = identity("a" * 64, issuer_dn="CN=Example CA")
    other_ca = identity("b" * 64, origin="ct", issuer_dn="CN=Other CA", not_before=NOW + timedelta(days=1))
    same_ca = identity("c" * 64, origin="ct", issuer_dn="CN=Example CA", not_before=NOW + timedelta(days=1))
    db_session.add_all([our, other_ca, same_ca])
    await db_session.flush()
    db_session.add(sighting(our, ip=OUR_IP, source="tlsprobe", is_ours=True))
    # Address-less findings: these are about issuance, not about deployment.
    db_session.add(sighting(other_ca, ip=None, source="ctlogs"))
    db_session.add(sighting(same_ca, ip=None, source="ctlogs"))
    await db_session.commit()

    await add_exception(db_session, match_kind="issuer", match_value="cn=other ca", reason="Acme intermediate")
    await db_session.commit()

    result = await evaluate_identities(db_session, now=NOW)
    await db_session.commit()

    assert result["queued"]["R3"] == 1
    assert result["suppressed"] == 1
    payloads = [event.payload for event in await notifications(db_session)]
    assert [payload["rule"] for payload in payloads] == ["tls.certificate.unexpected"]
    assert payloads[0]["Issuer"] == "CN=Example CA"


@pytest.mark.asyncio
async def test_an_expired_exception_stops_applying_on_its_own(db_session):
    """An expiry is a promise to re-decide, so a lapsed exception alerts again."""
    our = identity("a" * 64)
    db_session.add(our)
    await db_session.flush()
    db_session.add(sighting(our, ip=OUR_IP, source="tlsprobe", is_ours=True))
    db_session.add(sighting(our, ip="198.51.100.7", source="shodan"))
    await db_session.commit()

    lapsed = await add_exception(
        db_session,
        match_kind="fingerprint",
        match_value="a" * 64,
        reason="Customer CDN",
        expires_at=NOW - timedelta(days=1),
    )
    await db_session.commit()

    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R1"] == 1
    await db_session.commit()
    listed = await exceptions_payload(db_session, now=NOW)
    assert listed[0]["expired"] is True and listed[0]["id"] == lapsed.id

    # Extending the same exception updates it in place rather than creating a second.
    renewed = await add_exception(
        db_session,
        match_kind="fingerprint",
        match_value="a" * 64,
        reason="Customer CDN, renewed",
        expires_at=NOW + timedelta(days=30),
    )
    await db_session.commit()
    assert renewed.id == lapsed.id
    rows = list((await db_session.execute(select(CertificateScopeException))).scalars())
    assert len(rows) == 1
    assert rows[0].reason == "Customer CDN, renewed"
    assert (await exceptions_payload(db_session, now=NOW))[0]["expired"] is False

    db_session.add(sighting(our, ip="198.51.100.8", source="shodan"))
    await db_session.commit()
    assert (await evaluate_identities(db_session, now=NOW))["queued"]["R1"] == 0
    await db_session.commit()
    assert len(await notifications(db_session)) == 1


@pytest.mark.asyncio
async def test_an_exception_that_could_never_apply_is_refused_with_the_reason(db_session):
    """A decision that cannot match anything is worse than no decision.

    The ``asn`` kind reads a signal only a provider writes, so storing one on an
    installation with no such source records a judgement that silently does nothing.
    """
    with pytest.raises(ValueError, match="unsupported match kind"):
        await add_exception(db_session, match_kind="serial", match_value="0a1b")
    with pytest.raises(ValueError, match="must not be empty"):
        await add_exception(db_session, match_kind="ip", match_value="   ")
    with pytest.raises(ValueError, match="SHA-256 fingerprint"):
        await add_exception(db_session, match_kind="fingerprint", match_value="abc")
    with pytest.raises(ValueError, match="SHA-256 key digest"):
        await add_exception(db_session, match_kind="spki", match_value="abc")
    with pytest.raises(ValueError, match="none is enabled"):
        await add_exception(db_session, match_kind="asn", match_value="64500")

    # With a source that reports ASNs enabled, the same decision can apply.
    db_session.add(
        Connector(
            name="dns-shodan-asn",
            connector_type="dns",
            provider="shodan",
            status="enabled",
            default_job_type="dns.shodan",
        )
    )
    await db_session.commit()
    stored = await add_exception(db_session, match_kind="asn", match_value="64500", reason="Cloud range")
    await db_session.commit()
    assert stored.match_kind == "asn" and stored.match_value == "64500"


# ---------------------------------------------------------------------------
# Review state and the stack-echo rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_verdict_outlives_the_alert_and_an_unknown_verdict_is_refused(db_session):
    our = identity("a" * 64)
    db_session.add(our)
    await db_session.flush()
    db_session.add(sighting(our, ip=OUR_IP, source="tlsprobe", is_ours=True))
    foreign = sighting(our, ip="198.51.100.7", source="shodan")
    db_session.add(foreign)
    await db_session.commit()

    with pytest.raises(ValueError, match="unsupported verdict"):
        await record_verdict(db_session, sighting_id=foreign.id, verdict="maybe")
    assert await record_verdict(db_session, sighting_id=uuid4(), verdict="expected") is None

    await record_verdict(db_session, sighting_id=foreign.id, verdict="rejected", note="  old   edge  ")
    await db_session.commit()
    # A reviewed sighting is not the sweep's question any more, whichever verdict
    # the reviewer chose.
    result = await evaluate_identities(db_session, now=NOW)
    await db_session.commit()
    assert result["queued"]["R1"] == 0
    assert await notifications(db_session) == []
    items, _ = await identities_payload(db_session)
    reviewed = [item for item in items[0]["sightings"] if item["verdict"] == "rejected"]
    assert reviewed[0]["review_note"] == "old edge"


@pytest.mark.asyncio
async def test_an_echoed_stack_is_a_candidate_for_review_not_an_alert(db_session):
    """R4: the same JARM and title elsewhere is a clone hypothesis, not a finding.

    It marks the sighting for a human and adds no notification, and a host that also
    serves our certificate is R1's case rather than an echo.
    """
    jarm = "29d3fd00029d29d00042d43d00041d"
    our = identity("a" * 64)
    echo = identity("b" * 64, origin="provider", san_dns=[])
    db_session.add_all([our, echo])
    await db_session.flush()
    db_session.add(
        sighting(
            our,
            ip=OUR_IP,
            source="tlsprobe",
            is_ours=True,
            signals={"jarm": jarm, "title": "Example Shop", "http_title": "Example Shop"},
        )
    )
    replicated = sighting(
        echo,
        ip="198.51.100.60",
        source="shodan",
        signals={"jarm": jarm, "title": "Example Shop"},
    )
    db_session.add(replicated)
    await db_session.commit()

    result = await evaluate_identities(db_session, now=NOW)
    await db_session.commit()

    assert result["queued"]["R4"] == 1
    assert replicated.verdict == "candidate"
    assert replicated.signals["rules"] == ["R4"]
    assert replicated.signals["echo"] == ["title"]
    assert replicated.signals["needs_review"] is True
    assert replicated.confidence == 2
    # A hypothesis is not a notification.
    assert [event.payload["rule"] for event in await notifications(db_session)] == []


def test_monitor_kind_is_the_only_switch_the_expiry_column_reads():
    """One function decides which control an observation type feeds, and it must not
    silently answer ``None`` for a type the page still shows.

    It takes the row rather than the type alone: a probe's control is keyed by port,
    because two services on one asset are two things to remind about (AUD-036), and
    the port is named in either `metadata.port` or a `TLS:<port>` record type.
    """
    from app.api.v1.routers.dns_security import expiry_kind, monitor_kind

    def probe(*, metadata=None, record_type=None) -> SimpleNamespace:
        return SimpleNamespace(
            observation_type="tls_probe",
            metadata_json=metadata or {},
            record_type=record_type,
        )

    assert monitor_kind(SimpleNamespace(observation_type="rdap")) == "registration"
    assert monitor_kind(SimpleNamespace(observation_type="certificate_check")) == "certificate"
    assert monitor_kind(probe()) == "tls:443"
    assert monitor_kind(probe(metadata={"port": 8443})) == "tls:8443"
    assert monitor_kind(probe(record_type="TLS:9443")) == "tls:9443"
    assert monitor_kind(SimpleNamespace(observation_type="hostname")) is None
    assert expiry_kind(SimpleNamespace(observation_type="tls_certificate", source="netlas")) == "tls"
    assert expiry_kind(SimpleNamespace(observation_type="dns_record", source="resolver")) == "dns_cache"
    assert expiry_kind(SimpleNamespace(observation_type="hostname", source="shodan")) == "unknown"


# ---------------------------------------------------------------------------
# The guards a rule reads before it scores anything
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_exception_whose_kind_the_sighting_cannot_answer_does_not_apply(db_session):
    """An SPKI exception on a certificate with no key digest is not a match.

    ``_exception_match`` reads the value a kind names from the identity or the
    sighting, and a kind with nothing to compare against has to fall through to the
    next exception rather than match on ``None == None`` - otherwise one exception
    would silence every certificate whose SPKI a provider did not report.
    """
    our = identity("a" * 64, spki_sha256=None)
    db_session.add(our)
    await db_session.flush()
    db_session.add(sighting(our, ip=OUR_IP, source="tlsprobe", is_ours=True))
    db_session.add(sighting(our, ip="198.51.100.7", source="shodan"))
    await db_session.commit()

    await add_exception(db_session, match_kind="spki", match_value="9" * 64, reason="Partner re-issue")
    await db_session.commit()

    result = await evaluate_identities(db_session, now=NOW)
    await db_session.commit()

    assert result["queued"]["R1"] == 1
    assert result["suppressed"] == 0


@pytest.mark.asyncio
async def test_an_issuance_for_a_name_we_never_served_has_no_baseline(db_session):
    """R3 compares against our newest certificate *for that name*.

    A CT certificate for a name none of our own sightings covers is not "newer than
    ours" - it is a different name - so without a baseline the rule has nothing to
    say and must stay quiet rather than treat the missing baseline as epoch.
    """
    our = identity("a" * 64)
    elsewhere = identity(
        "b" * 64,
        origin="ct",
        issuer_dn="CN=Other CA",
        subject_dn="CN=other.example.com",
        san_dns=["other.example.com"],
        not_before=NOW + timedelta(days=1),
    )
    db_session.add_all([our, elsewhere])
    await db_session.flush()
    db_session.add(sighting(our, ip=OUR_IP, source="tlsprobe", is_ours=True))
    db_session.add(sighting(elsewhere, ip=None, subject="other.example.com", source="ctlogs"))
    await db_session.commit()

    result = await evaluate_identities(db_session, now=NOW)
    await db_session.commit()

    assert result["queued"]["R3"] == 0
    assert await notifications(db_session) == []


@pytest.mark.asyncio
async def test_an_echo_of_a_host_that_serves_our_certificate_is_r1s_case(db_session):
    """R4 asks about a clone of the stack, not about a host already holding our key.

    The same JARM and title on a host that also serves one of our certificates is the
    foreign deployment R1 already alerts on; scoring it again as an echo would add a
    second, weaker finding for one fact.
    """
    jarm = "29d3fd00029d29d00042d43d00041d"
    our = identity("a" * 64)
    echo = identity("b" * 64, origin="ct", san_dns=[])
    db_session.add_all([our, echo])
    await db_session.flush()
    db_session.add(
        sighting(
            our,
            ip=OUR_IP,
            source="tlsprobe",
            is_ours=True,
            signals={"jarm": jarm, "title": "Example Shop"},
        )
    )
    db_session.add(sighting(echo, ip=OUR_IP, source="tlsprobe", is_ours=True))
    replicated = sighting(
        echo,
        ip="198.51.100.60",
        source="shodan",
        signals={"jarm": jarm, "title": "Example Shop"},
    )
    db_session.add(replicated)
    await db_session.commit()

    result = await evaluate_identities(db_session, now=NOW)
    await db_session.commit()

    assert result["queued"]["R4"] == 0
    assert "R4" not in (replicated.signals or {}).get("rules", [])
    # It is still R1's finding: a certificate of ours served from a foreign address.
    assert result["queued"]["R1"] == 1
