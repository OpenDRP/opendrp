"""Design B: certificates as objects, and the rules that flag a foreign deployment.

The threat this answers is a copied service: a VM, disk image or container carrying a
web server *and its private key* is deployed somewhere else, and the evidence is that
the same certificate is served from an address that is not ours. Certificate
Transparency and our own probe give the identities, the provider sources give the
places a certificate was seen, and these rules turn the difference into one alert that
names the foreign address, the signals that fired and what to do about it.

Two properties are deliberate:

* **No traffic is sent to third-party infrastructure.** Every provider read is a search
  over data the vendor already collected, and the only active traffic is our own probe
  against our own assets. An alert never invites an operator to probe the foreign host.
* **A verdict outlives the alert that produced it.** A sighting a human marked
  ``expected``, a fingerprint covered by a scope exception, or a match the scoring
  itself classified as shared hosting produces nothing on the next sweep, which is what
  keeps the feature usable in a real estate with CDNs and partner appliances.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, AssetType
from app.models.connector import Connector, ConnectorStatus
from app.models.dns_observation import DNSObservation
from app.models.tls_certificate import (
    CertificateScopeException,
    TLSCertificateIdentity,
    TLSCertificateSighting,
)
from app.services.ingestion_events import record_event

#: The sources that can name a certificate. ``rdap`` and ``resolver`` describe a
#: registration or a record set, so they never contribute an identity.
CERTIFICATE_SOURCES = ("tlsprobe", "ctlogs", "virustotal", "shodan", "netlas")

#: Where a fingerprint may come from, in preference order. ``certificate_id`` is what
#: our own probe and the CT control row write; ``id`` is the alone-spelling the CT
#: worker's historical rows carry, and the one `observation_key` already keys those
#: rows by — a projector that does not read it drops the whole CT corpus (AUD-035).
#: The hex check below is what keeps any of them from meaning "some provider id".
_FINGERPRINT_KEYS = (
    "fingerprint_sha256",
    "certificate_fingerprint_sha256",
    "certificate_id",
    "fingerprint",
    "id",
)

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SHA1_HEX = re.compile(r"^[0-9a-f]{40}$")

#: Hosting and CDN organisations. A certificate of ours legitimately served from one of
#: these by many foreign addresses is shared infrastructure rather than a copy, so the
#: scoring says so instead of alerting (see ``_shared_infrastructure``).
_CDN_HINTS = (
    "cloudflare",
    "akamai",
    "fastly",
    "cloudfront",
    "amazon",
    "incapsula",
    "imperva",
    "sucuri",
    "stackpath",
    "bunny",
    "gcore",
    "github",
    "google",
    "azure",
    "microsoft",
)

#: The states a review may set, and the one the rules may queue for. Anything else
#: suppresses: a sighting a person or the scoring has already judged is not news.
REVIEW_VERDICTS = ("candidate", "expected", "shared_infrastructure", "confirmed_foreign", "rejected")

EXCEPTION_KINDS = ("fingerprint", "spki", "ip", "asn", "issuer")

#: The provider facts a sighting may carry, and the keys the rules score on.
SIGNAL_KEYS = (
    "org",
    "asn",
    "jarm",
    "title",
    "favicon_hash",
    "http_title",
    "http_favicon_hash",
    "host_lookup_confirmed",
)

#: Which source writes each signal above.
#:
#: This declaration exists because three of these keys were read by the rules and
#: written by nobody (F-10/F-11 of the DNS & TLS audit): R4 needs ``jarm``, the
#: shared-infrastructure suppression needs ``org``/``asn`` to recognise a CDN, and an
#: ``asn`` scope exception reads ``asn``. A signal with no producer is a rule that can
#: never fire and a decision an operator can record that can never apply, so the
#: producers are named here, ``backend/tests/test_signal_producers.py`` fails when one
#: stops writing its key, and ``add_exception`` refuses a match kind whose signal nothing
#: in the installation produces.
SIGNAL_PRODUCERS: dict[str, tuple[str, ...]] = {
    "org": ("netlas", "shodan"),
    "asn": ("netlas", "shodan"),
    "jarm": ("netlas", "shodan"),
    "title": ("netlas", "shodan"),
    "favicon_hash": ("netlas", "shodan"),
    "http_title": ("shodan",),
    "http_favicon_hash": ("shodan",),
    "host_lookup_confirmed": ("shodan",),
}

#: The signal an exception match kind needs a producer for. The other kinds are
#: resolved from evidence the core holds itself - the fingerprint and SPKI of the
#: identity, the sighting's address, the issuer distinguished name - so they can always
#: be matched and are deliberately absent here.
EXCEPTION_KIND_SIGNALS = {"asn": "asn"}

#: How many foreign addresses serving one certificate turn "someone copied us" into
#: "this is a CDN", together with an organisation that looks like one.
SHARED_INFRASTRUCTURE_ADDRESSES = 5


def _utc(value: datetime | None, fallback: datetime) -> datetime:
    if value is None:
        return fallback
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _text(value: object, limit: int) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(str(value).split())
    return cleaned[:limit] or None


def _as_list(value: object, limit: int = 100) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in (_text(item, 253) for item in value[:limit]) if item]


def fingerprint_of(metadata: dict[str, Any]) -> str | None:
    """The SHA-256 identity a certificate-shaped observation carries, if any."""
    for key in _FINGERPRINT_KEYS:
        value = metadata.get(key)
        if isinstance(value, str):
            candidate = value.strip().lower()
            if _SHA256_HEX.fullmatch(candidate):
                return candidate
    return None


def _sha1_of(metadata: dict[str, Any]) -> str | None:
    for key in ("fingerprint_sha1", "certificate_fingerprint_sha1"):
        value = metadata.get(key)
        if isinstance(value, str) and _SHA1_HEX.fullmatch(value.strip().lower()):
            return value.strip().lower()
    return None


def _observation_identity_facts(row: DNSObservation) -> dict[str, Any]:
    metadata = row.metadata_json or {}
    not_after = _parse_moment(metadata.get("not_after"))
    if not_after is None and row.expires_at is not None:
        not_after = _utc(row.expires_at, datetime.now(timezone.utc))
    return {
        "fingerprint_sha1": _sha1_of(metadata),
        "spki_sha256": (_text(metadata.get("spki_sha256"), 64) or "").lower() or None,
        "serial_hex": (_text(metadata.get("serial_hex"), 128) or "").lower() or None,
        "subject_dn": _text(metadata.get("subject_dn"), 1000),
        "issuer_dn": _text(metadata.get("issuer_dn") or metadata.get("issuer"), 1000),
        "not_before": _parse_moment(metadata.get("not_before")),
        "not_after": not_after,
        "san_dns": _as_list(metadata.get("san_dns")),
        "key_algo": _text(metadata.get("key_algo"), 64),
    }


def _parse_moment(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return _utc(value, value)
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")), datetime.now(timezone.utc))
    except ValueError:
        return None


def _sighting_address(row: DNSObservation) -> tuple[str | None, int | None]:
    """The address a provider names for this observation, and its port."""
    metadata = row.metadata_json or {}
    ip = _text(metadata.get("probe_ip"), 64) or _text(metadata.get("ip"), 64) or _text(metadata.get("ip_address"), 64)
    if ip is None and row.observation_type == "vt_resolution":
        ip = _text(row.subject, 64)
    port = metadata.get("port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        port = None
    return ip, port


def _sighting_signals(row: DNSObservation) -> dict[str, Any]:
    """Provider facts a rule may score on, kept for the triage view."""
    metadata = row.metadata_json or {}
    signals: dict[str, Any] = {}
    for key in SIGNAL_KEYS:
        value = metadata.get(key)
        if isinstance(value, bool):
            # A flag such as `host_lookup_confirmed` is what the free host lookup
            # answered, and it feeds the confidence of the rule below.
            signals[key] = value
        elif isinstance(value, str) and value.strip():
            signals[key] = value.strip()[:200]
        elif isinstance(value, int):
            signals[key] = value
    if row.observation_type == "vt_resolution":
        signals.setdefault("host_name", _text(metadata.get("host_name"), 253))
    return {key: value for key, value in signals.items() if value is not None}


def sighting_subjects(sighting: TLSCertificateSighting) -> list[str]:
    """Every name one certificate was reported for at this endpoint (AUD-037).

    The sighting is keyed by (certificate, address, port, source) on purpose:
    re-observing the same fact refreshes a row instead of stacking a duplicate.
    The hostnames are evidence rather than key, and the first one to arrive used
    to be the only one stored, so a certificate served for two names at one
    address was invisible to the issuance rule under the second name. They are
    accumulated here, and the rule iterates the set.
    """
    stored = (sighting.signals or {}).get("subjects")
    subjects = (
        [value for value in stored if isinstance(value, str) and value]
        if isinstance(stored, list)
        else []
    )
    if sighting.subject and sighting.subject not in subjects:
        subjects.append(sighting.subject)
    return subjects


async def project_observations(db: AsyncSession, *, limit: int = 5000) -> dict:
    """Turn stored observations into certificate identities and sightings.

    Idempotent by construction: an identity is keyed by its SHA-256 fingerprint and a
    sighting by (identity, address, port, source), so re-projecting the same evidence
    refreshes ``last_seen_at`` and never duplicates a row. ``is_ours`` is the
    platform's own answer - our probe, or an address we hold as an ``ip_address``
    asset - and is never taken from a source's opinion.
    """
    rows = list(
        (
            await db.execute(
                select(DNSObservation)
                .where(DNSObservation.source.in_(CERTIFICATE_SOURCES))
                .order_by(DNSObservation.last_seen_at.desc())
                .limit(limit)
            )
        ).scalars()
    )
    our_addresses = await _asset_addresses(db) | await probed_addresses(db)
    identities = {
        row.fingerprint_sha256: row
        for row in (await db.execute(select(TLSCertificateIdentity))).scalars()
    }
    sightings = {
        (row.identity_id, row.ip, row.port, row.source): row
        for row in (
            await db.execute(
                select(TLSCertificateSighting).where(
                    TLSCertificateSighting.source.in_(CERTIFICATE_SOURCES)
                )
            )
        ).scalars()
    }
    created_identities = created_sightings = 0
    for observation in rows:
        metadata = observation.metadata_json or {}
        fingerprint = fingerprint_of(metadata)
        if fingerprint is None:
            continue
        seen_at = _utc(observation.last_seen_at, datetime.now(timezone.utc))
        identity = identities.get(fingerprint)
        facts = _observation_identity_facts(observation)
        if identity is None:
            identity = TLSCertificateIdentity(
                fingerprint_sha256=fingerprint,
                origin={"tlsprobe": "our_probe", "ctlogs": "ct"}.get(observation.source, "provider"),
                first_seen_at=seen_at,
                last_seen_at=seen_at,
                **facts,
            )
            db.add(identity)
            await db.flush()
            identities[fingerprint] = identity
            created_identities += 1
        else:
            identity.last_seen_at = max(_utc(identity.last_seen_at, seen_at), seen_at)
            for field, value in facts.items():
                # Provider records are often sparser than a handshake; the first
                # evidence that carries a field owns it.
                if value is not None and getattr(identity, field) in (None, [], ""):
                    setattr(identity, field, value)
            identity.first_seen_at = min(_utc(identity.first_seen_at, seen_at), seen_at)
        ip, port = _sighting_address(observation)
        if ip is None and observation.source == "tlsprobe":
            # Our own handshake writes two rows: the control row that names the probed
            # address and port, and the chain member keyed by fingerprint. The control
            # row is the sighting; the chain row is what gives the identity its SPKI,
            # serial and SANs, and a second, address-less copy of the same handshake
            # would only make the review list longer than the evidence.
            continue
        is_ours = (
            observation.source == "tlsprobe"
            # A host lookup is a provider's record of one address the platform itself
            # named - a monitored `ip_address` asset, or an address one of our monitored
            # domains resolves to right now. The worker asks about nothing else, so the
            # evidence is about our own service even when no operator registered the
            # address and no probe has verified it yet.
            or observation.observation_type == "host_lookup"
            or (ip is not None and ip in our_addresses)
        )
        key = (identity.id, ip, port, observation.source)
        sighting = sightings.get(key)
        signals = _sighting_signals(observation)
        if sighting is None:
            sighting = TLSCertificateSighting(
                identity_id=identity.id,
                subject=observation.subject,
                ip=ip,
                port=port,
                source=observation.source,
                observed_at=seen_at,
                first_seen_at=seen_at,
                last_seen_at=seen_at,
                is_ours=is_ours,
                signals={**signals, "subjects": [observation.subject]},
                verdict="candidate",
                confidence=0,
            )
            db.add(sighting)
            await db.flush()
            sightings[key] = sighting
            created_sightings += 1
        else:
            sighting.last_seen_at = max(_utc(sighting.last_seen_at, seen_at), seen_at)
            sighting.first_seen_at = min(_utc(sighting.first_seen_at, seen_at), seen_at)
            sighting.is_ours = sighting.is_ours or is_ours
            merged = sorted(set(sighting_subjects(sighting)) | {observation.subject})
            sighting.signals = {
                **signals,
                **{k: v for k, v in (sighting.signals or {}).items() if k not in signals},
                "subjects": merged,
            }
    await db.flush()
    return {"identities": created_identities, "sightings": created_sightings, "scanned": len(rows)}


async def _asset_addresses(db: AsyncSession) -> set[str]:
    """The addresses an operator registered as monitored ``ip_address`` assets."""
    return {
        value
        for (value,) in (
            await db.execute(
                select(Asset.normalized_value).where(
                    Asset.asset_type == AssetType.ip_address, Asset.normalized_value.is_not(None)
                )
            )
        ).all()
    }


async def probed_addresses(db: AsyncSession, *, limit: int = 5000) -> set[str]:
    """The addresses our own handshake verified our certificate on.

    R1 asks whether a certificate of ours is served somewhere that is not ours, and a
    provider asked "where is this certificate served" answers with *every* endpoint it has
    seen, our own server included. Reading that back as a foreign deployment would be the
    loudest possible false positive, so an address our probe verified is ours even when no
    operator registered it as an ``ip_address`` asset.

    Only a verified handshake counts. A failed, expired or name-mismatched probe says
    nothing about who owns the address it could not speak to, and treating it as ours would
    hide a copy behind a broken handshake.
    """
    rows = (
        await db.execute(
            select(DNSObservation.metadata_json)
            .where(DNSObservation.source == "tlsprobe")
            .limit(limit)
        )
    ).all()
    addresses: set[str] = set()
    for (metadata,) in rows:
        if not isinstance(metadata, dict) or metadata.get("check_state") != "verified":
            continue
        value = metadata.get("probe_ip")
        if not isinstance(value, str):
            continue
        try:
            addresses.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return addresses


async def resolved_addresses(db: AsyncSession, *, limit: int = 5000) -> set[str]:
    """The addresses our own monitored names publish, as our own DNS answers them.

    R1 asks whether a certificate of ours is served somewhere that is not ours, and a
    provider asked "where is this certificate served" answers with every endpoint it
    indexed - our own CDN edge included. That edge is usually neither an `ip_address`
    asset nor an address our probe verified, so without this set the loudest rule in the
    module would fire on the operator's own site the first time a provider source was
    enabled. The rows are the resolver's own answers for the monitored inventory, so what
    this says is "our own DNS points here" rather than a provider's opinion.
    """
    rows = (
        await db.execute(
            select(
                DNSObservation.metadata_json, DNSObservation.record_type, DNSObservation.value
            )
            .where(
                DNSObservation.source == "resolver",
                DNSObservation.observation_type == "dns_record",
            )
            .limit(limit)
        )
    ).all()
    addresses: set[str] = set()
    for metadata, record_type, value in rows:
        values: list[object] = []
        if isinstance(metadata, dict) and isinstance(metadata.get("record_values"), list):
            values = metadata["record_values"][:100]
        elif str(record_type or "").upper() in {"A", "AAAA"}:
            values = [value]
        for item in values:
            if not isinstance(item, str):
                continue
            try:
                addresses.add(str(ipaddress.ip_address(item.strip())))
            except ValueError:
                continue
    return addresses


async def _our_addresses(db: AsyncSession) -> set[str]:
    """Every address the platform holds as its own.

    Three declarations, all of them the platform's own rather than a source's: an
    operator registered the address as an asset, our handshake verified our certificate
    on it, or our own DNS answers with it for a monitored name.
    """
    return await _asset_addresses(db) | await probed_addresses(db) | await resolved_addresses(db)


async def active_exceptions(db: AsyncSession, *, now: datetime) -> list[CertificateScopeException]:
    rows = list(
        (
            await db.execute(
                select(CertificateScopeException).where(
                    (CertificateScopeException.expires_at.is_(None))
                    | (CertificateScopeException.expires_at > now)
                )
            )
        ).scalars()
    )
    return rows


def _exception_match(
    exceptions: list[CertificateScopeException],
    *,
    identity: TLSCertificateIdentity,
    sighting: TLSCertificateSighting,
) -> CertificateScopeException | None:
    values = {
        "fingerprint": identity.fingerprint_sha256,
        "spki": identity.spki_sha256,
        "ip": sighting.ip,
        "asn": sighting.signals.get("asn"),
        "issuer": identity.issuer_dn,
    }
    for exception in exceptions:
        candidate = values.get(exception.match_kind)
        if candidate is None:
            continue
        if str(candidate).strip().lower() == exception.match_value.strip().lower():
            return exception
    return None


def _looks_like_cdn(sighting: TLSCertificateSighting) -> bool:
    haystack = f"{sighting.signals.get('org', '')} {sighting.signals.get('asn', '')}".lower()
    return any(hint in haystack for hint in _CDN_HINTS)


def _digest(*parts: object) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode()).hexdigest()[:32]


async def evaluate_identities(db: AsyncSession, *, now: datetime | None = None) -> dict:
    """Score identities and queue one alert per foreign deployment (rules R1-R4).

    Every rule is idempotent: an outbox row is keyed by what fired (identity, address
    or key plus the signals), so a daily sweep over unchanged evidence queues nothing,
    while a *new* independent source confirming the same fact is new information and
    does arrive.
    """
    instant = now or datetime.now(timezone.utc)
    identities = {
        row.id: row
        for row in (await db.execute(select(TLSCertificateIdentity))).scalars()
    }
    sightings = list(
        (
            await db.execute(
                select(TLSCertificateSighting).where(
                    TLSCertificateSighting.verdict == "candidate"
                )
            )
        ).scalars()
    )
    exceptions = await active_exceptions(db, now=instant)
    our_addresses = await _our_addresses(db)
    queued = {"R1": 0, "R2": 0, "R3": 0, "R4": 0}
    suppressed = 0

    # --- R1: a certificate of ours served somewhere that is not ours -------------
    foreign: dict[UUID, list[TLSCertificateSighting]] = {}
    for sighting in sightings:
        identity = identities.get(sighting.identity_id)
        if identity is None or sighting.ip is None:
            continue
        if sighting.is_ours or sighting.ip in our_addresses:
            continue
        foreign.setdefault(sighting.identity_id, []).append(sighting)
    our_sightings = list(
        (
            await db.execute(
                select(TLSCertificateSighting).where(TLSCertificateSighting.is_ours.is_(True))
            )
        ).scalars()
    )
    our_identities = {row.identity_id for row in our_sightings}
    for identity_id, rows in foreign.items():
        identity = identities[identity_id]
        if identity_id not in our_identities:
            continue
        # One deployment, one alert: several providers indexing the same address are
        # independent confirmations of the same fact, and they belong in the confidence
        # rather than in the number of messages.
        by_address: dict[str, list[TLSCertificateSighting]] = {}
        for row in rows:
            # An address-less sighting says a certificate exists, not where it is
            # served (see the model), so it cannot group a deployment — and the guard
            # is what lets the grouping key be the address rather than "somewhere".
            if row.ip is None:
                continue
            by_address.setdefault(row.ip, []).append(row)
        for address, group in by_address.items():
            sighting = group[0]
            sources = sorted({row.source for row in group})
            signals = {key: value for row in group for key, value in (row.signals or {}).items()}
            exception = _exception_match(exceptions, identity=identity, sighting=sighting)
            if exception is None and sighting.signals.get("asn") is None:
                # An exception may name the ASN, which only the group's signals know.
                sighting.signals = {**signals}
                exception = _exception_match(exceptions, identity=identity, sighting=sighting)
            if exception is not None:
                for row in group:
                    row.verdict = "expected"
                    row.signals = {**(row.signals or {}), **signals, "exception": exception.match_kind}
                suppressed += 1
                continue
            if len({row.ip for row in rows}) >= SHARED_INFRASTRUCTURE_ADDRESSES and any(
                _looks_like_cdn(row) for row in group
            ):
                for row in group:
                    row.verdict = "shared_infrastructure"
                    row.signals = {**(row.signals or {}), **signals, "reason": "cdn_shared_certificate"}
                suppressed += 1
                continue
            confirmed = any(row.signals.get("host_lookup_confirmed") for row in group)
            confidence = len(sources) + (1 if confirmed else 0)
            for row in group:
                row.confidence = confidence
                row.signals = {**(row.signals or {}), **signals, "rules": ["R1"], "sources": sources}
            subject = sighting.subject or (identity.san_dns or ["unknown"])[0]
            queued_foreign = await record_event(
                db,
                kind="notification",
                module="dns",
                entity_id=sighting.id,
                payload={
                    "severity": "high",
                    "rule": "tls.certificate.foreign",
                    "title": f"{subject}: our certificate is served from {sighting.ip}",
                    "host": subject,
                    "Certificate fingerprint (SHA-256)": identity.fingerprint_sha256,
                    "Serial": identity.serial_hex or "unknown",
                    "Issuer": identity.issuer_dn or "unknown",
                    "Foreign address": sighting.ip,
                    "Port": str(sighting.port or "unknown"),
                    "Organisation": sighting.signals.get("org") or "unknown",
                    "ASN": sighting.signals.get("asn") or "unknown",
                    "First observed": _utc(sighting.first_seen_at, instant).isoformat(),
                    "Sources": ", ".join(sources),
                    "Confidence": str(confidence),
                    "What to do": (
                        "Revoke and reissue this certificate with a NEW key pair, treat the "
                        "private key as compromised, rebuild the machine or image it was "
                        "copied from, and check who can deploy from that image."
                    ),
                },
                dedup=_digest("R1", identity.fingerprint_sha256, sighting.ip, sources),
            )
            if queued_foreign:
                queued["R1"] += 1

    # --- R2: one key inside two certificates -------------------------------------
    by_spki: dict[str, list[TLSCertificateIdentity]] = {}
    for identity in identities.values():
        if identity.spki_sha256:
            by_spki.setdefault(identity.spki_sha256, []).append(identity)
    # The loop variables are named for what they hold: ``group`` is already the sightings
    # sharing one address in R1 above, and R2 works on *certificates*. One name for two
    # shapes is how a reader (and a type checker) loses track of which list is in hand.
    for spki, key_group in by_spki.items():
        if len(key_group) < 2:
            continue
        ours = [certificate for certificate in key_group if certificate.id in our_identities]
        if not ours:
            continue
        exception = next(
            (item for item in exceptions if item.match_kind == "spki" and item.match_value.lower() == spki.lower()),
            None,
        )
        if exception is not None:
            suppressed += 1
            continue
        fingerprints = sorted(certificate.fingerprint_sha256 for certificate in key_group)
        confidence = len(key_group) - 1 + (1 if any(certificate.origin != "our_probe" for certificate in key_group) else 0)
        queued_reuse = await record_event(
            db,
            kind="notification",
            module="dns",
            entity_id=ours[0].id,
            payload={
                "severity": "high",
                "rule": "tls.key.reuse",
                "title": f"The same private key is inside {len(key_group)} certificates",
                "host": ours[0].san_dns[0] if ours[0].san_dns else "unknown",
                "Key (SPKI SHA-256)": spki,
                "Certificates": ", ".join(fingerprints),
                "Issuers": ", ".join(sorted({certificate.issuer_dn or "unknown" for certificate in key_group})),
                "First seen (UTC)": min(_utc(certificate.first_seen_at, instant) for certificate in key_group).isoformat(),
                "Confidence": str(confidence),
                "What to do": (
                    "One key pair produced more than one certificate. Treat the key as "
                    "compromised, reissue with a new key pair, and find out where the "
                    "second certificate is served."
                ),
            },
            dedup=_digest("R2", spki, fingerprints),
        )
        if queued_reuse:
            queued["R2"] += 1

    # --- R3: a certificate for our name that we did not deploy -------------------
    ours_by_subject: dict[str, datetime] = {}
    issuers_by_subject: dict[str, set[str]] = {}
    for sighting in our_sightings:
        identity = identities.get(sighting.identity_id)
        if identity is None:
            continue
        for subject in sighting_subjects(sighting):
            if identity.not_before is not None:
                current = ours_by_subject.get(subject)
                ours_by_subject[subject] = max(current, _utc(identity.not_before, instant)) if current else _utc(identity.not_before, instant)
            if identity.issuer_dn:
                issuers_by_subject.setdefault(subject, set()).add(identity.issuer_dn.lower())
    for sighting in sightings:
        identity = identities.get(sighting.identity_id)
        if identity is None or sighting.is_ours:
            continue
        if identity.origin != "ct" or identity.not_before is None:
            continue
        issued = _utc(identity.not_before, instant)
        # One sighting can name several hostnames; each is the question R3 asks,
        # and each gets its own baseline and its own event (AUD-037).
        for subject in sighting_subjects(sighting):
            baseline = ours_by_subject.get(subject)
            if baseline is None:
                continue
            if issued <= baseline:
                continue
            if _exception_match(exceptions, identity=identity, sighting=sighting) is not None:
                suppressed += 1
                continue
            # Bound to a local so the emptiness check and the lookup above read as one
            # question: an issuer the platform has not seen on our own certificates is
            # what makes a fresh issuance for our name more than a renewal.
            issuer = identity.issuer_dn or ""
            unknown_issuer = bool(issuer) and issuer.lower() not in issuers_by_subject.get(subject, set())
            confidence = 1 + (1 if unknown_issuer else 0)
            sighting.confidence = confidence
            sighting.signals = {**(sighting.signals or {}), "rules": ["R3"]}
            queued_issuance = await record_event(
                db,
                kind="notification",
                module="dns",
                entity_id=sighting.id,
                payload={
                    "severity": "medium",
                    "rule": "tls.certificate.unexpected",
                    "title": f"{subject}: a certificate we did not deploy was issued for this name",
                    "host": subject,
                    "Certificate fingerprint (SHA-256)": identity.fingerprint_sha256,
                    "Issuer": identity.issuer_dn or "unknown",
                    "Issued at (UTC)": issued.isoformat(),
                    "Our newest certificate for this name": baseline.isoformat(),
                    "Issuer known for this name": "no" if unknown_issuer else "yes",
                    "Confidence": str(confidence),
                    "What to do": (
                        "Confirm with the certificate authority who requested it, check the "
                        "ACME/DNS accounts that can prove control of this name, and revoke it "
                        "if it is not ours."
                    ),
                },
                dedup=_digest("R3", subject, identity.fingerprint_sha256),
            )
            if queued_issuance:
                queued["R3"] += 1

    # --- R4: a service stack that echoes ours ------------------------------------
    # Not an alert: matching a JARM and a title is strong evidence of a clone and weak
    # evidence of *which* clone, so it becomes a candidate a human confirms, which is
    # also what the plan's rule table requires.
    our_jarms = {
        row.signals.get("jarm"): row for row in our_sightings if row.signals.get("jarm")
    }
    if our_jarms:
        for sighting in sightings:
            if sighting.is_ours or sighting.verdict != "candidate":
                continue
            jarm = sighting.signals.get("jarm")
            if not jarm or jarm not in our_jarms:
                continue
            reference = our_jarms[jarm]
            echo = [
                key
                for key in ("title", "http_title", "favicon_hash", "http_favicon_hash")
                if sighting.signals.get(key)
                and sighting.signals.get(key) == reference.signals.get(key)
            ]
            if not echo:
                continue
            # "With no certificate match": a host that also serves our certificate is
            # already R1's case, and the rule asks about a clone of the whole stack.
            if sighting.identity_id in our_identities:
                continue
            sighting.confidence = max(sighting.confidence or 0, 1 + len(echo))
            sighting.signals = {
                **(sighting.signals or {}),
                "rules": ["R4"],
                "echo": echo,
                "needs_review": True,
            }
            queued["R4"] += 1
    await db.flush()
    return {"queued": queued, "suppressed": suppressed, "candidates": len(sightings)}


async def record_verdict(
    db: AsyncSession,
    *,
    sighting_id: UUID,
    verdict: str,
    user_id: UUID | None = None,
    note: str | None = None,
    now: datetime | None = None,
) -> TLSCertificateSighting | None:
    """Record a review decision on one sighting.

    The decision is what suppresses the next alert: the rules only queue for
    ``candidate`` rows, so a reviewed sighting stays quiet until a new source or a new
    address makes it a different question.
    """
    if verdict not in REVIEW_VERDICTS:
        raise ValueError("unsupported verdict")
    instant = now or datetime.now(timezone.utc)
    sighting = (
        await db.execute(
            select(TLSCertificateSighting)
            .where(TLSCertificateSighting.id == sighting_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if sighting is None:
        return None
    sighting.verdict = verdict
    sighting.reviewed_by = user_id
    sighting.reviewed_at = instant
    sighting.review_note = _text(note, 2000)
    await db.flush()
    return sighting


async def unproduced_match_kinds(db: AsyncSession, kinds) -> dict[str, list[str]]:
    """Exception kinds whose signal nothing enabled in this installation writes.

    An ``asn`` exception reads the ASN a provider reported for a sighting, so it can only
    apply once a source that reports one is registered and enabled. Without this check the
    exception was stored, audited and displayed while matching nothing - the failure mode
    the audit found in the ``asn`` kind, where a decision looked recorded and had no effect.
    """
    needed = {kind: EXCEPTION_KIND_SIGNALS[kind] for kind in kinds if kind in EXCEPTION_KIND_SIGNALS}
    if not needed:
        return {}
    producers = {
        provider
        for (provider,) in (
            await db.execute(
                select(Connector.provider).where(
                    Connector.connector_type == "dns",
                    Connector.status == ConnectorStatus.ENABLED,
                    Connector.provider.is_not(None),
                )
            )
        ).all()
    }
    return {
        kind: list(SIGNAL_PRODUCERS.get(signal, ()))
        for kind, signal in needed.items()
        if not set(SIGNAL_PRODUCERS.get(signal, ())) & producers
    }


async def add_exception(
    db: AsyncSession,
    *,
    match_kind: str,
    match_value: str,
    reason: str | None = None,
    user_id: UUID | None = None,
    expires_at: datetime | None = None,
) -> CertificateScopeException:
    """Allow one identity, key, address, ASN or issuer out of the rules' scope."""
    if match_kind not in EXCEPTION_KINDS:
        raise ValueError("unsupported match kind")
    unproduced = await unproduced_match_kinds(db, [match_kind])
    if unproduced:
        sources = " or ".join(unproduced[match_kind])
        raise ValueError(
            f"a {match_kind} exception needs a registered source that reports it "
            f"({sources}); none is enabled, so it would never apply"
        )
    cleaned = _text(match_value, 255)
    if cleaned is None:
        raise ValueError("match value must not be empty")
    if match_kind == "fingerprint" and not _SHA256_HEX.fullmatch(cleaned.lower()):
        raise ValueError("a fingerprint exception needs a SHA-256 fingerprint")
    if match_kind == "spki" and not _SHA256_HEX.fullmatch(cleaned.lower()):
        raise ValueError("an SPKI exception needs a SHA-256 key digest")
    kind, value = match_kind, cleaned.lower() if match_kind in {"fingerprint", "spki", "issuer"} else cleaned
    existing = (
        await db.execute(
            select(CertificateScopeException).where(
                CertificateScopeException.match_kind == kind,
                CertificateScopeException.match_value == value,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.reason = _text(reason, 1000) or existing.reason
        existing.expires_at = expires_at
        await db.flush()
        return existing
    exception = CertificateScopeException(
        match_kind=kind,
        match_value=value,
        reason=_text(reason, 1000),
        created_by=user_id,
        expires_at=expires_at,
    )
    db.add(exception)
    await db.flush()
    return exception


async def exceptions_payload(db: AsyncSession, *, now: datetime | None = None) -> list[dict]:
    instant = now or datetime.now(timezone.utc)
    rows = list(
        (
            await db.execute(
                select(CertificateScopeException).order_by(CertificateScopeException.created_at)
            )
        ).scalars()
    )
    return [
        {
            "id": row.id,
            "match_kind": row.match_kind,
            "match_value": row.match_value,
            "reason": row.reason,
            "created_by": row.created_by,
            "expires_at": row.expires_at,
            "expired": row.expires_at is not None and _utc(row.expires_at, instant) <= instant,
            "created_at": row.created_at,
        }
        for row in rows
    ]


async def identities_payload(
    db: AsyncSession,
    *,
    verdict: str | None = None,
    foreign_only: bool = False,
    page: int = 1,
    size: int = 50,
) -> tuple[list[dict], int]:
    """The triage view: certificates with the places they were observed.

    The filters are part of the query rather than a pass over a page, so the total a
    caller paginates against is the total of the set it asked for.
    """
    matching = select(TLSCertificateSighting.id).where(
        TLSCertificateSighting.identity_id == TLSCertificateIdentity.id
    )
    if verdict:
        matching = matching.where(TLSCertificateSighting.verdict == verdict)
    if foreign_only:
        matching = matching.where(TLSCertificateSighting.is_ours.is_(False))
    filtered = select(TLSCertificateIdentity.id).where(exists(matching))
    total = int((await db.execute(select(func.count()).select_from(filtered.subquery()))).scalar() or 0)
    rows = list(
        (
            await db.execute(
                select(TLSCertificateIdentity)
                .where(TLSCertificateIdentity.id.in_(filtered))
                .order_by(TLSCertificateIdentity.last_seen_at.desc(), TLSCertificateIdentity.id)
                .offset((page - 1) * size)
                .limit(size)
            )
        ).scalars()
    )
    # Two reads, not a join fan-out: an identity's sightings are what the review
    # workflow acts on, and a page is at most a few hundred of them.
    if rows:
        sightings = list(
            (
                await db.execute(
                    select(TLSCertificateSighting)
                    .where(TLSCertificateSighting.identity_id.in_([row.id for row in rows]))
                    .order_by(TLSCertificateSighting.last_seen_at.desc())
                )
            ).scalars()
        )
    else:
        sightings = []
    grouped: dict[UUID, list[TLSCertificateSighting]] = {}
    for sighting in sightings:
        grouped.setdefault(sighting.identity_id, []).append(sighting)
    items: list[dict] = []
    for identity in rows:
        related = grouped.get(identity.id, [])
        items.append(
            {
                "id": identity.id,
                "fingerprint_sha256": identity.fingerprint_sha256,
                "fingerprint_sha1": identity.fingerprint_sha1,
                "spki_sha256": identity.spki_sha256,
                "serial_hex": identity.serial_hex,
                "subject_dn": identity.subject_dn,
                "issuer_dn": identity.issuer_dn,
                "not_before": identity.not_before,
                "not_after": identity.not_after,
                "san_dns": identity.san_dns or [],
                "key_algo": identity.key_algo,
                "origin": identity.origin,
                "first_seen_at": identity.first_seen_at,
                "last_seen_at": identity.last_seen_at,
                "sightings": [
                    {
                        "id": item.id,
                        "subject": item.subject,
                        "subjects": sighting_subjects(item),
                        "ip": item.ip,
                        "port": item.port,
                        "source": item.source,
                        "is_ours": item.is_ours,
                        "confidence": item.confidence,
                        "signals": item.signals or {},
                        "verdict": item.verdict,
                        "first_seen_at": item.first_seen_at,
                        "last_seen_at": item.last_seen_at,
                        "reviewed_at": item.reviewed_at,
                        "review_note": item.review_note,
                    }
                    for item in related
                ],
                "foreign_sightings": sum(1 for item in related if not item.is_ours),
            }
        )
    return items, total


async def run_certificate_sweep(db: AsyncSession, *, now: datetime | None = None) -> dict:
    """Project, then score: the whole Design B step, idempotent per sweep."""
    projected = await project_observations(db)
    evaluated = await evaluate_identities(db, now=now)
    await db.commit()
    return {**projected, **evaluated}
