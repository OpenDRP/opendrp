"""Validated, idempotent connector ingestion with caller-owned transactions."""

from datetime import date as _date, datetime
from dataclasses import dataclass, field
import json

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from app.models import Finding, PhishingDomain, Breach, Job
from app.services.alert_delivery_service import (
    AlertDeliveryService,
)  # findings reach the alert queue through this service
from app.schemas.connector import sanitize_attributes, MAX_FINDINGS_PER_BATCH
from app.services.connector_manifest import (
    GENERIC_ADAPTER,
    declared_dedup_key,
    declared_title,
)
from app.services.module_registry import get_module
from app.services.dns_security_service import ingest_dns_observations
from app.services.source_observations import persist, source_identity
from app.services.ingestion_events import record_event

__all__ = ["AlertDeliveryService"]

_MAX_FINDINGS_PER_BATCH = MAX_FINDINGS_PER_BATCH


def _json_safe(value):
    """Round-trip a finding into strict JSON-native primitives.

    The HTTP adapter already serializes Pydantic models this way, but service
    callers and plugins are also untrusted boundaries. Handle only stable scalar
    conversions rather than leaking Python reprs into persisted payloads.
    """

    def encode(item):
        if isinstance(item, (_date, datetime)):
            return str(item)
        if hasattr(item, "hex") and item.__class__.__module__ == "uuid":
            return str(item)
        raise TypeError(f"unsupported finding value: {type(item).__name__}")

    try:
        return json.loads(json.dumps(value, default=encode, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ValueError("finding is not JSON serializable") from exc


def _clean_str(value, limit):
    return str(value).strip()[:limit] if value is not None else ""


def _parse_nonnegative_int(value):
    try:
        return max(0, int(value or 0))
    except (ValueError, TypeError):
        return 0


def _parse_date(value):
    if isinstance(value, _date):
        return value
    try:
        return _date.fromisoformat(str(value)[:10])
    except (ValueError, TypeError):
        return _date(1970, 1, 1)


def _breach_attributes(finding):
    return sanitize_attributes(finding.get("attributes") or {}, strict=False)


@dataclass
class IngestionResult:
    received: int = 0
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    rejected: int = 0
    errors: list = field(default_factory=list)

    @property
    def accepted(self):
        return self.created + self.updated + self.unchanged

    def __iter__(self):
        yield self.accepted
        yield self.rejected

    def payload(self):
        return {
            "received": self.received,
            "created": self.created,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "errors": self.errors,
        }


async def _phishing(db, connector, finding, job_id, module_spec):
    source = source_identity(connector)
    domain = _clean_str(finding.get("phishing_domain"), 253)
    if not domain:
        raise ValueError("missing_subject")
    finding = {
        **finding,
        "matched_asset": _clean_str(finding.get("matched_asset"), 512) or "unknown",
    }
    row = (
        await db.execute(
            select(PhishingDomain).where(PhishingDomain.phishing_domain == domain)
        )
    ).scalar_one_or_none()
    created = row is None
    if row is None:
        row = PhishingDomain(
            phishing_domain=domain,
            matched_asset=finding["matched_asset"],
            ip_address=finding.get("ip_address"),
            web_ports=finding.get("web_ports"),
            detection_source=source,
            original_domain=finding.get("original_domain"),
            status="active",
        )
        db.add(row)
        await db.flush()
    row_changed = False
    if not created:
        for field_name in (
            "matched_asset",
            "ip_address",
            "web_ports",
            "original_domain",
        ):
            if (
                field_name in finding
                and finding[field_name] is not None
                and getattr(row, field_name) != finding[field_name]
            ):
                setattr(row, field_name, finding[field_name])
                row_changed = True
    changed = await persist(
        db,
        module="phishing",
        source=source,
        finding=finding,
        candidate_id=row.id,
        job_id=job_id,
        connector=connector,
        commit=False,
    )
    if created:
        await record_event(
            db,
            kind="notification",
            module="phishing",
            entity_id=row.id,
            job_id=job_id,
            payload={
                "finding_id": str(row.id),
                "evidence": finding,
                "web_ports": row.web_ports,
                "original_domain": row.original_domain,
                "status": row.status,
                "phishing_domain": domain,
                "matched_asset": row.matched_asset,
                "ip_address": row.ip_address,
                "detection_source": row.detection_source,
                "created_at": row.created_at.isoformat(),
            },
        )
        await record_event(
            db,
            kind="whois",
            module="phishing",
            entity_id=row.id,
            job_id=job_id,
            payload={},
        )
    return (
        "created" if created else "updated" if changed or row_changed else "unchanged"
    )


async def _breach(db, connector, finding, job_id, module_spec):
    source = source_identity(connector)
    name = _clean_str(finding.get("breach_name"), 255)
    email, domain = finding.get("matched_email"), finding.get("matched_domain")
    if not name or not (email or domain):
        raise ValueError("missing_breach_match")
    conditions = [Breach.source_id == source, Breach.breach_name == name]
    conditions += (
        [Breach.matched_email == email]
        if email
        else [Breach.matched_email.is_(None), Breach.matched_domain == domain]
    )
    row = (await db.execute(select(Breach).where(*conditions))).scalar_one_or_none()
    created = row is None
    if row is None:
        row = Breach(
            source_id=source,
            breach_name=name,
            title=_clean_str(finding.get("title") or name, 255),
            domain=_clean_str(finding.get("domain"), 255),
            breach_date=_parse_date(finding.get("breach_date")),
            pwn_count=_parse_nonnegative_int(finding.get("pwn_count")),
            description=_clean_str(finding.get("description"), 10000) or None,
            data_classes=finding.get("data_classes")
            if isinstance(finding.get("data_classes"), list)
            else [],
            matched_email=email,
            matched_domain=domain,
            attributes=_breach_attributes(finding),
        )
        db.add(row)
        await db.flush()
    row_changed = False
    if not created:
        refreshed = {
            "title": _clean_str(finding.get("title") or name, 255),
            "attributes": _breach_attributes(finding),
        }
        if "domain" in finding:
            refreshed["domain"] = _clean_str(finding.get("domain"), 255)
        if "breach_date" in finding:
            refreshed["breach_date"] = _parse_date(finding.get("breach_date"))
        if "pwn_count" in finding:
            refreshed["pwn_count"] = _parse_nonnegative_int(finding.get("pwn_count"))
        if "description" in finding:
            refreshed["description"] = (
                _clean_str(finding.get("description"), 10000) or None
            )
        if isinstance(finding.get("data_classes"), list):
            refreshed["data_classes"] = finding["data_classes"]
        for field_name, value in refreshed.items():
            if getattr(row, field_name) != value:
                setattr(row, field_name, value)
                row_changed = True
    evidence = {
        **finding,
        "subject": email or domain,
        "matched_asset": email or domain,
        "attributes": _breach_attributes(finding),
    }
    changed = await persist(
        db,
        module="breaches",
        source=source,
        finding=evidence,
        job_id=job_id,
        connector=connector,
        commit=False,
    )
    if created:
        await record_event(
            db,
            kind="notification",
            module="breach",
            entity_id=row.id,
            job_id=job_id,
            payload={
                "finding_id": str(row.id),
                "source": source,
                "description": row.description,
                "status": row.status,
                "created_at": row.created_at.isoformat(),
                "breach_name": name,
                "title": row.title,
                "domain": row.domain,
                "breach_date": str(row.breach_date),
                "pwn_count": row.pwn_count,
                "data_classes": row.data_classes,
                "matched_email": email,
                "matched_domain": domain,
                "attributes": row.attributes,
            },
        )
    return (
        "created" if created else "updated" if changed or row_changed else "unchanged"
    )


async def _generic(db, connector, finding, job_id, module_spec):
    source = source_identity(connector)
    key = declared_dedup_key(module_spec, finding)
    if not key or set(key.split("|")) == {""}:
        raise ValueError("missing_dedup_key")
    row = (
        await db.execute(
            select(Finding).where(
                Finding.module == module_spec.id, Finding.dedup_key == key
            )
        )
    ).scalar_one_or_none()
    if row:
        if row.payload == finding:
            return "unchanged"
        row.payload = finding
        return "updated"
    row = Finding(
        module=module_spec.id,
        finding_kind=module_spec.finding_kind,
        connector_name=connector.name,
        job_id=job_id,
        dedup_key=key,
        title=declared_title(module_spec, finding),
        matched_asset=finding.get("matched_asset"),
        status="active",
        payload=finding,
    )
    db.add(row)
    await db.flush()
    await record_event(
        db,
        kind="notification",
        module=f"module:{module_spec.id}",
        entity_id=row.id,
        job_id=job_id,
        payload={
            "module_label": module_spec.label,
            "module": module_spec.id,
            "title": row.title,
            "fields": finding,
            "source": source,
        },
    )
    return "created"


async def _dns(db, connector, finding, job_id, module_spec):
    from app.models.dns_observation import DNSObservation
    from app.services.dns_security_service import observation_key

    source = source_identity(connector)
    key = observation_key(source, finding)
    old = (
        await db.execute(
            select(DNSObservation).where(
                DNSObservation.source == source, DNSObservation.observation_key == key
            )
        )
    ).scalar_one_or_none()
    same = (
        old is not None
        and old.value == finding.get("value")
        and old.metadata_json == (finding.get("metadata") or {})
    )
    await ingest_dns_observations(db, source=source, findings=[finding], commit=False)
    return "created" if old is None else "unchanged" if same else "updated"


async def _exposure(db, connector, finding, job_id, module_spec):
    from app.models import Job
    from app.services.dns_security_service import normalize_subject

    job = await db.get(Job, job_id)
    params = job.params if job and isinstance(job.params, dict) else {}
    target = normalize_subject(finding["matched_asset"])
    subject = normalize_subject(finding["subject"])
    # Both sides of this comparison are canonicalized here, and this is the side
    # that owns it. The scan parameters carry each monitored asset exactly as the
    # operator stored it in ``Asset.asset_value`` — that is the value the
    # connector was asked to scan, and it is what ``/me/work`` hands out — while
    # the finding carries whatever the source reported. An asset entered as
    # ``Example.COM``, with a trailing dot, or in an expanded IPv6 spelling
    # therefore used to compare unequal to the canonical name coming back, and the
    # check that exists to reject an unrelated finding rejected a correct one
    # instead: the whole response was refused as ``unrelated_asset``, the job was
    # marked failed, and findings the operator never learned about were dropped.
    # ``normalize_subject`` is the platform's one canonical form for a DNS name or
    # an address (see ``app.services.dns_security_service``), so the fix belongs
    # on the comparing side rather than on the snapshot, which must keep sending
    # the stored value.
    allowed = set()
    for raw in (*params.get("domains", []), *params.get("ips", [])):
        try:
            allowed.add(normalize_subject(raw))
        except (ValueError, TypeError):
            # A value that is not a DNS name or an address cannot match a subject
            # that is, so it contributes nothing to the membership test below.
            continue
    if target not in allowed or not (
        subject == target or subject.endswith("." + target)
    ):
        raise ValueError("unrelated_asset")
    changed = await persist(
        db,
        module="exposure",
        source=source_identity(connector),
        finding=finding,
        job_id=job_id,
        connector=connector,
        commit=False,
    )
    return "updated" if changed else "unchanged"


_HANDLERS = {
    "phishing": _phishing,
    "breach": _breach,
    "dns_observation": _dns,
    "exposure": _exposure,
    GENERIC_ADAPTER: _generic,
}


async def ingest_findings(
    db,
    *,
    connector,
    job_id,
    findings,
    connector_name=None,
    connector_type=None,
    finding_kind=None,
    module_spec=None,
):
    result = IngestionResult(
        received=len(findings) if isinstance(findings, list) else 0
    )
    if not isinstance(findings, list):
        return result
    if connector is None:
        result.rejected = len(findings)
        result.errors = [
            {"index": index, "code": "invalid_contract", "retryable": False}
            for index in range(min(len(findings), MAX_FINDINGS_PER_BATCH))
        ]
        return result
    selected_type = connector_type or connector.connector_type
    spec = module_spec or await get_module(db, selected_type)
    handler = _HANDLERS.get(spec.adapter) if spec else None
    if selected_type != connector.connector_type or (
        module_spec is not None and module_spec.id != connector.connector_type
    ):
        handler = None
    if job_id is not None and await db.get(Job, job_id) is None:
        # A service caller may supply a scan correlation id without a
        # persisted job; do not write an invalid FK into the durable outbox.
        job_id = None
    # The HTTP contract rejects an over-limit request before this service is
    # called. A direct caller keeps the original bounded-prefix behavior;
    # never perform unbounded validation or persistence work.
    for index, raw in enumerate(findings[:MAX_FINDINGS_PER_BATCH]):
        if (
            not handler
            or (finding_kind and finding_kind != spec.finding_kind)
            or not isinstance(raw, dict)
        ):
            result.rejected += 1
            result.errors.append(
                {"index": index, "code": "invalid_contract", "retryable": False}
            )
            continue
        try:
            raw = _json_safe(raw)
            async with db.begin_nested():
                outcome = await handler(db, connector, raw, job_id, spec)
            setattr(result, outcome, getattr(result, outcome) + 1)
        except IntegrityError:
            # Retry a uniqueness race after only the item's savepoint rolls back.
            async with db.begin_nested():
                outcome = await handler(db, connector, raw, job_id, spec)
            setattr(result, outcome, getattr(result, outcome) + 1)
        except (ValueError, KeyError):
            result.rejected += 1
            result.errors.append(
                {"index": index, "code": "invalid_observation", "retryable": False}
            )
    await db.flush()
    return result


async def _direct(
    handler, db, connector, finding, job_id=None, module_spec=None, **kwargs
):
    if connector is None:
        return False
    if job_id is not None and await db.get(Job, job_id) is None:
        job_id = None
    spec = module_spec or await get_module(db, connector.connector_type)
    if spec is None or spec.id != connector.connector_type:
        return False
    try:
        finding = _json_safe(finding)
        outcome = await handler(db, connector, finding, job_id, spec)
        await db.flush()
        return outcome != "unchanged"
    except (ValueError, KeyError):
        return False


async def ingest_phishing_finding(db, connector, finding, **kwargs):
    return await _direct(_phishing, db, connector, finding, **kwargs)


async def ingest_breach_finding(db, connector, finding, **kwargs):
    return await _direct(_breach, db, connector, finding, **kwargs)


async def ingest_generic_finding(db, connector, finding, **kwargs):
    return await _direct(_generic, db, connector, finding, **kwargs)


async def ingest_dns_observation_finding(db, connector, finding, **kwargs):
    return await _direct(_dns, db, connector, finding, **kwargs)


async def ingest_exposure(db, connector, finding, **kwargs):
    return await _direct(_exposure, db, connector, finding, **kwargs)
