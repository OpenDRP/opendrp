"""Connector findings ingestion.

The *only* write path for connector-discovered data. Normalized findings
submitted by connectors are validated, persisted with the same dedup
semantics as before the refactor (unique phishing domain / unique breach
pairs), enriched (whois for phishing), and *enqueued* into the durable alert
queue (``AlertDeliveryService``), which a worker drains. Nothing here calls the
providers directly: SMTP or Telegram being down must not delay, fail or roll
back a finding that is already durable. Connectors never touch the DB.
"""

from datetime import date as _date

import structlog
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Connector, Finding, PhishingDomain
from app.schemas.connector import sanitize_attributes
from app.services.connector_manifest import (
    GENERIC_ADAPTER,
    ModuleSpec,
    declared_dedup_key,
    declared_title,
)
from app.services.alert_delivery_service import AlertDeliveryService
from app.services.module_registry import get_module

log = structlog.get_logger()

_MAX_FINDINGS_PER_BATCH = 500
_MAX_BLOB_LEN = 2048


def _clean_str(v, limit: int) -> str:
    if v is None:
        return ""
    return str(v).strip()[:limit]


def _parse_nonnegative_int(v) -> int:
    """Parse provider counters without letting malformed payloads abort a job."""
    try:
        value = int(v or 0)
    except (TypeError, ValueError):
        return 0
    return max(value, 0)


def _parse_date(v) -> "_date":
    """Defensively parse a breach date; malformed input -> 1970-01-01.

    Pure module-level function (pinned by characterization tests): accepts
    ``date`` instances, ISO ``YYYY-MM-DD`` strings (first 10 chars), and
    falls back to the epoch date for anything else.
    """
    if v is None:
        return _date(1970, 1, 1)
    if isinstance(v, _date):
        return v
    try:
        return _date.fromisoformat(str(v)[:10])
    except (ValueError, TypeError):
        return _date(1970, 1, 1)


def _breach_attributes(finding: dict) -> dict:
    """Provider payload of a breach finding.

    A source knows things the core has no column for (verification flags,
    exposed-secret samples, catalog timestamps). Those travel in ``attributes``
    and are validated here; anything sent outside that field is a payload the
    protocol does not declare, and is dropped rather than folded in.
    """
    declared = finding.get("attributes")
    if not isinstance(declared, dict):
        return {}
    return sanitize_attributes(declared, strict=False)


async def ingest_phishing_finding(
    db: AsyncSession,
    connector: Connector,
    finding: dict,
    *,
    connector_name: str | None = None,
    job_id=None,
) -> bool:
    """Persist one normalized phishing finding. Returns True when stored.

    Recognized fields (all optional except phishing_domain):
      phishing_domain, matched_asset, ip_address, web_ports,
      original_domain, detection_source.
    """
    # Read connector attributes immediately: commits below expire the ORM
    # object and expired-attribute access is sync IO (forbidden in async).
    conn_name = connector_name or connector.name
    ph_domain = _clean_str(finding.get("phishing_domain"), 512)
    if not ph_domain:
        log.warning("ingest_phishing_missing_domain", connector=conn_name)
        return False

    threat = PhishingDomain(
        phishing_domain=ph_domain,
        matched_asset=_clean_str(finding.get("matched_asset") or "", 512) or "unknown",
        ip_address=_clean_str(finding.get("ip_address"), 255) or None,
        web_ports=_clean_str(finding.get("web_ports"), 255) or None,
        detection_source=_clean_str(finding.get("detection_source") or conn_name, 100),
        original_domain=_clean_str(finding.get("original_domain"), 512) or None,
        status="active",
    )
    try:
        db.add(threat)
        await db.commit()
    except IntegrityError:
        # Unique phishing_domain: already known — skip quietly, no alert.
        await db.rollback()
        log.debug("ingest_phishing_duplicate", domain=ph_domain)
        return False
    except Exception as exc:
        await db.rollback()
        log.warning("ingest_phishing_failed", domain=ph_domain, err=str(exc)[:200])
        return False

    await db.refresh(threat)

    # Enrichment stays core-side (whois), best-effort.
    try:
        from app.services.phishing.whois_service import WhoisService

        await WhoisService(db).enrich(threat)
    except Exception as exc:
        log.warning("ingest_whois_failed", domain=ph_domain, err=str(exc)[:200])

    # Persist the notification event only. Delivery is performed by a separate
    # worker, so SMTP/Telegram outages cannot delay or fail finding ingestion.
    try:
        await AlertDeliveryService(db).enqueue(
            job_id=job_id,
            threat_type="phishing",
            details={
                "phishing_domain": threat.phishing_domain,
                "ip_address": threat.ip_address,
                "matched_asset": threat.matched_asset,
                "detection_source": threat.detection_source,
                "original_domain": threat.original_domain,
                "whois_abuse_email": threat.whois_abuse_email,
                "created_at": threat.created_at.isoformat() if threat.created_at else None,
            },
        )
        await db.commit()
    except Exception as exc:
        # The finding is already durable. A queue failure is visible in the
        # service log and can be retried by the next scan; never roll back the
        # intelligence result because notification infrastructure is down.
        await db.rollback()
        log.warning("alert_queue_enqueue_failed", domain=ph_domain, err=str(exc)[:200])

    return True


async def ingest_breach_finding(
    db: AsyncSession,
    connector: Connector,
    finding: dict,
    *,
    connector_name: str | None = None,
    job_id=None,
) -> bool:
    """Persist one normalized breach finding. Returns True when stored.

    Provider-neutral fields: breach_name, title, domain, breach_date, pwn_count,
    description, data_classes, matched_email, matched_domain. Anything a source
    knows beyond that travels in ``attributes`` (re-sanitized here even though
    the protocol boundary already validated it, because direct service callers
    reach this function without going through the wire schema).
    """
    conn_name = connector_name or connector.name
    from app.models import Breach

    breach_name = _clean_str(finding.get("breach_name"), 255)
    if not breach_name:
        log.warning("ingest_breach_missing_name", connector=conn_name)
        return False

    matched_email = _clean_str(finding.get("matched_email"), 255) or None
    matched_domain = _clean_str(finding.get("matched_domain"), 255) or None
    if not matched_email and not matched_domain:
        log.warning(
            "ingest_breach_missing_match", breach=breach_name, connector=conn_name
        )
        return False

    attributes = _breach_attributes(finding)
    breach = Breach(
        breach_name=breach_name,
        title=_clean_str(finding.get("title") or breach_name, 255),
        domain=_clean_str(finding.get("domain"), 255),
        breach_date=_parse_date(finding.get("breach_date")),
        pwn_count=_parse_nonnegative_int(finding.get("pwn_count")),
        description=_clean_str(finding.get("description"), 10000) or None,
        data_classes=finding.get("data_classes") if isinstance(finding.get("data_classes"), list) else [],
        matched_email=matched_email,
        matched_domain=matched_domain,
        attributes=attributes,
    )
    try:
        db.add(breach)
        await db.commit()
    except IntegrityError:
        await db.rollback()
        log.debug("ingest_breach_duplicate", breach=breach_name, email=matched_email)
        return False
    except Exception as exc:
        await db.rollback()
        log.warning("ingest_breach_failed", breach=breach_name, err=str(exc)[:200])
        return False

    try:
        await AlertDeliveryService(db).enqueue(
            job_id=job_id,
            threat_type="breach",
            details={
                "breach_name": breach.breach_name,
                "title": breach.title,
                "domain": breach.domain,
                "breach_date": str(breach.breach_date),
                "pwn_count": breach.pwn_count,
                "data_classes": breach.data_classes or [],
                "matched_email": breach.matched_email,
                "matched_domain": breach.matched_domain,
                # The source's own payload travels as it was stored: the alert
                # names no vendor field, so a new source needs no change here.
                "attributes": dict(attributes or {}),
            },
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        log.warning("alert_queue_enqueue_failed", breach=breach_name, err=str(exc)[:200])

    return True


async def ingest_generic_finding(
    db: AsyncSession,
    connector: Connector,
    finding: dict,
    *,
    module_spec: ModuleSpec,
    connector_name: str | None = None,
    job_id=None,
) -> bool:
    """Persist one finding of a registry-declared module. Returns True when stored.

    The module's own record drives everything: which fields identify it (the
    unique dedup key), what headline to show, and that the whole validated
    payload is stored as JSON. No core code knows this module exists.
    """
    conn_name = connector_name or connector.name
    dedup_key = declared_dedup_key(module_spec, finding)
    if not dedup_key or set(dedup_key.split("|")) == {""}:
        # A declared module must be deduplicated; an empty key would mean
        # "store everything again", so it is refused rather than guessed at.
        log.warning(
            "ingest_generic_missing_dedup_key",
            module=module_spec.id,
            connector=conn_name,
        )
        return False

    row = Finding(
        module=module_spec.id,
        finding_kind=module_spec.finding_kind,
        connector_name=conn_name,
        job_id=job_id,
        dedup_key=dedup_key,
        title=declared_title(module_spec, finding),
        matched_asset=_clean_str(finding.get("matched_asset"), 512) or None,
        status="active",
        payload=finding,
    )
    try:
        db.add(row)
        await db.commit()
    except IntegrityError:
        # Unique (module, dedup_key): already known — skip quietly, no alert.
        await db.rollback()
        log.debug("ingest_generic_duplicate", module=module_spec.id, key=dedup_key)
        return False
    except Exception as exc:
        await db.rollback()
        log.warning(
            "ingest_generic_failed", module=module_spec.id, err=str(exc)[:200]
        )
        return False

    try:
        await AlertDeliveryService(db).enqueue(
            job_id=job_id,
            threat_type=f"module:{module_spec.id}",
            details={
                "module_label": module_spec.label,
                "module": module_spec.id,
                "title": row.title,
                "matched_asset": row.matched_asset,
                "fields": {
                    name: finding.get(name)
                    for name in module_spec.declared_field_names
                    if finding.get(name) not in (None, "")
                },
                "source": conn_name,
            },
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        log.warning(
            "alert_queue_enqueue_failed", module=module_spec.id, err=str(exc)[:200]
        )

    return True


#: Write adapter name -> persister. The *module record* names the adapter, so the
#: write path never branches on which connector submitted a finding; these two
#: exist because the platform's original modules own domain-specific enrichment
#: and alert rendering. Every other module uses ``generic``.
_NATIVE_INGESTORS = {
    "phishing": ingest_phishing_finding,
    "breach": ingest_breach_finding,
}


async def ingest_findings(
    db: AsyncSession,
    *,
    connector: Connector,
    job_id,
    findings: list[dict],
    connector_name: str | None = None,
    connector_type: str | None = None,
    finding_kind: str | None = None,
    module_spec: ModuleSpec | None = None,
) -> tuple[int, int]:
    """Batch entry point. Returns (accepted, rejected).

    ``connector_name``, ``connector_type`` and ``finding_kind`` are accepted as
    immutable request-context values so a long batch does not depend on
    potentially expired SQLAlchemy ORM attributes after an earlier finding
    commits. The module specification decides the write adapter; when a caller
    does not supply one it is loaded from the registry (so a submission can never
    be persisted through an adapter the module did not declare).
    """
    if not isinstance(findings, list):
        return 0, 0
    batch = findings[:_MAX_FINDINGS_PER_BATCH]
    conn_name = connector_name
    module = connector_type
    if not module:
        # The HTTP endpoint always passes the snapshot; a direct caller may omit
        # it, and then it is read from the connector row.
        try:
            module = connector.connector_type
        except Exception:
            module = None
    if not conn_name:
        try:
            conn_name = connector.name
        except Exception:
            conn_name = None
    if module_spec is None and module:
        module_spec = await get_module(db, str(module))
    if module_spec is None or not conn_name:
        # An unknown module (or a connector that vanished) rejects the batch:
        # never silently reinterpret a payload the caller labelled.
        log.warning(
            "ingest_connector_context_unavailable",
            module=str(module or ""),
            kind=str(finding_kind or ""),
        )
        return 0, len(batch)
    if finding_kind and str(finding_kind) != module_spec.finding_kind:
        # A caller that labelled the payload with another module's kind is a
        # contract violation: reject rather than persist under the wrong module.
        log.warning(
            "ingest_finding_kind_mismatch",
            module=module_spec.id,
            declared=module_spec.finding_kind,
            given=str(finding_kind),
        )
        return 0, len(batch)

    adapter = module_spec.adapter
    native_ingestor = _NATIVE_INGESTORS.get(adapter)
    accepted = rejected = 0
    for raw in batch:
        if not isinstance(raw, dict):
            rejected += 1
            continue
        if native_ingestor is not None:
            ok = await native_ingestor(
                db, connector, raw, connector_name=conn_name, job_id=job_id
            )
        elif adapter == GENERIC_ADAPTER:
            ok = await ingest_generic_finding(
                db,
                connector,
                raw,
                module_spec=module_spec,
                connector_name=conn_name,
                job_id=job_id,
            )
        else:
            log.warning("ingest_unknown_write_adapter", adapter=adapter)
            return 0, len(batch)
        if ok:
            accepted += 1
        else:
            rejected += 1
    return accepted, rejected
