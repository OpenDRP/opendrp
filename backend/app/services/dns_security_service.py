from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import case, delete, exists, or_, select
from sqlalchemy.dialects.postgresql import Insert as PGInsert, insert as pg_insert
from sqlalchemy.dialects.sqlite import Insert as SQLiteInsert, insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, AssetType
from app.models.dns_observation import DNSObservation
from app.schemas.connector import DNSObservationPayload, DNS_NAME_RE
from app.services.asset_matching import asset_sql_key

def normalize_subject(value: str) -> str:
    """Canonicalize a validated DNS name or address for matching and display.

    The grammar is the one `app.schemas.connector` applies at the wire boundary, so a
    payload the schema accepted is never rejected here, and it includes the RFC 8552
    underscore service labels (`_dmarc.example.com`, `_sip._tcp.example.com`) under
    which a domain publishes records that are not hostnames.
    """
    raw = str(value or "").strip().rstrip(".")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        normalized = raw.encode("idna").decode("ascii").lower()
        if len(normalized) > 253 or not DNS_NAME_RE.fullmatch(normalized):
            raise ValueError("subject must be a valid DNS name or IP address")
        return normalized


def observation_key(source: str, payload: dict[str, Any]) -> str:
    """Stable source-scoped identity, including cert identifiers when present."""
    metadata = payload.get("metadata") or {}
    observation_type = payload["observation_type"]
    # `tls_probe` belongs here for the same reason `certificate_check` does: it is the
    # current answer for one host and port, so a re-probe must update that row rather
    # than leave the previous handshake as if it were still true. The certificate the
    # probe read is a separate, historical row keyed by fingerprint.
    # `vt_domain` is the provider's current reputation for the monitored name, so a
    # re-scan refreshes that row instead of accumulating one per scan the way the
    # historical discovery and certificate rows deliberately do.
    is_mutable_current_fact = observation_type in {"dns_record", "rdap", "vt_resolution", "vt_domain", "certificate_check", "tls_probe"}
    identity = {
        "source": source,
        "type": observation_type,
        "subject": normalize_subject(payload["subject"]),
        "record_type": payload.get("record_type"),
        # Current DNS/RDAP facts are mutable observations: a value change should
        # update the existing source+type+subject+record row, not leave stale state.
        # Historical certificates/subdomain sightings remain distinct by value/id.
        "value": None if is_mutable_current_fact else payload.get("value"),
        # Certificate IDs (not issuer-local serials) and wildcard scope both
        # belong to identity. Passive-DNS facts must retain their scan provenance.
        "identity": (
            None
            if is_mutable_current_fact
            else metadata.get("id") or metadata.get("fingerprint") or metadata.get("serial_hex")
        ),
    }
    # Keep the RDAP/resolver provenance keys unchanged; new dimensions are
    # needed only for evidence that can originate from multiple scan targets.
    if observation_type in {"passive_dns", "vt_resolution", "vt_subdomain", "certificate"} and metadata.get("source_domain"):
        identity["source_domain"] = normalize_subject(metadata["source_domain"])
    if observation_type == "certificate_response" and metadata.get("ip"):
        # Where an endpoint was seen is part of *which* observation it is. A provider
        # answers "where else is this certificate served" with one row per endpoint, and
        # it names the same host at several addresses; without the address in the
        # identity those rows collapse into one and the copy at the earlier address
        # disappears from the projection - the deployment rules read sightings, and a
        # vanished row is a foreign address nobody reviews.
        try:
            identity["ip"] = str(ipaddress.ip_address(str(metadata["ip"]).strip()))
        except ValueError:
            pass
    if observation_type == "passive_dns":
        # Historical record bounds change only when first/last seen changes;
        # include their window in identity so future windows do not overwrite old facts.
        for field in ("first_seen", "last_seen"):
            if metadata.get(field):
                identity[field] = str(metadata[field])
    if observation_type == "certificate" and metadata.get("wildcard") is True:
        identity["wildcard"] = True
    if observation_type == "vt_resolution":
        if metadata.get("host_name"):
            identity["host_name"] = normalize_subject(metadata["host_name"])
        if metadata.get("resolution_date"):
            identity["resolution_date"] = str(metadata["resolution_date"])
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


async def clean_orphan_observations(db: AsyncSession) -> int:
    """Remove observations without a configured subject or originating domain.

    Inactive assets still count. Certificate values and passive-DNS provenance
    link discovered hosts/IPs back to the scanned asset, not to inferred ownership.
    Use a correlated DELETE so cleanup does not load unbounded inventory into RAM.
    """
    asset_value = asset_sql_key()
    source_domain = DNSObservation.metadata_json["source_domain"].as_string()
    linked = exists(select(Asset.id).where(or_(
        (Asset.asset_type.in_([AssetType.domain, AssetType.ip_address]))
        & (asset_value == DNSObservation.subject),
        (Asset.asset_type == AssetType.domain) & or_(
            asset_value == source_domain,
            (DNSObservation.observation_type == "certificate")
            & (asset_value == DNSObservation.value),
        ),
    )))
    result = await db.execute(delete(DNSObservation).where(~linked))
    await db.commit()
    return result.rowcount or 0


async def ingest_dns_observations(
    db: AsyncSession, *, source: str, findings: list[dict[str, Any]], commit: bool = True
) -> int:
    """Insert or refresh bounded observations without erasing other providers."""
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", source):
        raise ValueError("invalid DNS source identifier")
    now = datetime.now(timezone.utc)
    rows_by_key: dict[str, dict[str, Any]] = {}
    for raw in findings[:500]:
        payload = DNSObservationPayload.model_validate(raw).model_dump()
        subject = normalize_subject(payload["subject"])
        if payload["observation_type"] in {"certificate", "tls_certificate"}:
            from app.services.dns_expiry_monitor_service import parse_date
            issued = parse_date(payload["metadata"].get("not_before"))
            if issued:
                payload["metadata"]["not_before"] = issued.isoformat()
            else:
                payload["metadata"].pop("not_before", None)
        key = observation_key(source, payload)
        rows_by_key[key] = {
            "observation_key": key,
            "observation_type": payload["observation_type"],
            "subject": subject,
            "record_type": payload.get("record_type"),
            "value": payload.get("value"),
            "source": source,
            "first_seen_at": now,
            "last_seen_at": now,
            "expires_at": payload.get("expires_at"),
            "status": payload.get("status", "current"),
            "metadata_json": payload.get("metadata") or {},
            "alerted_thresholds": [],
            "updated_at": now,
        }
    # PostgreSQL ON CONFLICT cannot update the same target twice in one INSERT.
    rows = list(rows_by_key.values())
    if not rows:
        return 0
    dialect = db.bind.dialect.name if db.bind is not None else ""
    statement: PGInsert | SQLiteInsert
    if dialect == "postgresql":
        statement = pg_insert(DNSObservation).values(rows)
        statement = statement.on_conflict_do_update(
            constraint="uq_dns_observation_source_key",
            set_={
                "observation_type": statement.excluded.observation_type,
                "subject": statement.excluded.subject,
                "record_type": statement.excluded.record_type,
                "value": statement.excluded.value,
                "last_seen_at": now,
                # Expiry alerts are per threshold and must survive normal refreshes.
                "expires_at": statement.excluded.expires_at,
                "status": statement.excluded.status,
                "metadata_json": statement.excluded.metadata_json,
                "alerted_thresholds": case(
                    (DNSObservation.expires_at.is_distinct_from(statement.excluded.expires_at), statement.excluded.alerted_thresholds),
                    else_=DNSObservation.alerted_thresholds,
                ),
                "updated_at": now,
            },
        )
    elif dialect == "sqlite":
        statement = sqlite_insert(DNSObservation).values(rows)
        statement = statement.on_conflict_do_update(
            index_elements=[DNSObservation.source, DNSObservation.observation_key],
            set_={
                "observation_type": statement.excluded.observation_type,
                "subject": statement.excluded.subject,
                "record_type": statement.excluded.record_type,
                "value": statement.excluded.value,
                "last_seen_at": now,
                # Expiry alerts are per threshold and must survive normal refreshes.
                "expires_at": statement.excluded.expires_at,
                "status": statement.excluded.status,
                "metadata_json": statement.excluded.metadata_json,
                "alerted_thresholds": case(
                    (DNSObservation.expires_at.is_distinct_from(statement.excluded.expires_at), statement.excluded.alerted_thresholds),
                    else_=DNSObservation.alerted_thresholds,
                ),
                "updated_at": now,
            },
        )
    else:
        raise RuntimeError(f"DNS observation upsert is unsupported for database {dialect!r}")
    await db.execute(statement)
    from app.services.dns_expiry_monitor_service import update_monitor

    # Every control kind has to be named here or its monitor is never written: the
    # active probe was added to this list with its own kind, and a new control type
    # that forgets it looks like a scan that succeeded and recorded nothing.
    controls = list((await db.execute(select(DNSObservation).where(DNSObservation.source == source, DNSObservation.observation_key.in_(rows_by_key), DNSObservation.observation_type.in_(["rdap", "certificate_check", "tls_probe"])).execution_options(populate_existing=True))).scalars())
    for control in controls:
        await update_monitor(db, control, now=now)
    if commit:
        await db.commit()
    else:
        await db.flush()
    return len(rows)
