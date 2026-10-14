from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.asset import Asset, AssetType
from app.models.dns_expiry_monitor import DNSExpiryMonitor
from app.models.dns_observation import DNSObservation
from app.services.asset_matching import POLICY_SCAN, asset_scope, key_variants, sql_key


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def parse_date(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        return utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def monitor_state(row: DNSExpiryMonitor, now: datetime) -> str:
    if row.successful_at and utc(row.successful_at) < utc(now) - timedelta(hours=settings.DNS_EXPIRY_MAX_AGE_HOURS):
        return "stale"
    if row.state == "verified" and row.observation_id is None:
        return "unverified"
    return row.state


async def update_monitor(db: AsyncSession, row: DNSObservation, *, now: datetime) -> None:
    state: str
    if row.source == "rdap" and row.observation_type == "rdap":
        kind = "registration"
        state = "failed" if row.metadata_json.get("check_state") == "failed" else "verified" if row.expires_at else "unknown"
        cert_id, issued = None, None
    elif row.source == "ctlogs" and row.observation_type == "certificate_check":
        kind = "certificate"
        state = str(row.metadata_json.get("check_state", ""))
        if state not in {"verified", "no_certificate", "future_only", "failed", "incomplete"}:
            raise ValueError("invalid certificate check state")
        cert_id = row.metadata_json.get("certificate_id")
        issued = parse_date(row.metadata_json.get("not_before"))
        if state == "verified" and (not isinstance(cert_id, str) or not cert_id or len(cert_id) > 128 or issued is None or issued > utc(now) or row.expires_at is None or utc(row.expires_at) <= issued):
            raise ValueError("invalid selected certificate")
    else:
        return
    checked = parse_date(row.metadata_json.get("checked_at")) if row.metadata_json.get("checked_at") else now
    if checked is None or checked > utc(now) + timedelta(minutes=5):
        raise ValueError("invalid check timestamp")
    asset = (await db.execute(select(Asset).where(Asset.asset_type == AssetType.domain, sql_key(Asset.normalized_value).in_(sorted(key_variants(row.subject))), *asset_scope(POLICY_SCAN)).limit(1))).scalar_one_or_none()
    if asset is None:
        return
    values = dict(asset_id=asset.id, kind=kind, subject=row.subject, state="unverified", checked_at=now, alerted_thresholds=[])
    if db.bind.dialect.name == "postgresql":
        await db.execute(pg_insert(DNSExpiryMonitor).values(**values).on_conflict_do_nothing(index_elements=["asset_id", "kind"]))
    else:
        await db.execute(sqlite_insert(DNSExpiryMonitor).values(**values).on_conflict_do_nothing(index_elements=["asset_id", "kind"]))
    monitor = (await db.execute(select(DNSExpiryMonitor).where(DNSExpiryMonitor.asset_id == asset.id, DNSExpiryMonitor.kind == kind).with_for_update())).scalar_one()
    if utc(checked) < utc(monitor.checked_at) and monitor.state != "unverified":
        return
    monitor.checked_at = checked
    monitor.state = state
    if state in {"failed", "incomplete"}:
        # Preserve prior evidence and cycle, but never alert from a failed check.
        return
    expiry = utc(row.expires_at) if row.expires_at else None
    cycle = hashlib.sha256(f"{kind}|{cert_id or ''}|{expiry.isoformat() if expiry else ''}".encode()).hexdigest()
    if monitor.cycle is None:
        # Registration backfill retained already queued thresholds.
        if monitor.expires_at is None or expiry != utc(monitor.expires_at):
            monitor.alerted_thresholds = []
    elif cycle != monitor.cycle:
        monitor.alerted_thresholds = []
    monitor.cycle = cycle
    monitor.successful_at = checked
    monitor.expires_at = expiry
    monitor.certificate_id = cert_id if isinstance(cert_id, str) else None
    monitor.not_before = issued
    monitor.observation_id = row.id


def monitor_payload(row: DNSExpiryMonitor, now: datetime) -> dict:
    return {
        "kind": row.kind, "state": monitor_state(row, now), "checked_at": row.checked_at,
        "successful_at": row.successful_at, "expires_at": row.expires_at,
        "certificate_id": row.certificate_id, "not_before": row.not_before,
        "alerted_thresholds": row.alerted_thresholds,
        "remaining_seconds": (utc(row.expires_at) - utc(now)).total_seconds() if row.expires_at else None,
    }
