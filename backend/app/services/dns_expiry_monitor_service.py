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


def tls_port(row: DNSObservation) -> int:
    """The port a probe's control belongs to.

    The worker names it twice — in `metadata.port` and in `record_type`
    (`TLS:8443`, with plain `TLS` for the default port) — and either spelling is
    enough. 443 is the answer when neither names one, which is the port the
    worker probes by default.
    """
    port = (row.metadata_json or {}).get("port")
    if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
        return port
    record_type = row.record_type or ""
    if record_type.startswith("TLS:"):
        try:
            candidate = int(record_type[4:])
        except ValueError:
            return 443
        if 0 < candidate < 65536:
            return candidate
    return 443


def tls_kind(row: DNSObservation) -> str:
    """The control kind for one probed certificate: `tls:<port>` (AUD-036).

    A control keyed by asset alone made a second port overwrite the first: the
    unique key is (asset, kind), every probe became `kind="tls"`, and the
    thresholds the first port had already sent were cleared with it. The port is
    part of the thing being reminded about, so it is part of the key.
    """
    return f"tls:{tls_port(row)}"


def kind_is_tls(kind: str) -> bool:
    """Whether a control kind is a live-TLS one, with or without its port."""
    return kind == "tls" or kind.startswith("tls:")


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
    elif row.observation_type == "tls_probe":
        # The one control kind that answers "what is served now" instead of "what was
        # issued": its evidence is a handshake this platform performed against its own
        # asset, which is what makes a reminder actionable (F-05 in the DNS & TLS audit).
        # The port is part of the control's identity (AUD-036).
        kind = tls_kind(row)
        state = str(row.metadata_json.get("check_state", ""))
        if state not in {"verified", "expired", "failed", "incomplete", "skipped_no_public_address"}:
            raise ValueError("invalid tls probe state")
        cert_id = row.metadata_json.get("certificate_id")
        issued = parse_date(row.metadata_json.get("not_before"))
        if state == "verified" and (
            not isinstance(cert_id, str) or not cert_id or len(cert_id) > 128
            or issued is None or issued > utc(now)
            or row.expires_at is None or utc(row.expires_at) <= issued
        ):
            raise ValueError("invalid served certificate")
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
    if kind.startswith("tls:"):
        await _adopt_portless_tls_control(db, asset.id, kind)
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
    if state in {"failed", "incomplete", "skipped_no_public_address"}:
        # Preserve prior evidence and cycle, but never alert from a check that did not
        # produce a certificate: a failed handshake and a host with no public address
        # are both silence about the served certificate, not evidence about it.
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
    # A successful check ends a staleness episode, so the "control has not been
    # checked" warning is owed again the next time this control goes quiet.
    monitor.stale_alerted_at = None
    monitor.successful_at = checked
    monitor.expires_at = expiry
    monitor.certificate_id = cert_id if isinstance(cert_id, str) else None
    monitor.not_before = issued
    monitor.observation_id = row.id


async def _adopt_portless_tls_control(db: AsyncSession, asset_id, kind: str) -> None:
    """Rename a pre-port TLS control to the port it was actually probing.

    An installation built before the port dimension holds one `kind="tls"` row
    per asset. The first probe to arrive for that asset renames it in place, so
    the threshold history it carries survives and the next sweep finds it under
    the port key. Idempotent: a control already at the port key is left alone,
    and the rename never creates a second row.
    """
    port_row = (
        await db.execute(
            select(DNSExpiryMonitor.id).where(
                DNSExpiryMonitor.asset_id == asset_id, DNSExpiryMonitor.kind == kind
            )
        )
    ).first()
    if port_row is not None:
        return
    portless = (
        await db.execute(
            select(DNSExpiryMonitor)
            .where(DNSExpiryMonitor.asset_id == asset_id, DNSExpiryMonitor.kind == "tls")
            .with_for_update()
        )
    ).scalar_one_or_none()
    if portless is not None:
        portless.kind = kind
        await db.flush()


def monitor_payload(row: DNSExpiryMonitor, now: datetime) -> dict:
    return {
        "kind": row.kind, "state": monitor_state(row, now), "checked_at": row.checked_at,
        "successful_at": row.successful_at, "expires_at": row.expires_at,
        "certificate_id": row.certificate_id, "not_before": row.not_before,
        "alerted_thresholds": row.alerted_thresholds,
        "remaining_seconds": (utc(row.expires_at) - utc(now)).total_seconds() if row.expires_at else None,
    }
