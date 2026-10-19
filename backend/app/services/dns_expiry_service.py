from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.asset import Asset, AssetType
from app.models.dns_expiry_monitor import DNSExpiryMonitor
from app.models.dns_observation import DNSObservation
from app.models.module import Module
from app.services.alert_delivery_service import AlertDeliveryService
from app.services.asset_matching import POLICY_SCAN, asset_scope, sql_key
from app.services.dns_expiry_monitor_service import monitor_state, utc

_THRESHOLDS = (30, 14, 7, 3, 1)

#: How many freshness windows a control may miss before the platform says so. One
#: window is the normal gap between daily scans, so the warning waits for the second.
_STALE_FACTOR = 2


def due_threshold(expires_at: datetime, now: datetime) -> int | None:
    days = (utc(expires_at) - utc(now)).total_seconds() / 86400
    if days <= 0:
        return 0
    return next((day for day in reversed(_THRESHOLDS) if days <= day), None)


async def queue_expiry_alerts(db: AsyncSession, *, now: datetime | None = None) -> int:
    instant = utc(now or datetime.now(timezone.utc))
    enabled = (await db.execute(select(Module.enabled).where(Module.id == "dns"))).scalar_one_or_none()
    if not enabled:
        return 0
    # Lock only control rows, not the nullable sides of joins. Provider ingestion
    # takes the same lock; queue writes and threshold history share one commit.
    active_asset = exists(select(Asset.id).where(Asset.id == DNSExpiryMonitor.asset_id, Asset.asset_type == AssetType.domain, *asset_scope(POLICY_SCAN), sql_key(Asset.normalized_value) == sql_key(DNSExpiryMonitor.subject)))
    evidence_exists = exists(select(DNSObservation.id).where(DNSObservation.id == DNSExpiryMonitor.observation_id))
    rows = list((await db.execute(select(DNSExpiryMonitor).where(
        # "expired" is a state of its own: a handshake that found the certificate already
        # past its notAfter is the most urgent reminder there is, and it has no threshold
        # to reach - `due_threshold` answers 0 for it.
        active_asset, evidence_exists, DNSExpiryMonitor.state.in_(["verified", "expired"]),
        DNSExpiryMonitor.successful_at >= instant - timedelta(hours=settings.DNS_EXPIRY_MAX_AGE_HOURS),
        DNSExpiryMonitor.successful_at <= instant,
        DNSExpiryMonitor.expires_at <= instant + timedelta(days=30),
    ).order_by(DNSExpiryMonitor.expires_at, DNSExpiryMonitor.id).limit(5000).with_for_update(skip_locked=True))).scalars())
    # The served certificate's probe details live on the control row's metadata, not on
    # the monitor: reading them here keeps the reminder reproducible (which IP and port
    # were probed) without widening the monitor table for one kind.
    probe_evidence: dict = {}
    observation_ids = [row.observation_id for row in rows if row.kind == "tls" and row.observation_id]
    if observation_ids:
        evidence_rows = (await db.execute(select(DNSObservation.id, DNSObservation.metadata_json).where(DNSObservation.id.in_(observation_ids)))).all()
        # Spelled out as a pair rather than handed to ``dict()``: a ``Row`` is a two-member
        # tuple to the reader and a named tuple to the ORM, and the pair is what says so.
        probe_evidence = {row[0]: row[1] for row in evidence_rows}
    queued = 0
    for row in rows:
        if row.expires_at is None or row.successful_at is None:
            continue
        threshold = due_threshold(row.expires_at, instant)
        if threshold is None or threshold in (row.alerted_thresholds or []):
            continue
        seconds = (utc(row.expires_at) - instant).total_seconds()
        label = {"registration": "Domain registration", "tls": "Live TLS certificate"}.get(row.kind, "Observed certificate")
        timing = "has expired" if threshold == 0 else f"expires in {math.ceil(seconds / 86400)} day(s)"
        fields = {
            "Subject": row.subject, "Expiry kind": row.kind,
            "Expires at (UTC)": utc(row.expires_at).isoformat(),
            "Days remaining": str(max(0, math.ceil(seconds / 86400))),
            "Threshold": "expired" if threshold == 0 else str(threshold),
            "Last successful check (UTC)": utc(row.successful_at).isoformat(),
            "Certificate ID": row.certificate_id or "Not applicable",
        }
        if row.kind == "tls":
            metadata = probe_evidence.get(row.observation_id) or {}
            fields["Probed address"] = str(metadata.get("probe_ip") or "unknown")[:64]
            fields["Probed port"] = str(metadata.get("port") or "unknown")[:6]
            fields["Evidence"] = "Active TLS probe of the service (verified handshake)"
        elif row.kind == "certificate":
            fields["Evidence"] = "Passive CT evidence; deployment on the service is not verified"
        else:
            fields["Evidence"] = "RDAP registration expiry"
        alert = await AlertDeliveryService(db).enqueue(
            threat_type="dns",
            details={
                "module_label": f"{label} expiry",
                "title": f"{row.subject}: {label.lower()} {timing}",
                "fields": fields,
            },
        )
        if alert is not None:
            row.alerted_thresholds = list(row.alerted_thresholds or []) + [threshold]
            queued += 1
    await db.commit()
    return queued


async def queue_stale_monitor_alerts(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Report the controls that have silently stopped being checked (F-16).

    A source that stopped running, a disabled connector and a deactivated domain all
    look the same from this table: rows that age. The page shows ``stale`` for whoever
    opens it, which is exactly the problem - the platform holds both the fact
    (``successful_at``) and the channel, and said nothing. Every control that has not
    been checked successfully for two freshness windows therefore queues one warning
    here, on the same aggregated delivery path as everything else in this module, and
    a successful check clears the marker so the notice can be repeated when the
    control next goes quiet.

    The threshold is a multiple of ``DNS_EXPIRY_MAX_AGE_HOURS`` rather than an
    independent setting: a single window is the ordinary gap between two scans, and
    calling a control stale at the exact moment its next check is due would report
    every healthy installation.
    """
    instant = utc(now or datetime.now(timezone.utc))
    enabled = (await db.execute(select(Module.enabled).where(Module.id == "dns"))).scalar_one_or_none()
    if not enabled:
        return 0
    freshness = timedelta(hours=settings.DNS_EXPIRY_MAX_AGE_HOURS * _STALE_FACTOR)
    # The same scope the reminders use: a monitor for an asset the operator no longer
    # monitors is not a control that has gone quiet, it is one that was retired, and
    # warning about it would be noise the operator cannot act on.
    active_asset = exists(select(Asset.id).where(Asset.id == DNSExpiryMonitor.asset_id, Asset.asset_type == AssetType.domain, *asset_scope(POLICY_SCAN), sql_key(Asset.normalized_value) == sql_key(DNSExpiryMonitor.subject)))
    rows = list((await db.execute(select(DNSExpiryMonitor).where(
        active_asset,
        DNSExpiryMonitor.stale_alerted_at.is_(None),
        func.coalesce(DNSExpiryMonitor.successful_at, DNSExpiryMonitor.checked_at) <= instant - freshness,
        DNSExpiryMonitor.checked_at <= instant,
    ).order_by(DNSExpiryMonitor.checked_at, DNSExpiryMonitor.id).limit(5000).with_for_update(skip_locked=True))).scalars())
    label = {"registration": "Domain registration", "tls": "Live TLS certificate"}
    hours = settings.DNS_EXPIRY_MAX_AGE_HOURS * _STALE_FACTOR
    queued = 0
    for row in rows:
        reference = utc(row.successful_at or row.checked_at)
        control = label.get(row.kind, "Observed certificate")
        alert = await AlertDeliveryService(db).enqueue(
            threat_type="dns",
            details={
                "severity": "warning",
                "module_label": "Expiry monitoring",
                "title": f"{row.subject}: {control.lower()} has not been checked for over {hours} hours",
                "fields": {
                    "Subject": row.subject,
                    "Expiry kind": row.kind,
                    "Control state": monitor_state(row, instant),
                    "Last successful check (UTC)": utc(row.successful_at).isoformat() if row.successful_at else "never",
                    "Last check attempt (UTC)": utc(row.checked_at).isoformat(),
                    "Expires at (UTC)": utc(row.expires_at).isoformat() if row.expires_at else "unknown",
                    "Reason": f"No successful check since {reference.isoformat()}; the source may have stopped, the connector may be disabled, or the domain may be inactive.",
                },
            },
        )
        if alert is not None:
            row.stale_alerted_at = instant
            queued += 1
    await db.commit()
    return queued
