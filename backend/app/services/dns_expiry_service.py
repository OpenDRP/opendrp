from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.asset import Asset, AssetType
from app.models.dns_expiry_monitor import DNSExpiryMonitor
from app.models.dns_observation import DNSObservation
from app.models.module import Module
from app.services.alert_delivery_service import AlertDeliveryService
from app.services.asset_matching import POLICY_SCAN, asset_scope, sql_key
from app.services.dns_expiry_monitor_service import utc

_THRESHOLDS = (30, 14, 7, 3, 1)


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
        active_asset, evidence_exists, DNSExpiryMonitor.state == "verified",
        DNSExpiryMonitor.successful_at >= instant - timedelta(hours=settings.DNS_EXPIRY_MAX_AGE_HOURS),
        DNSExpiryMonitor.successful_at <= instant,
        DNSExpiryMonitor.expires_at <= instant + timedelta(days=30),
    ).order_by(DNSExpiryMonitor.expires_at, DNSExpiryMonitor.id).limit(5000).with_for_update(skip_locked=True))).scalars())
    queued = 0
    for row in rows:
        if row.expires_at is None or row.successful_at is None:
            continue
        threshold = due_threshold(row.expires_at, instant)
        if threshold is None or threshold in (row.alerted_thresholds or []):
            continue
        seconds = (utc(row.expires_at) - instant).total_seconds()
        label = "Domain registration" if row.kind == "registration" else "Observed certificate"
        timing = "has expired" if threshold == 0 else f"expires in {math.ceil(seconds / 86400)} day(s)"
        alert = await AlertDeliveryService(db).enqueue(
            threat_type="dns",
            details={
                "module_label": f"{label} expiry",
                "title": f"{row.subject}: {label.lower()} {timing}",
                "fields": {
                    "Subject": row.subject, "Expiry kind": row.kind,
                    "Expires at (UTC)": utc(row.expires_at).isoformat(),
                    "Days remaining": str(max(0, math.ceil(seconds / 86400))),
                    "Threshold": "expired" if threshold == 0 else str(threshold),
                    "Last successful check (UTC)": utc(row.successful_at).isoformat(),
                    "Certificate ID": row.certificate_id or "Not applicable",
                    "Evidence": "Passive CT evidence; deployment on the service is not verified" if row.kind == "certificate" else "RDAP registration expiry",
                },
            },
        )
        if alert is not None:
            row.alerted_thresholds = list(row.alerted_thresholds or []) + [threshold]
            queued += 1
    await db.commit()
    return queued
