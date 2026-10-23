import asyncio
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_active_account
from app.api.v1.routers.alerts import AlertChannelsHealthResponse
from app.api.v1.routers.connectors import ConnectorHealthResponse
from app.core import health
from app.core.audit import AuditLogger, audit_is_degraded
from app.core.config import settings

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


class BreachKpiCaptions(BaseModel):
    """What each breach number counts, in the words the page prints.

    The captions travel with the numbers because the report carries the same object:
    an operator comparing the two documents is comparing one definition, and a
    caption that vanished from this answer would leave the page printing a number
    without the sentence that says what it counts.
    """

    total_findings: str
    active_findings_7d: str
    new_incidents_7d: str
    findings_by_exposure_kind: str


class BreachKpi(BaseModel):
    """The breach half of the KPI, from the one rule the report also reads (WI-16).

    `catalogue_synced_at` is ISO text for the same reason `_iso` exists in
    `breach_kpi`: the source's own date carries no offset, and the conversion is the
    composer's decision rather than this model's.
    """

    window_days: int
    total_findings: int
    findings_by_exposure_kind: dict[str, int]
    active_findings_7d: int
    new_incidents_7d: int
    catalogue_incidents: int
    undated_incidents: int
    catalogue_sources: int
    catalogue_synced_at: str | None
    captions: BreachKpiCaptions


class DashboardKpi(BaseModel):
    """The four headline numbers, plus the breach block they are explained by."""

    total_assets: int
    total_phishing: int
    total_breaches: int
    active_threats_7d: int
    new_breach_incidents_7d: int
    breach: BreachKpi


class PhishingBySource(BaseModel):
    source: str
    count: int


class AssetsByCriticality(BaseModel):
    """One criticality's share of the active inventory.

    `criticality` stays a plain string: the column is written through a validated
    literal today, and a row adopted from elsewhere should be printed under its own
    name rather than fail every block of the first screen over one asset.
    """

    criticality: str
    count: int


class DashboardTimelineSeries(BaseModel):
    """One line of the chart: a registry module that records dated findings."""

    key: str
    label: str
    module_id: str


class DashboardTimelineExcluded(BaseModel):
    """A module the chart does not count, with the reason code."""

    module_id: str
    label: str
    reason: str


class DashboardTimelineComparison(BaseModel):
    """One series' totals for the window and for the 30 days before it (U-4)."""

    current: int
    previous: int


class DashboardTimelineDay(BaseModel):
    """A calendar day with one count per series key.

    The keys are data: they are the module ids the registry declares, so the model
    allows extras and the composer stays the only place that decides which modules a
    day counts.
    """

    date: str

    model_config = ConfigDict(extra="allow")


class LongestSilence(BaseModel):
    """The longest silence among enabled connectors; `seconds: null` is never-seen."""

    name: str
    seconds: int | None


class PlatformConnectors(BaseModel):
    enabled: int
    disabled: int
    silent: int
    longest_silence: LongestSilence | None


class PlatformDeliveryCounts(BaseModel):
    pending: int
    delivering: int
    sent: int
    failed: int
    cancelled: int
    ambiguous: int


class PlatformDeliveries(BaseModel):
    counts: PlatformDeliveryCounts
    stuck: int
    waiting_recipients: int


class PlatformStatus(BaseModel):
    """Self-diagnostics computed inside this answer, from the probes `/ready` runs."""

    database: Literal["ok", "error"]
    redis: Literal["ok", "error"]
    audit_degraded: bool
    connectors: PlatformConnectors
    oldest_running_job_seconds: int | None
    deliveries: PlatformDeliveries


class DashboardStats(BaseModel):
    """The summary half of the dashboard, as `/dashboard/stats` also answers it."""

    kpi: DashboardKpi
    timeline: list[DashboardTimelineDay]
    timeline_series: list[DashboardTimelineSeries]
    timeline_excluded: list[DashboardTimelineExcluded]
    timeline_comparison: dict[str, DashboardTimelineComparison]
    phishing_by_source: list[PhishingBySource]
    assets_by_criticality: list[AssetsByCriticality]
    platform: PlatformStatus


class DashboardOverview(BaseModel):
    """Everything the dashboard draws, in one request and one audit row (DHP-10).

    The three sections are the payloads the page used to fetch separately, and two of
    them reuse the models those endpoints already declare: a second declaration of one
    reading would be a second contract to keep in step.
    """

    summary: DashboardStats
    connectors: ConnectorHealthResponse
    channels: AlertChannelsHealthResponse
    generated_at: datetime


async def _stats_payload(db: AsyncSession, now: datetime) -> dict:
    """The summary half of the dashboard, with no audit row of its own.

    Shared by ``GET /dashboard/stats`` and ``GET /dashboard/overview`` (DHP-10),
    so the two entry points cannot publish different numbers for the same page.
    The caller owns the trail entry its request deserves.
    """
    from app.models import Asset, DrpPhishingDomain as P
    from app.models.connector import Connector
    from app.models.job import Job
    from app.services.alert_delivery_service import AlertDeliveryService
    from app.services.breach_kpi import breach_kpi

    total_assets = (await db.execute(select(func.count(Asset.id)).where(Asset.is_active.is_(True)))).scalar_one()
    total_ph = (await db.execute(select(func.count(P.id)))).scalar_one()
    # The breach half of every KPI comes from the shared rule the report reads too, so
    # the two pages cannot publish different definitions of the same number (WI-16).
    breach = await breach_kpi(db, now=now)
    total_hb = breach["total_findings"]
    seven = now - timedelta(days=7)
    open_statuses = ("active", "investigating")
    active_phishing = (
        await db.execute(
            select(func.count(P.id)).where(
                P.created_at >= seven,
                P.status.in_(open_statuses),
            )
        )
    ).scalar_one()
    active_threats_7d = int(active_phishing or 0) + int(breach["active_findings_7d"] or 0)

    # The series are the registry's, not this file's (DHP-11): a module that
    # declares dated findings appears in the row without a change here or in the
    # page, and an adapter that stores current state is excluded by name. The
    # service also computes the previous 30-day window, so "more than last month"
    # is answerable from the same data instead of a second endpoint.
    from app.services.dashboard_timeline import build_timeline

    timeline_result = await build_timeline(db, now=now)
    timeline = timeline_result.rows

    pb = (await db.execute(select(P.detection_source, func.count(P.id)).group_by(P.detection_source))).all()
    phishing_by_source = [{"source": src or "unknown", "count": cnt} for (src, cnt) in pb]

    ab = (await db.execute(select(Asset.criticality, func.count(Asset.id)).where(Asset.is_active.is_(True)).group_by(Asset.criticality))).all()
    assets_by_criticality = [{"criticality": c or "medium", "count": cnt} for (c, cnt) in ab]

    # Platform self-diagnostics, computed here rather than fetched by the page
    # from a fourth endpoint (D11): the block must not add a request, an audit
    # row or a second view of rules that already exist in `/ready` and
    # `core/metrics.py`. The dependency probes are the same functions `/ready`
    # calls, not HTTP calls to ourselves, and they are bounded so a hung probe
    # cannot hold the dashboard.
    async def _dependency(probe) -> str:
        try:
            await asyncio.wait_for(probe(), timeout=2.0)
            return "ok"
        except Exception:
            return "error"

    database_state, redis_state = await asyncio.gather(
        _dependency(health.check_database), _dependency(health.check_redis)
    )

    stale_after = int(settings.CONNECTOR_HEALTH_STALE_AFTER_SECONDS)
    connector_rows = (
        await db.execute(select(Connector.name, Connector.status, Connector.last_seen_at))
    ).all()
    enabled_connectors = sum(1 for _name, status, _seen in connector_rows if status == "enabled")
    silent_connectors = 0
    longest_silence: dict | None = None
    for name, status, last_seen in connector_rows:
        if status != "enabled":
            continue
        if last_seen is not None:
            seen = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
            silence = int((now - seen.astimezone(timezone.utc)).total_seconds())
        else:
            # Never having checked in is the worst silence, not a missing value.
            silence = None
        if silence is None or silence > stale_after:
            silent_connectors += 1
        # Never seen outranks every measurable silence: it is the worst case.
        rank = float("inf") if silence is None else silence
        if longest_silence is None or rank > longest_silence["rank"]:
            longest_silence = {"name": name, "seconds": silence, "rank": rank}
    if longest_silence is not None:
        longest_silence.pop("rank")

    oldest_running = (
        await db.execute(select(func.min(Job.created_at)).where(Job.status == "running"))
    ).scalar()
    oldest_running_seconds = None
    if oldest_running is not None:
        started = (
            oldest_running
            if oldest_running.tzinfo
            else oldest_running.replace(tzinfo=timezone.utc)
        )
        oldest_running_seconds = int((now - started.astimezone(timezone.utc)).total_seconds())

    delivery_by_channel, waiting_recipients = await AlertDeliveryService(
        db
    ).channel_delivery_summary(
        stuck_after_seconds=int(settings.ALERT_RECIPIENT_HOLD_SECONDS)
    )
    delivery_counts = {
        name: 0
        for name in ("pending", "delivering", "sent", "failed", "cancelled", "ambiguous")
    }
    stuck_deliveries = 0
    for summary in delivery_by_channel.values():
        for name, count in summary["counts"].items():
            delivery_counts[name] = delivery_counts.get(name, 0) + int(count)
        stuck_deliveries += int(summary["stuck"])

    platform = {
        "database": database_state,
        "redis": redis_state,
        # The marker `/ready` serves 503 on: serving mutations while audit writes
        # fail leaves an unreviewable window, so it belongs on the first screen,
        # not only behind a probe URL nobody opens.
        "audit_degraded": audit_is_degraded(),
        "connectors": {
            "enabled": enabled_connectors,
            "disabled": len(connector_rows) - enabled_connectors,
            "silent": silent_connectors,
            "longest_silence": longest_silence,
        },
        "oldest_running_job_seconds": oldest_running_seconds,
        "deliveries": {
            "counts": delivery_counts,
            "stuck": stuck_deliveries,
            "waiting_recipients": waiting_recipients,
        },
    }

    return {
        "kpi": {
            "total_assets": total_assets,
            "total_phishing": total_ph,
            "total_breaches": total_hb,
            "active_threats_7d": active_threats_7d,
            # Findings are what happened to our accounts; these are what the sources
            # added to their own catalogues, whether or not any address of ours is in
            # them. The two are printed apart because they are not the same fact.
            "new_breach_incidents_7d": breach["new_incidents_7d"],
            # The same object the report's KPI carries, captions included: an operator
            # comparing the two documents is comparing one definition, not two.
            "breach": breach,
        },
        "timeline": timeline,
        # What the row is made of: one entry per registry module whose storage
        # carries dated findings, with the label the registry gives it.
        "timeline_series": [
            {"key": item.key, "label": item.label, "module_id": item.module_id}
            for item in timeline_result.series
        ],
        # Modules the row does not count, with the reason — never a silent zero.
        "timeline_excluded": [
            {"module_id": item.module_id, "label": item.label, "reason": item.reason}
            for item in timeline_result.excluded
        ],
        # Each series against the 30 days before the window (U-4).
        "timeline_comparison": timeline_result.comparison,
        "phishing_by_source": phishing_by_source,
        "assets_by_criticality": assets_by_criticality,
        # Additive: the page reads the block from the query it already makes.
        "platform": platform,
    }


async def _record_view(
    db: AsyncSession, *, request: Request, user, payload: dict, sections: list[str]
) -> dict:
    """Write the one ``dashboard.view`` row a page load is worth.

    ``sections`` names what the response contained, so a trail entry for the
    single-request overview is as specific as the three it replaced: a reader can
    still tell which health views were included in what the account saw.
    """
    kpi = payload["kpi"]
    await AuditLogger.emit_background(
        db,
        action="dashboard.view",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "total_assets": int(kpi["total_assets"]),
            "total_phishing": int(kpi["total_phishing"]),
            "total_breaches": int(kpi["total_breaches"]),
            "active_threats_7d": kpi["active_threats_7d"],
            "new_breach_incidents_7d": kpi["new_breach_incidents_7d"],
            "sections": sections,
        },
    )
    return payload


@router.get("/stats")
async def dashboard_stats(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    payload = await _stats_payload(db, datetime.now(timezone.utc))
    return await _record_view(
        db, request=request, user=user, payload=payload, sections=["summary"]
    )


@router.get("/overview", response_model=DashboardOverview)
async def dashboard_overview(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    """Everything the dashboard shows, in one request and one audit row.

    The page used to load its summary, connector health and channel health as
    three requests in three transactions, each writing its own audit entry and
    each spending one acquisition of the audit chain's advisory lock (DHP-10).
    This endpoint computes the same three sections here, from the same functions
    the standalone endpoints call, and records one ``dashboard.view`` naming
    them; the lock is transactional, so one row in one transaction is one
    acquisition.

    ``/connectors/health`` and ``/alerts/health`` keep their own contracts: the
    DNS page reads the first, and both are documented in ``docs/api.md``. This
    is an addition, not a replacement.
    """
    from app.api.v1.routers.alerts import channel_health_payload
    from app.api.v1.routers.connectors import connector_health_items

    now = datetime.now(timezone.utc)
    summary = await _stats_payload(db, now)
    connector_items, connectors_generated_at = await connector_health_items(
        db, user=user, now=now
    )
    # The reads are over before any network work: an SMTP probe may hold its
    # worker for the whole budget, and the pooled connection must not be held
    # with it (D9). The channel helper commits for itself before probing.
    channel_items, delivery_queue, blocked = await channel_health_payload(db)
    # The channel probes can take their whole budget, so the envelope's time is
    # taken after them: `generated_at` says when the answer was assembled, not
    # when the page started asking (DHP-06). `checked_at` on each channel still
    # says when that probe actually ran, and `from_cache` says if it ran at all.
    assembled_at = datetime.now(timezone.utc)

    await _record_view(
        db,
        request=request,
        user=user,
        payload=summary,
        sections=["summary", "connectors", "channels"],
    )
    if blocked:
        # A refused destination stays a security event on this path too; it is
        # not a view row and only appears when a probe was actually refused.
        await AuditLogger.emit_background(
            db,
            action="outbound.blocked",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={"operation": "alert_channel_probe", "channels": blocked},
        )

    return DashboardOverview(
        summary=DashboardStats(**summary),
        connectors=ConnectorHealthResponse(
            items=connector_items, generated_at=connectors_generated_at
        ),
        channels=AlertChannelsHealthResponse(
            items=channel_items,
            delivery_queue=delivery_queue,
            generated_at=assembled_at,
        ),
        generated_at=assembled_at,
    )
