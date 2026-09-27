import math
import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import ColumnElement, and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    extract_ip,
    get_db,
    require_analyst_or_admin,
    require_admin,
    require_viewer_plus,
)
from app.core.audit import AuditLogger
from app.core.exceptions import NotFoundException
from app.services.scan_admission import NoEnabledConnector, ScanAdmissionUnavailable, ScanAlreadyRunning
from app.core.manual_rate_limit import enforce_manual_rate_limit
from app.models import DrpPhishingDomain
from app.schemas.common import PaginatedResponse
from app.schemas.phishing import (
    DetectionSource,
    PhishingListResponse,
    PhishingThreatResponse,
    PhishingThreatUpdate,
    ThreatStatus,
)

router = APIRouter(prefix="/phishing", tags=["Phishing"])


@router.get("/threats", response_model=PhishingListResponse)
async def list_threats(
    request: Request,
    detection_source: DetectionSource | None = None,
    status: ThreatStatus | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    D = DrpPhishingDomain
    skip = (page - 1) * size
    q = select(D)
    w: list[ColumnElement[bool]] = []
    if detection_source:
        w.append(D.detection_source == detection_source)
    if status:
        w.append(D.status == status)
    if search:
        raw_search = search.strip()[:100]
        escaped = raw_search.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        like = f"%{escaped}%"
        w.append(or_(
            D.phishing_domain.ilike(like, escape="\\"),
            D.ip_address.ilike(like, escape="\\"),
            D.matched_asset.ilike(like, escape="\\"),
        ))
    if w:
        q = q.where(and_(*w))
    # No-arg and_() is a SQL-true clause; same semantics as the former
    # ``and_(*w) if w else True`` expression without the bool union.
    total = (
        await db.execute(select(func.count(D.id)).where(and_(*w)))
    ).scalar_one()
    items = list((await db.execute(q.order_by(D.created_at.desc(), D.id.desc()).offset(skip).limit(size))).scalars().all())
    pages = math.ceil(total / size) if size > 0 else 0
    await AuditLogger.emit_background(
        db,
        action="phishing.threat.list",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "detection_source": str(detection_source) if detection_source else None,
            "status": str(status) if status else None,
            "search_used": bool(search),
            "page": page,
            "size": size,
            "results": int(total),
        },
    )
    return PaginatedResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.post("/threats/cleanup-orphans")
async def clean_orphan_phishing_findings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Delete phishing findings that are not linked to any configured asset."""
    from app.services.asset_service import AssetService

    deleted = await AssetService(db).clean_orphan_phishing_findings()
    await AuditLogger.emit(
        db,
        action="phishing.threat.orphans.cleaned",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"deleted": deleted},
    )
    return {"status": "completed", "deleted": deleted}


@router.get("/threats/{threat_id}", response_model=PhishingThreatResponse)
async def get_threat(
    request: Request,
    threat_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    t = (await db.execute(select(DrpPhishingDomain).where(DrpPhishingDomain.id == threat_id))).scalar_one_or_none()
    if not t:
        raise NotFoundException("Phishing threat not found")
    await AuditLogger.emit_background(
        db,
        action="phishing.threat.view",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "threat_id": str(threat_id),
            "phishing_domain": str(t.phishing_domain),
            "ip_address": str(t.ip_address or ""),
            "status": str(t.status or ""),
        },
    )
    return t


@router.patch("/threats/{threat_id}", response_model=PhishingThreatResponse)
async def update_threat(
    request: Request,
    threat_id: uuid.UUID,
    data: PhishingThreatUpdate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    D = DrpPhishingDomain
    t = (await db.execute(select(D).where(D.id == threat_id))).scalar_one_or_none()
    if not t:
        raise NotFoundException("Phishing threat not found")
    changes = list(data.model_dump(exclude_unset=True).keys())
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(t, k, v)
    await db.commit()
    await db.refresh(t)
    await AuditLogger.emit(
        db,
        action="phishing.threat.update",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "threat_id": str(threat_id),
            "changed_fields": changes,
        },
    )
    return t


@router.post("/scan/dnstwist", status_code=202, response_model=dict)
async def trigger_dnstwist_scan(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    """Enqueue one pending scan job per enabled phishing connector.

    Connectors claim the work via their work-poll; the core stays stateless
    with respect to connector execution.
    """
    from app.services.connector_service import ConnectorService

    # Scope = connector name, so a phishing rescan never consumes the report
    # module's window (and vice versa).
    await enforce_manual_rate_limit(
        db=db,
        user=user,
        scope="dnstwist",
        action="phishing rescan (dnstwist)",
        ip_address=extract_ip(request),
    )

    try:
        jobs = await ConnectorService(db).enqueue_module_scan(
            connector_type="phishing",
            created_by=user.id,
            title="Phishing domain scan",
            params={"trigger": "manual"},
            connector_name="dnstwist",
        )
        status = "scheduled"
        error = None
    except NoEnabledConnector as e:
        jobs = []
        status = "no_connector"
        error = str(e.detail)[:200]
    except (ScanAlreadyRunning, ScanAdmissionUnavailable):
        raise
    await AuditLogger.emit(
        db,
        action="phishing.scan.dnstwist.start",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "status": status,
            "error": error,
            "jobs": [str(j.id) for j in jobs],
        },
    )
    payload: dict = {"status": status, "job_ids": [str(j.id) for j in jobs]}
    if error:
        payload["error"] = error
    return payload


@router.post("/scan/shodan", status_code=202, response_model=dict)
async def trigger_shodan_scan(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    from app.services.connector_service import ConnectorService

    await enforce_manual_rate_limit(
        db=db,
        user=user,
        scope="shodan",
        action="phishing rescan (shodan)",
        ip_address=extract_ip(request),
    )

    try:
        jobs = await ConnectorService(db).enqueue_module_scan(
            connector_type="phishing",
            created_by=user.id,
            title="Shodan brand hunting scan",
            params={"trigger": "manual"},
            connector_name="shodan",
        )
        status = "scheduled"
        error = None
    except NoEnabledConnector as e:
        jobs = []
        status = "no_connector"
        error = str(e.detail)[:200]
    except (ScanAlreadyRunning, ScanAdmissionUnavailable):
        raise
    await AuditLogger.emit(
        db,
        action="phishing.scan.shodan.start",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "status": status,
            "error": error,
            "jobs": [str(j.id) for j in jobs],
        },
    )
    payload: dict = {"status": status, "job_ids": [str(j.id) for j in jobs]}
    if error:
        payload["error"] = error
    return payload


@router.delete("/threats/{threat_id}", status_code=204)
async def delete_threat(
    request: Request,
    threat_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    D = DrpPhishingDomain
    t = (await db.execute(select(D).where(D.id == threat_id))).scalar_one_or_none()
    if not t:
        raise NotFoundException("Phishing threat not found")
    details = {
        "threat_id": str(threat_id),
        "phishing_domain": str(t.phishing_domain),
        "ip_address": str(t.ip_address or ""),
        "matched_asset": str(t.matched_asset or ""),
        "detection_source": str(t.detection_source or ""),
    }
    await db.delete(t)
    await db.commit()
    await AuditLogger.emit(
        db,
        action="phishing.threat.delete",
        ip_address=extract_ip(request),
        user_id=user.id,
        details=details,
    )
    return None
