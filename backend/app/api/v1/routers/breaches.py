import math
import uuid

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, or_, select
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
from app.models.asset import Asset, AssetType
from app.models.breach import Breach
from app.schemas.common import PaginatedResponse
from app.schemas.phishing import ThreatStatus
from app.schemas.breaches import (
    BreachListResponse,
    BreachResponse,
    BreachScanDomainRequest,
    BreachScanEmailRequest,
)

router = APIRouter(prefix="/breaches", tags=["Breaches"])

# Rate-limit scopes. Targeted lookups are throttled per connector name; the
# module-wide rescan is throttled once per module, because it fans out to every
# enabled breaches connector and is the action an operator repeats by accident.
_SCOPE_CONNECTOR = "manual_lookup"
_SCOPE_MODULE = "breaches"


class BreachStatusUpdate(BaseModel):
    status: ThreatStatus

async def _asset_matches_for_breaches(
    db: AsyncSession, breaches: list[Breach]
) -> dict[uuid.UUID, tuple[str, str]]:
    """Resolve breach rows to currently configured monitored assets."""
    candidates: set[str] = set()
    for breach in breaches:
        if breach.matched_domain:
            candidates.add(str(breach.matched_domain).strip().lower())
        if breach.matched_email:
            email = str(breach.matched_email).strip().lower()
            candidates.add(email)
            if "@" in email:
                candidates.add(email.rsplit("@", 1)[1])
    if not candidates:
        return {}

    result = await db.execute(
        select(Asset).where(func.lower(Asset.asset_value).in_(candidates))
    )
    assets_by_value = {
        str(asset.asset_value).strip().lower(): asset for asset in result.scalars().all()
    }
    resolved: dict[uuid.UUID, tuple[str, str]] = {}
    for breach in breaches:
        email = str(breach.matched_email or "").strip()
        domain = str(breach.matched_domain or "").strip()
        inferred_domain = email.rsplit("@", 1)[1] if "@" in email else ""
        # Precedence: an exact *email-account* asset wins over the domain
        # derived from that same address. When both a mailbox and its parent
        # domain are monitored, the finding is about the mailbox, and naming
        # the domain told the analyst nothing about which account was exposed.
        # The domain candidate is still used when no email asset matches.
        for value, asset_type in (
            (email, AssetType.email_account.value),
            (domain or inferred_domain, AssetType.domain.value),
        ):
            asset = assets_by_value.get(value.lower()) if value else None
            if asset is not None:
                asset_type_value = getattr(asset.asset_type, "value", asset.asset_type)
                if str(asset_type_value) == asset_type:
                    resolved[breach.id] = (str(asset.asset_value), asset_type)
                    break
    return resolved


def _breach_payload(
    breach: Breach, resolved_asset: tuple[str, str] | None = None
) -> dict:
    payload = {column.name: getattr(breach, column.name) for column in breach.__table__.columns}
    payload["matched_asset"] = resolved_asset[0] if resolved_asset else None
    payload["matched_asset_type"] = resolved_asset[1] if resolved_asset else None
    return payload


def _breach_audit_snapshot(breach: Breach, breach_id: uuid.UUID) -> dict:
    """Audit details snapshot of a breach (identical for view and delete)."""
    return {
        "breach_id": str(breach_id),
        "breach_name": str(breach.breach_name or ""),
        "matched_email": str(breach.matched_email or ""),
        "matched_domain": str(breach.matched_domain or ""),
        "domain": str(breach.domain or ""),
    }


@router.get("", response_model=BreachListResponse)
async def list_breaches(
    request: Request,
    search: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    skip = (page - 1) * size
    stmt = select(Breach)
    count_stmt = select(func.count(Breach.id)).select_from(Breach)

    conditions = []
    if search:
        raw_search = search.strip()[:100]
        escaped = raw_search.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        like = f"%{escaped}%"
        conditions.append(
            or_(
                Breach.matched_email.ilike(like, escape="\\"),
                Breach.matched_domain.ilike(like, escape="\\"),
                Breach.domain.ilike(like, escape="\\"),
                Breach.breach_name.ilike(like, escape="\\"),
            )
        )

    if conditions:
        stmt = stmt.where(*conditions)
        count_stmt = count_stmt.where(*conditions)

    stmt = stmt.order_by(Breach.created_at.desc(), Breach.id.desc()).offset(skip).limit(size)

    items_result = await db.execute(stmt)
    items = list(items_result.scalars().all())
    matched_assets = await _asset_matches_for_breaches(db, items)


    total_result = await db.execute(count_stmt)
    total = total_result.scalar() or 0

    pages = math.ceil(total / size) if size > 0 else 0
    await AuditLogger.emit_background(
        db,
        action="breach.list",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "search_used": bool(search),
            "page": page,
            "size": size,
            "results": int(total),
        },
    )
    return PaginatedResponse(
        items=[_breach_payload(item, matched_assets.get(item.id)) for item in items],
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.post("/cleanup-orphans")
async def clean_orphan_breach_findings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Delete breach findings that are not linked to any configured asset."""
    from app.services.asset_service import AssetService

    deleted = await AssetService(db).clean_orphan_breach_findings()
    await AuditLogger.emit(
        db,
        action="breach.orphans.cleaned",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"deleted": deleted},
    )
    return {"status": "completed", "deleted": deleted}


@router.get("/{breach_id}", response_model=BreachResponse)
async def get_breach(
    request: Request,
    breach_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    result = await db.execute(select(Breach).where(Breach.id == breach_id))
    breach = result.scalar_one_or_none()
    if not breach:
        raise NotFoundException("Breach not found")
    matched_assets = await _asset_matches_for_breaches(db, [breach])
    await AuditLogger.emit_background(
        db,
        action="breach.view",
        ip_address=extract_ip(request),
        user_id=user.id,
        details=_breach_audit_snapshot(breach, breach_id),
    )
    return _breach_payload(breach, matched_assets.get(breach.id))
@router.patch("/{breach_id}", response_model=BreachResponse)
async def update_breach(
    request: Request,
    breach_id: uuid.UUID,
    data: BreachStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    result = await db.execute(select(Breach).where(Breach.id == breach_id))
    breach = result.scalar_one_or_none()
    if not breach:
        raise NotFoundException("Breach not found")
    breach.status = data.status
    await db.commit()
    await db.refresh(breach)
    await AuditLogger.emit(
        db,
        action="breach.update",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"breach_id": str(breach_id), "changed_fields": ["status"]},
    )
    matched_assets = await _asset_matches_for_breaches(db, [breach])
    return _breach_payload(breach, matched_assets.get(breach.id))


@router.post("/scan")
async def run_breach_scan(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    """Enqueue one pending scan job per enabled breaches connector."""
    from app.services.connector_service import ConnectorService

    await enforce_manual_rate_limit(
        db=db,
        user=user,
        scope=_SCOPE_MODULE,
        action="breach rescan (all sources)",
        ip_address=extract_ip(request),
    )

    try:
        jobs = await ConnectorService(db).enqueue_module_scan(
            connector_type="breaches",
            created_by=user.id,
            title="Breach rescan (all sources)",
            params={"trigger": "manual"},
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
        action="breach.scan.start",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "status": status,
            "error": error,
            "jobs": [str(j.id) for j in jobs],
        },
    )
    resp_payload: dict = {"status": status, "job_ids": [str(j.id) for j in jobs]}
    if error:
        resp_payload["error"] = error
    return resp_payload


@router.post("/scan-email", status_code=202)
async def scan_email_breaches(
    request: Request,
    payload: BreachScanEmailRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    from app.services.connector_service import ConnectorService

    await enforce_manual_rate_limit(
        db=db,
        user=user,
        scope=_SCOPE_CONNECTOR,
        action="breach email lookup",
        ip_address=extract_ip(request),
    )

    jobs = await ConnectorService(db).enqueue_module_scan(
        connector_type="breaches",
        created_by=user.id,
        title=f"Breach email scan: {payload.email}",
        params={"trigger": "manual", "emails": [str(payload.email)], "domains": []},
    )
    await AuditLogger.emit(
        db, action="breach.scan.email", ip_address=extract_ip(request), user_id=user.id,
        details={"email": str(payload.email), "job_ids": [str(j.id) for j in jobs]},
    )
    return {"status": "scheduled", "email": str(payload.email), "job_ids": [str(j.id) for j in jobs]}


@router.post("/scan-domain", status_code=202)
async def scan_domain_breaches(
    request: Request,
    payload: BreachScanDomainRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    from app.services.connector_service import ConnectorService

    await enforce_manual_rate_limit(
        db=db,
        user=user,
        scope=_SCOPE_CONNECTOR,
        action="breach domain lookup",
        ip_address=extract_ip(request),
    )

    jobs = await ConnectorService(db).enqueue_module_scan(
        connector_type="breaches",
        created_by=user.id,
        title=f"Breach domain scan: {payload.domain}",
        params={"trigger": "manual", "emails": [], "domains": [payload.domain]},
    )
    await AuditLogger.emit(
        db, action="breach.scan.domain", ip_address=extract_ip(request), user_id=user.id,
        details={"domain": payload.domain, "job_ids": [str(j.id) for j in jobs]},
    )
    return {"status": "scheduled", "domain": payload.domain, "job_ids": [str(j.id) for j in jobs]}


@router.delete("/{breach_id}", status_code=204)
async def delete_breach(
    request: Request,
    breach_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    result = await db.execute(select(Breach).where(Breach.id == breach_id))
    breach = result.scalar_one_or_none()
    if not breach:
        raise NotFoundException("Breach not found")
    details = _breach_audit_snapshot(breach, breach_id)
    await db.delete(breach)
    await db.commit()
    await AuditLogger.emit(
        db,
        action="breach.delete",
        ip_address=extract_ip(request),
        user_id=user.id,
        details=details,
    )
    return None
