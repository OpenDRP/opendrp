import math
import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    extract_ip,
    get_db,
    require_admin,
    require_analyst_or_admin,
    require_viewer_plus,
)
from app.core.audit import AuditLogger
from app.core.exceptions import ConflictException, NotFoundException
from app.schemas.asset import (
    AssetCreate,
    AssetCriticality,
    AssetListResponse,
    AssetResponse,
    AssetUpdate,
)
from app.schemas.common import PaginatedResponse
from app.schemas.user import AssetType
from app.services.asset_service import AssetService

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get("", response_model=AssetListResponse)
async def list_assets(
    request: Request,
    asset_type: AssetType | None = None,
    criticality: AssetCriticality | None = None,
    is_active: bool | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    skip = (page - 1) * size
    items, total = await AssetService(db).list_assets(
        asset_type=asset_type,
        criticality=criticality,
        is_active=is_active,
        search=search,
        skip=skip,
        limit=size,
    )
    await AuditLogger.emit_background(
        db,
        action="asset.list",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "asset_type": str(asset_type) if asset_type else None,
            "criticality": str(criticality) if criticality else None,
            "is_active": is_active,
            "search_used": bool(search),
            "page": page,
            "size": size,
            "results": int(total),
        },
    )
    pages = math.ceil(total / size) if size > 0 else 0
    return PaginatedResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.post("", response_model=AssetResponse, status_code=201)
async def create_asset(
    request: Request,
    data: AssetCreate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    try:
        asset = await AssetService(db).create_asset(data)
    except ConflictException:
        raise
    await AuditLogger.emit(
        db,
        action="asset.create",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "asset_id": str(asset.id),
            "asset_type": str(asset.asset_type),
            "asset_value": str(asset.asset_value),
            "criticality": str(asset.criticality),
        },
    )
    return asset


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    request: Request,
    asset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    asset = await AssetService(db).get_asset(asset_id)
    if not asset:
        raise NotFoundException("Asset not found")
    await AuditLogger.emit_background(
        db,
        action="asset.view",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "asset_id": str(asset.id),
            "asset_type": str(asset.asset_type),
            "asset_value": str(asset.asset_value),
        },
    )
    return asset


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    request: Request,
    asset_id: uuid.UUID,
    data: AssetUpdate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    service = AssetService(db)
    asset = await service.get_asset(asset_id)
    if not asset:
        raise NotFoundException("Asset not found")
    changes = list(data.model_dump(exclude_unset=True).keys())
    updated = await service.update_asset(asset, data)
    await AuditLogger.emit(
        db,
        action="asset.update",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "asset_id": str(asset_id),
            "changed_fields": changes,
        },
    )
    return updated


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    request: Request,
    asset_id: uuid.UUID,
    cascade_findings: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    service = AssetService(db)
    asset = await service.get_asset(asset_id)
    if not asset:
        raise NotFoundException("Asset not found")
    details = {
        "asset_id": str(asset.id),
        "asset_type": str(asset.asset_type),
        "asset_value": str(asset.asset_value),
        "cascade_findings": cascade_findings,
    }
    phishing_deleted, breach_deleted, generic_deleted = await service.delete_asset(
        asset, cascade_findings=cascade_findings
    )
    details.update(
        {
            "phishing_findings_deleted": phishing_deleted,
            "breach_findings_deleted": breach_deleted,
            "generic_findings_deleted": generic_deleted,
        }
    )
    await AuditLogger.emit(
        db,
        action="asset.delete",
        ip_address=extract_ip(request),
        user_id=user.id,
        details=details,
    )
    return None
