"""Module registry API and the generic findings read path.

Two halves:

* **Registry** — reading it is open to any signed-in user (the module list drives
  navigation and the job-type filters); changing it is admin-only. Declaring a
  module is what makes the platform plugin-capable: the module's finding fields,
  deduplication and title are data, so a data source whose findings fit neither
  the phishing nor the breach shape needs no core release.
* **Findings** — one paginated list over generic storage, filtered by module,
  plus the triage write that moves a finding to investigating/resolved. Built-in
  modules keep their dedicated pages; this is the read path for modules that
  exist only as a registry row.
"""

import uuid
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    extract_ip,
    get_db,
    require_admin,
    require_analyst_or_admin,
    require_viewer_plus,
)
from app.core.audit import AuditLogger
from app.core.exceptions import BadRequestException, NotFoundException
from app.models import Finding
from app.schemas.common import PaginatedResponse
from app.schemas.module import (
    FindingOut,
    FindingUpdateRequest,
    ModuleCreateRequest,
    ModuleListResponse,
    ModuleOut,
    ModuleUpdateRequest,
)
from app.services.module_registry import (
    create_module,
    load_modules,
    require_module,
    set_module_enabled,
    update_module_metadata,
)

log = structlog.get_logger()

router = APIRouter(tags=["Modules"])


@router.get("/modules", response_model=ModuleListResponse)
async def list_modules(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    """Every registered module, including disabled ones (flagged as such)."""
    specs = await load_modules(db)
    await AuditLogger.emit_background(
        db,
        action="modules.list",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"count": len(specs)},
    )
    return ModuleListResponse(
        modules=[ModuleOut(**spec.to_public_dict()) for _, spec in sorted(specs.items())],
        generated_at=datetime.now(timezone.utc),
    )


@router.post("/modules", response_model=ModuleOut, status_code=201)
async def declare_module(
    payload: ModuleCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Declare a module: its fields, deduplication and headline become data."""
    spec = await create_module(
        db,
        module_id=payload.id,
        label=payload.label,
        description=payload.description,
        fields=payload.fields,
        dedup_fields=payload.dedup_fields,
        title_field=payload.title_field,
        asset_types=payload.asset_types,
    )
    await AuditLogger.emit(
        db,
        action="module.declared",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "module": spec.id,
            "finding_kind": spec.finding_kind,
            "fields": sorted(spec.fields),
            "dedup_fields": list(spec.dedup_fields),
        },
    )
    return ModuleOut(**spec.to_public_dict())


@router.patch("/modules/{module_id}", response_model=ModuleOut)
async def update_module(
    module_id: str,
    payload: ModuleUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Rename, redescribe or enable/disable a module.

    A module's finding fields are deliberately not editable here: findings
    already stored against the previous specification would silently change
    shape. Declare a new module (or migrate the findings explicitly) instead.
    """
    if payload.label is None and payload.description is None and payload.enabled is None:
        raise BadRequestException("nothing to update")
    spec = await require_module(db, module_id)
    if payload.label is not None or payload.description is not None:
        spec = await update_module_metadata(
            db, module_id, label=payload.label, description=payload.description
        )
    if payload.enabled is not None:
        spec = await set_module_enabled(db, module_id, enabled=payload.enabled)
    await AuditLogger.emit(
        db,
        action="module.updated",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"module": spec.id, "enabled": spec.enabled, "label": spec.label},
    )
    return ModuleOut(**spec.to_public_dict())


@router.get("/findings", response_model=PaginatedResponse[FindingOut])
async def list_findings(
    request: Request,
    module: str | None = None,
    page: int = 1,
    size: int = 50,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    """Findings stored generically, newest first, optionally for one module."""
    from math import ceil

    size = max(1, min(size, 200))
    page = max(1, page)
    stmt = select(Finding)
    count_stmt = select(func.count(Finding.id))
    if module:
        spec = await require_module(db, module)
        stmt = stmt.where(Finding.module == spec.id)
        count_stmt = count_stmt.where(Finding.module == spec.id)

    total = int((await db.execute(count_stmt)).scalar_one())
    rows = (
        (
            await db.execute(
                stmt.order_by(Finding.created_at.desc()).offset((page - 1) * size).limit(size)
            )
        )
        .scalars()
        .all()
    )
    await AuditLogger.emit_background(
        db,
        action="findings.list",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"module": module or "", "count": len(rows), "total": total},
    )
    return PaginatedResponse[FindingOut](
        items=[FindingOut.model_validate(row) for row in rows],
        total=total,
        page=page,
        size=size,
        pages=ceil(total / size) if size else 0,
    )


@router.patch("/findings/{finding_id}", response_model=FindingOut)
async def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    """Move a generic finding through triage.

    Analysts and admins, matching the built-in modules' status endpoint: triage
    is a write an analyst owns, while declaring modules and destructive cleanup
    stay admin-only. Without this a declared module's findings were read-only,
    so an operator could see a finding but never mark it investigated.
    """
    row = await db.get(Finding, finding_id)
    if row is None:
        raise NotFoundException("Finding not found")
    previous = row.status
    if previous != payload.status:
        row.status = payload.status
        await db.commit()
        await db.refresh(row)
        await AuditLogger.emit(
            db,
            action="finding.status_update",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={
                "finding_id": str(row.id),
                "module": row.module,
                "from": previous,
                "to": payload.status,
            },
        )
    return FindingOut.model_validate(row)
