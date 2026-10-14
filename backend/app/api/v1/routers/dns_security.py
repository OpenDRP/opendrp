from __future__ import annotations

import ipaddress
import math
import uuid
from datetime import datetime, timezone
from app.models.dns_expiry_monitor import DNSExpiryMonitor
from app.services.dns_expiry_monitor_service import monitor_payload
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete
from app.services.dns_observation_inventory import inventory_query, certificate_group, rrset_members
from app.services.dns_security_service import normalize_subject
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_admin, require_analyst_or_admin, require_viewer_plus
from app.core.audit import AuditLogger
from app.core.exceptions import ConflictException, NotFoundException
from app.models.asset import Asset, AssetType
from app.models.dns_observation import DNSObservation
from app.schemas.asset import AssetCreate, validate_and_normalize_asset_value
from app.schemas.common import MAX_PAGE_SIZE, PaginatedResponse
from app.services.asset_matching import asset_sql_key, key_variants
from app.services.asset_service import AssetService, asset_type_value
from app.services.connector_service import ConnectorService

router = APIRouter(tags=["DNS Security"])


@router.get("/observations", response_model=PaginatedResponse[dict])
async def list_observations(
    request: Request,
    subject: str | None = Query(None, max_length=253),
    source: str | None = Query(None, pattern="^[a-z][a-z0-9_-]{0,31}$"),
    observation_type: str | None = Query(None, max_length=32),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    if subject:
        from app.services.dns_security_service import normalize_subject

        try:
            normalized_subject = normalize_subject(subject)
        except (UnicodeError, ValueError) as exc:
            from app.core.exceptions import BadRequestException

            raise BadRequestException("subject must be a valid hostname or IP address") from exc
    else:
        normalized_subject = None

    query = inventory_query(db)
    if normalized_subject:
        query = query.where(DNSObservation.subject == normalized_subject)
    if source:
        query = query.where(DNSObservation.source == source)
    if observation_type:
        query = query.where(DNSObservation.observation_type == observation_type)
    total = int((await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one())
    rows = (await db.execute(query.order_by(DNSObservation.last_seen_at.desc(), DNSObservation.id.desc(), query.selected_columns.display_value).offset((page - 1) * size).limit(size))).all()
    # One bounded asset lookup per page, including inactive configured assets.
    candidates = {row.subject for row, _, _, _ in rows}
    for row, value, _, _ in rows:
        target = value_asset_target(row, value)
        if target:
            candidates.add(target)
    # Canonical keys (WI-08): an observation counts as "in assets" when any
    # spelling of its subject or target matches a configured domain/IP asset.
    candidate_keys = {key for candidate in candidates for key in key_variants(candidate)}
    assets = (await db.execute(select(Asset.asset_type, asset_sql_key()).where(Asset.asset_type.in_([AssetType.domain, AssetType.ip_address]), asset_sql_key().in_(sorted(candidate_keys))))).all()
    asset_keys = {key for _, key in assets}

    def in_assets(value) -> bool:
        return bool(key_variants(value) & asset_keys)
    monitors = (await db.execute(select(DNSExpiryMonitor).where(DNSExpiryMonitor.subject.in_(candidates)))).scalars().all()
    controls = {(m.subject, m.kind): monitor_payload(m, datetime.now(timezone.utc)) for m in monitors}
    await AuditLogger.emit_background(db, action="dns_security.observations.list", ip_address=extract_ip(request), user_id=user.id, details={"source": source, "observation_type": observation_type, "count": len(rows), "total": total})
    return PaginatedResponse(items=[{
        "id": str(row.id), "observation_type": row.observation_type, "subject": row.subject,
        "record_type": row.record_type, "value": value, "source": row.source,
        "first_seen_at": first_seen, "last_seen_at": row.last_seen_at,
        "evidence_count": evidence_count, "subject_in_assets": in_assets(row.subject),
        "value_asset_target": value_asset_target(row, value),
        "value_in_assets": in_assets(value_asset_target(row, value)),
        "expires_at": row.expires_at, "status": row.status, "metadata": row.metadata_json,
        "alerted_thresholds": row.alerted_thresholds or [],
        "expiry_kind": "registration" if row.observation_type == "rdap" else "certificate" if row.observation_type in {"certificate", "certificate_check"} else "dns_cache" if row.source == "resolver" else "unknown",
        "expiry_monitor": controls.get((row.subject, "registration" if row.observation_type == "rdap" else "certificate")) if row.observation_type in {"rdap", "certificate", "certificate_check"} else None,
    } for row, value, evidence_count, first_seen in rows], total=total, page=page, size=size, pages=math.ceil(total / size) if size else 0)


@router.post("/scan", status_code=202)
async def scan_dns_security(request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_analyst_or_admin)):
    service = ConnectorService(db)
    offline = [conn.name for conn in await service.list_enabled_by_type("dns") if not service.is_online(conn)]
    # The queued Job rows and the event that says the scan was requested are one
    # commit: a scan nobody asked for in the trail must not exist.
    result = await service.enqueue_ready_sources(
        connector_type="dns", created_by=user.id, title="DNS Security scan",
        params={"trigger": "manual"},
        audit={
            "action": "dns_security.scan.queued",
            "user_id": user.id,
            "ip_address": extract_ip(request),
            "details": {"offline_connectors": offline},
        },
    )
    result["offline_connectors"] = offline
    if not result["job_ids"]:
        raise HTTPException(409, result)
    return result


@router.post("/observations/cleanup-orphans")
async def cleanup_orphans(request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    from app.services.dns_security_service import clean_orphan_observations

    deleted = await clean_orphan_observations(db)
    await AuditLogger.emit(db, action="dns_security.observation.orphans.cleaned", ip_address=extract_ip(request), user_id=user.id, details={"deleted": deleted})
    return {"status": "completed", "deleted": deleted}


class PromoteObservation(BaseModel):
    target: str | None = Field(None, max_length=253)


def value_asset_target(row: DNSObservation, value: str | None) -> str | None:
    if row.source != "resolver" or row.observation_type != "dns_record" or row.record_type not in {"A", "AAAA", "CNAME", "NS", "MX"} or not value:
        return None
    raw = value.split(maxsplit=1)[-1] if row.record_type == "MX" else value
    try:
        return normalize_subject(raw)
    except (ValueError, UnicodeError):
        return None


@router.delete("/observations/{observation_id}", status_code=204)
async def delete_observation(
    observation_id: uuid.UUID, request: Request,
    value: str | None = Query(None, max_length=1000),
    db: AsyncSession = Depends(get_db), user=Depends(require_analyst_or_admin),
):
    row = (await db.execute(select(DNSObservation).where(DNSObservation.id == observation_id).with_for_update())).scalar_one_or_none()
    if row is None:
        raise NotFoundException("DNS observation not found")
    if row.observation_type == "certificate":
        result = await db.execute(delete(DNSObservation).where(certificate_group(row)))
        deleted = result.rowcount
    elif row.source == "resolver" and row.observation_type == "dns_record" and value is not None:
        members = rrset_members(row)
        if value not in members:
            raise NotFoundException("DNS record member not found")
        remaining = [member for member in members if member != value]
        if remaining:
            row.metadata_json = {**row.metadata_json, "record_values": remaining}
            row.value = "; ".join(remaining)[:1000]
        else:
            await db.delete(row)
        deleted = 1
    else:
        await db.delete(row)
        deleted = 1
    if row.observation_type in {"rdap", "certificate", "certificate_check"}:
        from sqlalchemy import update
        kind = "registration" if row.observation_type == "rdap" else "certificate"
        await db.execute(update(DNSExpiryMonitor).where(DNSExpiryMonitor.subject == row.subject, DNSExpiryMonitor.kind == kind).values(state="unverified", observation_id=None))
    details = {"observation_id": str(observation_id), "subject": row.subject, "source": row.source, "deleted": deleted}
    await AuditLogger.emit(db, action="dns_security.observation.delete", ip_address=extract_ip(request), user_id=user.id, details=details, require_persistence=True, commit=False)
    await db.commit()
    return None


@router.post("/observations/{observation_id}/asset", status_code=201)
async def promote_observation_to_asset(
    observation_id: uuid.UUID,
    request: Request,
    payload: PromoteObservation | None = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyst_or_admin),
):
    observation = await db.get(DNSObservation, observation_id)
    if observation is None:
        raise NotFoundException("DNS observation not found")
    target = payload.target if payload and payload.target else observation.subject
    allowed_targets = {observation.subject}
    if observation.source == "resolver" and observation.observation_type == "dns_record":
        for member in rrset_members(observation):
            member_target = value_asset_target(observation, member)
            if member_target is not None:
                allowed_targets.add(member_target)
    if target not in allowed_targets:
        raise ConflictException("Asset target is not part of this observation")
    if target == observation.subject and observation.metadata_json.get("wildcard") is True:
        raise ConflictException("Wildcard certificate evidence cannot be promoted as a concrete hostname")
    try:
        ipaddress.ip_address(target)
        asset_type = AssetType.ip_address
    except ValueError:
        asset_type = AssetType.domain
    try:
        normalized_subject = validate_and_normalize_asset_value(asset_type.value, target)
    except ValueError as exc:
        raise ConflictException("This observation cannot be promoted to an asset") from exc
    existing = (await db.execute(select(Asset).where(
        Asset.asset_type == asset_type,
        Asset.normalized_value == normalized_subject,
    ).limit(1))).scalar_one_or_none()
    if existing is not None:
        # Same fields as the ``promoted`` branch below, so the trail answers
        # "where did this asset come from" the same way whether the row was
        # created by this observation or was already monitored (WI-13).
        await AuditLogger.emit(db, action="dns_security.asset.already_exists", ip_address=extract_ip(request), user_id=user.id, details={"observation_id": str(observation.id), "asset_id": str(existing.id), "asset_type": asset_type.value, "asset_value": existing.asset_value, "criticality": asset_type_value(existing.criticality), "subject": observation.subject, "source": observation.source, "observation_type": observation.observation_type, "promoted_from": "dns_security"}, require_persistence=True)
        return {"already_exists": True, "asset": existing, "source": observation.source}
    try:
        # No commit here: the new asset and the audit row below are one
        # transaction, so the inventory cannot change without a record of who
        # changed it and from which observation.
        asset = await AssetService(db).create_asset(AssetCreate.model_validate({"asset_type": asset_type.value, "asset_value": normalized_subject}), commit=False)
    except ConflictException:
        # Unique normalized values close the race between the lookup and insert.
        existing = (await db.execute(select(Asset).where(Asset.asset_type == asset_type, Asset.normalized_value == normalized_subject).limit(1))).scalar_one_or_none()
        if existing is None:
            raise
        asset = existing
        already_exists = True
    else:
        already_exists = False
    await AuditLogger.emit(db, action="dns_security.asset.promoted", ip_address=extract_ip(request), user_id=user.id, details={"observation_id": str(observation.id), "asset_id": str(asset.id), "asset_type": asset_type.value, "asset_value": asset.asset_value, "criticality": asset_type_value(asset.criticality), "subject": observation.subject, "source": observation.source, "observation_type": observation.observation_type, "promoted_from": "dns_security", "already_exists": already_exists}, require_persistence=True, commit=False)
    await db.commit()
    return {"already_exists": already_exists, "asset": asset, "source": observation.source}
