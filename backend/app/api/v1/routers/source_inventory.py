import ipaddress
import math
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict

from fastapi import APIRouter, Depends, Query, Request, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_analyse, require_active_account
from app.core.audit import AuditLogger
from app.models.source_observation import SourceObservation
from app.models import Asset, AssetType, PhishingDomain
from app.schemas.asset import AssetCreate, validate_and_normalize_asset_value
from app.schemas.common import MAX_PAGE_SIZE
from app.services.asset_service import AssetService, asset_type_value
from app.core.exceptions import ConflictException
from app.core.manual_rate_limit import SCOPE_ASSETS, enforce_manual_rate_limit
from app.services.connector_service import ConnectorService

router = APIRouter(tags=["Source inventory"])


#: What a phishing evidence row may show from the connector's own payload.
#:
#: An allowlist rather than a passthrough. The payload is whatever a connector sent - a
#: provider document, a fact about a candidate, the capability that produced it - so
#: returning it whole would publish a shape the platform never promised and would grow a
#: new one the day a connector writes it. The names here are the facts the module's rules
#: and its alerts read, which is the useful half: what the list shows is what a decision
#: was made from.
EVIDENCE_FIELDS = (
    "capability",
    "verdict",
    "title",
    "association",
    "evidence",
    "detection_source",
    "ip_address",
    "web_ports",
    "registrar",
    "created",
    "mail_capable",
    "mx_hosts",
    "provider_observed_at",
    "wildcard",
    "subject_dn",
    "issuer_dn",
)


def evidence_fields(payload) -> dict:
    """The payload's own facts, flattened and bounded, for the evidence list.

    Metadata first, then the finding's own top level: a discovery carries the capability
    under ``metadata`` while an enrichment fact carries it beside the value it describes.
    A name that is absent is absent - never filled from another row, because an evidence
    list that guesses is worse than one that says it does not know.
    """
    if not isinstance(payload, dict):
        return {}
    metadata = payload.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    fields = {}
    for name in EVIDENCE_FIELDS:
        value = metadata.get(name, payload.get(name))
        if value is None or isinstance(value, (dict, tuple, set)):
            continue
        if isinstance(value, list) and not all(
            isinstance(item, (str, int, float, bool)) for item in value
        ):
            continue
        fields[name] = value
    return fields


class ExposureTriageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["observed", "investigating", "resolved"]


@router.post("/modules/{module_id}/scan", status_code=202)
async def scan(module_id: str, request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_analyse)):
    # The queued Job rows and the event that says the scan was requested are one
    # commit: a scan nobody asked for in the trail must not exist.
    result = await ConnectorService(db).enqueue_ready_sources(
        connector_type=module_id, created_by=user.id, title=f"{module_id} scan",
        params={"trigger": "manual"},
        audit={"action": "source.scan.queued", "user_id": user.id, "ip_address": extract_ip(request)},
    )
    if not result["job_ids"]:
        raise HTTPException(409, result)
    return result


@router.get("/exposure/observations")
async def exposure(request: Request, source: str | None = Query(None, pattern="^[a-z][a-z0-9_-]{0,99}$"), page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=MAX_PAGE_SIZE), db: AsyncSession = Depends(get_db), user=Depends(require_active_account)):
    conditions = [SourceObservation.module == "exposure"]
    if source:
        conditions.append(SourceObservation.source == source)
    total = (await db.execute(select(func.count(SourceObservation.id)).where(*conditions))).scalar_one()
    rows = list((await db.execute(select(SourceObservation).where(*conditions).order_by(SourceObservation.last_seen_at.desc()).offset((page-1)*size).limit(size))).scalars())
    await AuditLogger.emit_background(db, action="source.observations.list", user_id=user.id, ip_address=extract_ip(request), details={"module": "exposure", "total": total})
    return {"items": [{"id": str(row.id), "source": row.source, "subject": row.subject, "matched_asset": row.matched_asset, "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at, "observed_at": row.observed_at, "status": row.status, "payload": row.payload, "provenance": row.provenance, "connector_id": row.connector_id, "source_account_id": row.source_account_id} for row in rows], "total": total, "page": page, "size": size, "pages": math.ceil(total/size)}


@router.patch("/exposure/observations/{observation_id}")
async def update_exposure_observation(observation_id: uuid.UUID, payload: ExposureTriageRequest, request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_analyse)):
    row = await db.get(SourceObservation, observation_id)
    if row is None or row.module != "exposure":
        raise HTTPException(404, "Exposure observation not found")
    previous = row.status
    row.status = payload.status
    if previous != row.status:
        await AuditLogger.emit(db, action="exposure.observation.status_update", user_id=user.id, ip_address=extract_ip(request), details={"observation_id": str(row.id), "source": row.source, "from": previous, "to": row.status}, require_persistence=True, commit=False)
    await db.commit()
    return {"id": str(row.id), "status": row.status}


@router.post("/exposure/observations/{observation_id}/asset", status_code=201)
async def promote_exposure_observation(observation_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_analyse)):
    row = await db.get(SourceObservation, observation_id)
    if row is None or row.module != "exposure":
        raise HTTPException(404, "Exposure observation not found")
    try:
        ipaddress.ip_address(row.subject)
        asset_type = AssetType.ip_address
    except ValueError:
        asset_type = AssetType.domain
    try:
        normalized = validate_and_normalize_asset_value(asset_type.value, row.subject)
    except ValueError as exc:
        raise ConflictException("Exposure subject cannot be promoted as an asset") from exc
    # A promotion adds the subject to every scan of its type, exactly like the
    # direct-create route, so it charges the same per-user window (AWI-02/AST-43).
    # A repeat click on an already-monitored value counts too: the request still
    # writes an audit row, and this is how an observation list becomes inventory
    # in bulk.
    await enforce_manual_rate_limit(
        db=db,
        user=user,
        scope=SCOPE_ASSETS,
        action="asset promotion",
        ip_address=extract_ip(request),
    )
    existing = (await db.execute(select(Asset).where(Asset.asset_type == asset_type, Asset.normalized_value == normalized).limit(1))).scalar_one_or_none()
    if existing is not None:
        # Same fields as the ``promoted`` branch below: the audit trail is what
        # answers "where did this asset come from" (WI-13).
        await AuditLogger.emit(db, action="exposure.asset.already_exists", user_id=user.id, ip_address=extract_ip(request), details={"observation_id": str(row.id), "asset_id": str(existing.id), "asset_type": asset_type.value, "asset_value": existing.asset_value, "criticality": asset_type_value(existing.criticality), "subject": row.subject, "source": row.source, "promoted_from": "exposure"}, require_persistence=True)
        return {"already_exists": True, "asset": existing, "source": row.source}
    try:
        # One transaction with the audit row below: an inventory change nobody
        # can trace back to the observation that produced it is not a change this
        # platform makes.
        asset = await AssetService(db).create_asset(AssetCreate.model_validate({"asset_type": asset_type.value, "asset_value": normalized}), commit=False)
    except ConflictException:
        existing = (await db.execute(select(Asset).where(Asset.asset_type == asset_type, Asset.normalized_value == normalized).limit(1))).scalar_one_or_none()
        if existing is None:
            raise
        asset, already_exists = existing, True
    else:
        already_exists = False
    await AuditLogger.emit(db, action="exposure.asset.promoted", user_id=user.id, ip_address=extract_ip(request), details={"observation_id": str(row.id), "asset_id": str(asset.id), "asset_type": asset_type.value, "asset_value": asset.asset_value, "criticality": asset_type_value(asset.criticality), "subject": row.subject, "source": row.source, "promoted_from": "exposure", "already_exists": already_exists}, require_persistence=True, commit=False)
    await db.commit()
    return {"already_exists": already_exists, "asset": asset, "source": row.source}


@router.get("/phishing/threats/{candidate_id}/evidence")
async def phishing_evidence(candidate_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_active_account)):
    if await db.get(PhishingDomain, candidate_id) is None:
        raise HTTPException(404, "Candidate not found")
    await AuditLogger.emit_background(db, action="source.observations.list", user_id=user.id, ip_address=extract_ip(request), details={"module": "phishing", "candidate_id": str(candidate_id)})
    rows = list((await db.execute(select(SourceObservation).where(SourceObservation.candidate_id == candidate_id).order_by(SourceObservation.last_seen_at.desc()).limit(200))).scalars())
    return {"items": [{"source": r.source, "matched_asset": r.matched_asset, "observed_at": r.observed_at, "first_seen_at": r.first_seen_at, "last_seen_at": r.last_seen_at, "fields": evidence_fields(r.payload), "payload": r.payload, "provenance": r.provenance, "connector_id": r.connector_id, "source_account_id": r.source_account_id} for r in rows]}
