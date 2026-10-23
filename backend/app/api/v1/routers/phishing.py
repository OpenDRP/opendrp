import math
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import ColumnElement, and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from app.api.deps import (
    extract_ip,
    get_db,
    require_analyse,
    require_admin,
    require_active_account,
)
from app.core.audit import AuditLogger
from app.core.exceptions import (
    BadRequestException,
    ConflictException,
    NotFoundException,
)
from app.services.alert_policy import resolve_alert_policy
from app.services.scan_admission import NoEnabledConnector, ScanAdmissionUnavailable, ScanAlreadyRunning
from app.services.source_observations import sources_for_candidate, sources_for_candidates
from app.core.manual_rate_limit import SCOPE_ASSETS, enforce_manual_rate_limit
from app.models import DrpPhishingDomain
from app.models.asset import Asset, AssetType
from app.schemas.asset import (
    AssetCreate,
    PromotedAssetResponse,
    validate_and_normalize_asset_value,
)
from app.services.asset_service import AssetService, asset_type_value
from app.models.phishing import PhishingCandidateSignal
from app.schemas.common import MAX_PAGE_SIZE, CleanupResponse, PaginatedResponse
from app.schemas.connector import ScanStartResponse
from app.schemas.phishing import (
    AlertSignalName,
    DetectionSource,
    PhishingListResponse,
    PhishingSortField,
    PhishingThreatResponse,
    PhishingThreatUpdate,
    SortDirection,
    ThreatStatus,
)

router = APIRouter(prefix="/phishing", tags=["Phishing"])

#: The column behind each sortable field of the list (WI-05). Keyed by exactly the
#: literals ``PhishingSortField`` declares — the API refuses anything else with 422, so
#: no caller input ever reaches ``ORDER BY`` as text, and a test fails if the two sets
#: drift apart. ``age`` is a *position* on the registration date rather than a column
#: the database stores; ordering by it is handled where the query is built.
_PHISHING_SORT_COLUMNS: dict[str, InstrumentedAttribute[Any]] = {
    "created_at": DrpPhishingDomain.created_at,
    "age": DrpPhishingDomain.domain_created_at,
    # The scored list (WI-08/WI-11): "what is worth my morning" is the order an
    # analyst actually reads, and `ix_phishing_confidence` is the index for it.
    "confidence": DrpPhishingDomain.confidence,
}


@router.get("/threats", response_model=PhishingListResponse)
async def list_threats(
    request: Request,
    finding_id: uuid.UUID | None = None,
    detection_source: DetectionSource | None = None,
    status: ThreatStatus | None = None,
    search: str | None = None,
    min_confidence: int | None = Query(None, ge=0, le=100),
    signal: AlertSignalName | None = None,
    sort: PhishingSortField = Query("created_at"),
    order: SortDirection = Query("desc"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    D = DrpPhishingDomain
    skip = (page - 1) * size
    q = select(D)
    w: list[ColumnElement[bool]] = []
    if finding_id is not None:
        w.append(D.id == finding_id)
    if detection_source:
        w.append(D.detection_source == detection_source)
    if status:
        w.append(D.status == status)
    if min_confidence is not None:
        # Inclusive, and compared against the stored score rather than recomputed:
        # the filter and the column an operator reads are the same number, and a
        # score is written when the signals are.
        w.append(D.confidence >= min_confidence)
    if signal:
        # Asked of the evidence table, not of the JSON summary on the row: "this
        # signal fired" is a recorded row with a non-zero contribution, while the
        # summary also holds the facts the platform looked at and did not match —
        # which is not what an analyst filtering for a signal means. The correlated
        # `EXISTS` rides `ix_phishing_candidate_signals_candidate`.
        w.append(
            select(PhishingCandidateSignal.id)
            .where(
                PhishingCandidateSignal.candidate_id == D.id,
                PhishingCandidateSignal.name == signal,
                PhishingCandidateSignal.confidence != 0,
            )
            .exists()
        )
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
    # `id` breaks ties, so a row cannot appear on two pages of the same listing.
    tie = D.id.asc() if order == "asc" else D.id.desc()
    if sort == "age":
        # Ascending age is a *descending* registration date, and an unresolved
        # registration is placed last explicitly rather than left to each database's
        # default: a candidate whose registration nobody looked up is not the youngest
        # one, and it must not head a list an analyst reads top-down.
        column = _PHISHING_SORT_COLUMNS[sort]
        direction = (
            column.asc().nullslast() if order == "desc" else column.desc().nullslast()
        )
    else:
        direction = (
            _PHISHING_SORT_COLUMNS[sort].desc()
            if order == "desc"
            else _PHISHING_SORT_COLUMNS[sort].asc()
        )
    rows = list(
        (
            await db.execute(
                q.order_by(direction, tie).offset(skip).limit(size)
            )
        ).scalars().all()
    )
    # The band each row reports is the policy in force, resolved once for the page:
    # an operator who raised a threshold in Settings must not keep reading
    # "immediate" next to a candidate the channel has stopped messaging about.
    policy = await resolve_alert_policy(db)
    # Who reported them, in one statement for the page (WI-30): the column is read
    # beside the score it corroborates, and a query per row would make the list N+1.
    sources = await sources_for_candidates(db, [row.id for row in rows])
    items = [
        PhishingThreatResponse.from_row(
            row, policy=policy, sources=sources.get(str(row.id), [])
        )
        for row in rows
    ]
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
            "min_confidence": min_confidence,
            "signal": str(signal) if signal else None,
            "sort": sort,
            "order": order,
            "page": page,
            "size": size,
            "results": int(total),
        },
    )
    return PaginatedResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.post("/threats/cleanup-orphans", response_model=CleanupResponse)
async def clean_orphan_phishing_findings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Delete phishing findings that are not linked to any configured asset."""
    from app.services.asset_service import AssetService

    cleanup = await AssetService(db).clean_orphan_phishing_findings()
    await AuditLogger.emit(
        db,
        action="phishing.threat.orphans.cleaned",
        ip_address=extract_ip(request),
        user_id=user.id,
        # Batch by batch and committed inside the service: this row is the only
        # record of which findings went (AUD-030, the same shape as the breach
        # cleanup).
        details={
            "deleted": cleanup.deleted,
            "sample_finding_ids": cleanup.sample,
        },
    )
    return {"status": "completed", "deleted": cleanup.deleted}


@router.get("/threats/{threat_id}", response_model=PhishingThreatResponse)
async def get_threat(
    request: Request,
    threat_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
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
    return PhishingThreatResponse.from_row(
        t,
        policy=await resolve_alert_policy(db),
        sources=await sources_for_candidate(db, t.id),
    )


@router.patch("/threats/{threat_id}", response_model=PhishingThreatResponse)
async def update_threat(
    request: Request,
    threat_id: uuid.UUID,
    data: PhishingThreatUpdate,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
):
    D = DrpPhishingDomain
    t = (await db.execute(select(D).where(D.id == threat_id))).scalar_one_or_none()
    if not t:
        raise NotFoundException("Phishing threat not found")
    payload = data.model_dump(exclude_unset=True)
    deciding = "verdict" in payload
    if "verdict_reason" in payload and not deciding:
        # A reason explains a decision, so it cannot arrive without one: accepting it
        # would store a justification the list shows beside a candidate nobody decided
        # anything about.
        raise BadRequestException("verdict_reason requires a verdict in the same request")
    previous_verdict = t.verdict
    #: The instant of a decision made by *this* request, or ``None`` when the payload
    #: did not decide anything. Held as a local as well as written to the row: the
    #: confirmation's event is identified by the decision it came from, and reading it
    #: back off the row would mean trusting a value the session may not have flushed.
    decided_at: datetime | None = None
    changes = [name for name in payload if name not in {"verdict", "verdict_reason"}]
    for name in changes:
        setattr(t, name, payload[name])
    if deciding:
        reason = (payload.get("verdict_reason") or "").strip() or None
        verdict = payload["verdict"]
        if verdict is None:
            # An un-decision is a decision too (an analyst rejected the wrong row, or
            # the page turned out to be ours after all): the candidate goes back to
            # being routed by its score, and the author goes with the verdict — a name
            # beside a decision that no longer exists reads as an anonymous one.
            t.verdict = None
            t.verdict_reason = None
            t.verdict_by = None
            t.verdict_at = None
        else:
            if verdict == "rejected" and not reason:
                # "Rejected" with nothing written down is indistinguishable from a
                # misclick, and the reason is the only record of *why* — the candidate
                # itself keeps no trace of it (WI-12).
                raise BadRequestException(
                    "Rejecting a candidate needs a reason: it is what the next reader "
                    "of this finding will have instead of the decision"
                )
            decided_at = datetime.now(timezone.utc)
            t.verdict = verdict
            t.verdict_reason = reason
            t.verdict_by = user.id
            t.verdict_at = decided_at
    await db.flush()
    if changes or not deciding:
        await AuditLogger.emit(
            db,
            action="phishing.threat.update",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={
                "threat_id": str(threat_id),
                "changed_fields": changes,
            },
            require_persistence=True,
            commit=False,
        )
    if deciding:
        # One row per decision, and it carries what the generic update row cannot: the
        # verdict it replaced and the score it overrode, so "who rejected this, and
        # why?" is answered from the audit trail rather than by whoever remembers
        # (WI-12).
        await AuditLogger.emit(
            db,
            action="phishing.threat.verdict",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={
                "threat_id": str(threat_id),
                "phishing_domain": str(t.phishing_domain),
                "verdict": t.verdict,
                "previous_verdict": previous_verdict,
                "reason": t.verdict_reason,
                "confidence": int(t.confidence or 0),
            },
            require_persistence=True,
            commit=False,
        )
        if decided_at is not None and t.verdict == "confirmed" and previous_verdict != "confirmed":
            # A confirmation is a message, not only a flag: the candidate may sit below
            # the alert threshold (that is usually why somebody looked at it), and a
            # decision nobody hears about until the next scan is a decision the channel
            # has not made. The event goes through the ordinary outbox and the ordinary
            # routing, which is what makes the verdict outrank the score there.
            from app.services.ingestion_events import record_event

            await record_event(
                db,
                kind="notification",
                module="phishing",
                entity_id=t.id,
                # ``finding_id`` is the key the delivery path reads the stored candidate
            # by (WI-01/W0.2): the message is rendered from the row, so a confirmation
            # arrives with the same facts — age, registrar, score, signals — as the
            # alert a scan would have sent. Without it the event would be delivered
            # from the payload alone, which carries no facts at all.
            payload={
                "rule": "phishing.verdict.confirmed",
                "verdict": "confirmed",
                "finding_id": str(t.id),
            },
                dedup=f"verdict-confirmed-{int(decided_at.timestamp())}",
            )
    await db.commit()
    return PhishingThreatResponse.from_row(
        t,
        policy=await resolve_alert_policy(db),
        sources=await sources_for_candidate(db, t.id),
    )


@router.post(
    "/scan/dnstwist",
    status_code=202,
    response_model=ScanStartResponse,
    response_model_exclude_none=True,
)
async def trigger_dnstwist_scan(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
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


@router.post(
    "/scan/shodan",
    status_code=202,
    response_model=ScanStartResponse,
    response_model_exclude_none=True,
)
async def trigger_shodan_scan(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
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


@router.post(
    "/threats/{threat_id}/asset",
    status_code=201,
    response_model=PromotedAssetResponse,
    response_model_exclude_none=True,
)
async def promote_threat_to_asset(
    request: Request,
    threat_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
):
    """Take a look-alike candidate under monitoring (AWI-13/U-1).

    The candidate's own domain is the value the module already discovered and
    matched, so monitoring it keeps future scans reporting on the same name
    instead of the operator retyping it. The assets throttle and the audit trail
    are the same as on the DNS, exposure and breach promotion paths, including
    for a value that is already monitored.
    """
    threat = await db.get(DrpPhishingDomain, threat_id)
    if threat is None:
        raise NotFoundException("Threat not found")

    asset_type = AssetType.domain
    try:
        normalized = validate_and_normalize_asset_value(
            asset_type.value, threat.phishing_domain
        )
    except ValueError as exc:
        raise ConflictException(
            "This threat's domain cannot be promoted as an asset"
        ) from exc

    await enforce_manual_rate_limit(
        db=db,
        user=user,
        scope=SCOPE_ASSETS,
        action="asset promotion",
        ip_address=extract_ip(request),
    )

    existing = (
        await db.execute(
            select(Asset)
            .where(
                Asset.asset_type == asset_type,
                Asset.normalized_value == normalized,
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    details = {
        "threat_id": str(threat.id),
        "phishing_domain": threat.phishing_domain,
        "detection_source": threat.detection_source,
        "matched_asset": threat.matched_asset,
        "promoted_from": "phishing",
    }
    if existing is not None:
        await AuditLogger.emit(
            db,
            action="phishing.asset.already_exists",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={
                **details,
                "asset_id": str(existing.id),
                "asset_type": asset_type_value(existing.asset_type),
                "asset_value": existing.asset_value,
            },
            require_persistence=True,
        )
        return {"already_exists": True, "asset": existing}

    try:
        asset = await AssetService(db).create_asset(
            AssetCreate.model_validate(
                {"asset_type": asset_type.value, "asset_value": normalized}
            ),
            commit=False,
        )
    except ConflictException:
        existing = (
            await db.execute(
                select(Asset)
                .where(
                    Asset.asset_type == asset_type,
                    Asset.normalized_value == normalized,
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if existing is None:
            raise
        asset, already_exists = existing, True
    else:
        already_exists = False

    await AuditLogger.emit(
        db,
        action="phishing.asset.promoted",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            **details,
            "asset_id": str(asset.id),
            "asset_type": asset_type_value(asset.asset_type),
            "asset_value": asset.asset_value,
            "already_exists": already_exists,
        },
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    return {"already_exists": already_exists, "asset": asset}


@router.delete("/threats/{threat_id}", status_code=204)
async def delete_threat(
    request: Request,
    threat_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
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
    await AuditLogger.emit(
        db,
        action="phishing.threat.delete",
        ip_address=extract_ip(request),
        user_id=user.id,
        details=details,
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    return None
