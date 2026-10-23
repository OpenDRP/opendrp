from __future__ import annotations

import ipaddress
import math
import uuid
from datetime import datetime, timezone
from typing import Any
from app.models.dns_expiry_monitor import DNSExpiryMonitor
from app.services.dns_expiry_monitor_service import kind_is_tls, monitor_payload, tls_kind
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete
from app.services.dns_observation_inventory import inventory_query, certificate_group, rrset_members
from app.services.dns_security_service import normalize_subject
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_admin, require_analyse, require_active_account
from app.core.audit import AuditLogger
from app.core.exceptions import ConflictException, NotFoundException
from app.core.manual_rate_limit import SCOPE_ASSETS, enforce_manual_rate_limit
from app.models.asset import Asset, AssetType
from app.models.dns_observation import DNSObservation
from app.schemas.asset import (
    AssetCreate,
    PromotedAssetResponse,
    validate_and_normalize_asset_value,
)
from app.schemas.common import CleanupResponse, MAX_PAGE_SIZE, PaginatedResponse
from app.schemas.connector import ScanStartResponse
from app.services.asset_matching import asset_sql_key, key_variants
from app.services.asset_service import AssetService, asset_type_value
from app.services.connector_service import ConnectorService

router = APIRouter(tags=["DNS Security"])


class DNSExpiryMonitorResponse(BaseModel):
    """The expiry control an inventory row feeds, as the page shows it.

    `kind` is the control's key — `tls:8443` when the port is part of it (AUD-036)
    — while the row's `expiry_kind` is the label the column prints (`tls`). Both
    are published because they answer different questions: which control sent the
    reminder, and what kind of control it is.

    `remaining_seconds` is a float because it is a timedelta divided by seconds;
    the page renders it as days, and the type says what the arithmetic produces.
    """

    kind: str
    state: str
    checked_at: datetime
    successful_at: datetime | None
    expires_at: datetime | None
    certificate_id: str | None
    not_before: datetime | None
    #: Day counts already notified for this cycle, in the order the sweep crossed
    #: them. The control is their single writer (AUD-038).
    alerted_thresholds: list[int]
    remaining_seconds: float | None


class DNSObservationResponse(BaseModel):
    """One row of the DNS inventory, as the DNS Security page reads it.

    `observation_type`, `source`, `status` and `expiry_kind` stay strings. The client
    closes two of them with unions, but the columns are free text and the module's
    vocabulary has grown twice — the `vt_*` family, then the active probe — so a row
    written by a worker this build does not know must still render. A model that
    refused it would replace the row an operator needs with a 500.

    `expiry_monitor` is nullable because `monitor_kind` answers `None` for an
    observation type no control tracks: the row feeds nothing, and the page shows no
    expiry control rather than an empty one.

    `metadata` is the connector's own record — the RRset under `record_values`, the
    wildcard flag, a provider document — and the page reads three keys of it.
    """

    id: str
    observation_type: str
    subject: str
    record_type: str | None
    #: The RRset member this row stands for, which is what the inventory table shows
    #: rather than the stored `value` a grouped certificate keeps.
    value: str | None
    source: str
    first_seen_at: datetime
    last_seen_at: datetime
    expires_at: datetime | None
    status: str
    metadata: dict[str, Any]
    #: The control's history beside its own payload: the same list in both places,
    #: because the row's column and the nested control answer the same question.
    alerted_thresholds: list[int]
    #: How many observations one row stands for: an RRset member is one, a
    #: certificate group is its sightings.
    evidence_count: int
    subject_in_assets: bool
    #: The hostname or address this member resolves to, when the row is a DNS record
    #: whose value can be promoted as an asset.
    value_asset_target: str | None
    value_in_assets: bool
    expiry_kind: str
    expiry_monitor: DNSExpiryMonitorResponse | None


class DNSObservationPageResponse(PaginatedResponse[DNSObservationResponse]):
    """A page of the inventory with the counters the table pages by."""

    items: list[DNSObservationResponse]


@router.get("/observations", response_model=DNSObservationPageResponse)
async def list_observations(
    request: Request,
    subject: str | None = Query(None, max_length=253),
    source: str | None = Query(None, pattern="^[a-z][a-z0-9_-]{0,31}$"),
    observation_type: str | None = Query(None, max_length=32),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
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
    items: list[DNSObservationResponse] = []
    for row, value, evidence_count, first_seen in rows:
        # The control and the promotable target are asked once per row: both used to
        # be computed twice in the comprehension, which is two lookups for one answer.
        monitor = _expiry_monitor(controls, row)
        target = value_asset_target(row, value)
        items.append(
            DNSObservationResponse(
                id=str(row.id),
                observation_type=row.observation_type,
                subject=row.subject,
                record_type=row.record_type,
                value=value,
                source=row.source,
                first_seen_at=first_seen,
                last_seen_at=row.last_seen_at,
                expires_at=row.expires_at,
                status=row.status,
                metadata=row.metadata_json,
                # The reminder history is the control's, and only the control's: the
                # observation used to carry a second copy that nothing ever wrote, so
                # a control that had been reminding for weeks showed "nothing sent"
                # (AUD-038).
                alerted_thresholds=(monitor or {}).get("alerted_thresholds") or [],
                evidence_count=evidence_count,
                subject_in_assets=in_assets(row.subject),
                value_asset_target=target,
                value_in_assets=in_assets(target),
                expiry_kind=expiry_kind(row),
                expiry_monitor=(
                    DNSExpiryMonitorResponse.model_validate(monitor) if monitor else None
                ),
            )
        )
    return DNSObservationPageResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if size else 0,
    )


@router.post(
    "/scan",
    status_code=202,
    response_model=ScanStartResponse,
    response_model_exclude_none=True,
)
async def scan_dns_security(request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_analyse)):
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


@router.post("/observations/cleanup-orphans", response_model=CleanupResponse)
async def cleanup_orphans(request: Request, db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    from app.services.dns_security_service import clean_orphan_observations

    deleted = await clean_orphan_observations(db)
    await AuditLogger.emit(db, action="dns_security.observation.orphans.cleaned", ip_address=extract_ip(request), user_id=user.id, details={"deleted": deleted})
    # The same two keys the breaches and phishing cleanups answer: one shape for one
    # operation, declared once (plan 017).
    return CleanupResponse(status="completed", deleted=deleted)


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


def monitor_kind(row) -> str | None:
    """The expiry control an observation feeds, or None when it feeds none.

    `tls_probe` is a kind of its own rather than part of `certificate`: the active
    handshake and the passive Certificate Transparency check answer different
    questions about the same hostname, and a reader has to be able to tell which
    one a reminder came from. Within `tls_probe` the port is part of the kind, so
    two services on one asset are two controls (AUD-036).
    """
    observation_type = row.observation_type
    if observation_type == "rdap":
        return "registration"
    if observation_type in {"certificate", "certificate_check"}:
        return "certificate"
    if observation_type == "tls_probe":
        return tls_kind(row)
    return None


def _expiry_monitor(controls: dict[tuple[str, str], dict], row: Any) -> dict | None:
    """The expiry control an inventory row feeds, or None when it feeds none.

    ``monitor_kind`` answers ``None`` for an observation type no control tracks, and
    ``None`` is not a key any control row has — the guard states that in the one place
    the question is asked, instead of leaving a reader to notice that the lookup it
    would build could only ever miss.
    """
    kind = monitor_kind(row)
    if not kind:
        return None
    control = controls.get((row.subject, kind))
    if control is None and kind_is_tls(kind):
        # A control written before the port dimension is still the answer for
        # this row until the next sweep adopts it (AUD-036).
        control = controls.get((row.subject, "tls"))
    return control


def expiry_kind(row) -> str:
    """What the expiry column is about for one inventory row."""
    kind = monitor_kind(row)
    if kind:
        # The column labels the kind of control, not its key: the port is shown
        # beside the certificate it belongs to, not in the label (AUD-036).
        return "tls" if kind_is_tls(kind) else kind
    if row.observation_type == "tls_certificate":
        return "tls"
    if row.source == "resolver":
        return "dns_cache"
    return "unknown"


@router.delete("/observations/{observation_id}", status_code=204)
async def delete_observation(
    observation_id: uuid.UUID, request: Request,
    value: str | None = Query(None, max_length=1000),
    db: AsyncSession = Depends(get_db), user=Depends(require_analyse),
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
    deleted_kind = monitor_kind(row)
    if deleted_kind:
        from sqlalchemy import update
        await db.execute(update(DNSExpiryMonitor).where(DNSExpiryMonitor.subject == row.subject, DNSExpiryMonitor.kind == deleted_kind).values(state="unverified", observation_id=None))
    details = {"observation_id": str(observation_id), "subject": row.subject, "source": row.source, "deleted": deleted}
    await AuditLogger.emit(db, action="dns_security.observation.delete", ip_address=extract_ip(request), user_id=user.id, details=details, require_persistence=True, commit=False)
    await db.commit()
    return None


@router.post(
    "/observations/{observation_id}/asset",
    status_code=201,
    response_model=PromotedAssetResponse,
    response_model_exclude_none=True,
)
async def promote_observation_to_asset(
    observation_id: uuid.UUID,
    request: Request,
    payload: PromoteObservation | None = None,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
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
    # Promoting is creating: the value joins every scan of its type, exactly as
    # it would through the direct-create route, so it charges the same per-user
    # window (AWI-02/AST-43). The check sits after the observation is validated
    # and before the existing-row lookup, so a repeat click on an already
    # monitored value counts too - that click still writes an audit row, and a
    # batch of 300 observations is how an inventory grows in one sitting.
    await enforce_manual_rate_limit(
        db=db,
        user=user,
        scope=SCOPE_ASSETS,
        action="asset promotion",
        ip_address=extract_ip(request),
    )
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


class CertificateVerdict(BaseModel):
    """The review decision for one sighting, with the note that goes in the trail."""

    verdict: str = Field(pattern="^(expected|shared_infrastructure|confirmed_foreign|rejected|candidate)$")
    note: str | None = Field(default=None, max_length=2000)


class TLSSightingReview(BaseModel):
    """What `PATCH /dns/certificates/sightings/{id}` answers: the decision, as stored.

    `id` is a string because the route has always sent `str(sighting.id)`, and the
    page keys the row in its cache by it. `verdict` stays a free string rather than
    the request's pattern: a row can hold a value written before a verdict was
    retired, and reading it back is not the place to fail. `reviewed_at` is null for
    a decision that cleared a verdict instead of setting one.
    """

    id: str
    verdict: str
    reviewed_at: datetime | None = None


class CertificateExceptionCreate(BaseModel):
    match_kind: str = Field(pattern="^(fingerprint|spki|ip|asn|issuer)$")
    match_value: str = Field(min_length=1, max_length=255)
    reason: str | None = Field(default=None, max_length=1000)
    expires_at: datetime | None = None


class CertificateScopeExceptionResponse(BaseModel):
    """One identity the scope rules must not alert on, as the list answers it.

    `expired` is computed at read time rather than stored, so the rule it encodes —
    an end date in the past, compared in UTC — belongs beside the field. `created_by`
    is the account that added the exception, and it stays nullable because the CLI
    and seeded rows may not carry one.
    """

    id: uuid.UUID
    match_kind: str
    match_value: str
    reason: str | None
    created_by: uuid.UUID | None
    expires_at: datetime | None
    expired: bool
    created_at: datetime


class CertificateScopeExceptionCreated(BaseModel):
    """What `POST /dns/certificate-exceptions` answers: the row, without the
    computed fields and without `created_by`, which the create path does not send.
    """

    id: uuid.UUID
    match_kind: str
    match_value: str
    reason: str | None
    expires_at: datetime | None


class TLSCertificateSightingResponse(BaseModel):
    """Where one certificate was observed, and what the review decided about it.

    `subjects` is every hostname the certificate was reported for at this endpoint
    (AUD-037); the row is keyed by (certificate, address, port, source), so the
    names are evidence rather than identity and one sighting can carry several.

    `signals` is what the provider said, kept whole so a new signal needs no column.
    A model of its keys would be a second copy of the scoring rules.

    `verdict` stays a string although the client closes it with a union: the sweep
    writes five values and an older row has to keep listing.
    """

    id: uuid.UUID
    subject: str | None
    subjects: list[str]
    ip: str | None
    port: int | None
    source: str
    is_ours: bool
    #: 0-100, from the rules that judged this sighting.
    confidence: int
    signals: dict[str, Any]
    verdict: str
    first_seen_at: datetime
    last_seen_at: datetime
    reviewed_at: datetime | None
    review_note: str | None


class TLSCertificateResponse(BaseModel):
    """One certificate as an object that outlives any single hostname.

    Design B's view: the same certificate is legitimately seen by the probe, by
    Certificate Transparency and by a provider, so the interesting question — "is a
    certificate of ours served somewhere that is not ours?" — is asked of the
    certificate. `foreign_sightings` is the count the list sorts by eye, and
    `sightings` is where the review workflow acts.
    """

    id: uuid.UUID
    fingerprint_sha256: str
    fingerprint_sha1: str | None
    #: Subject Public Key Info digest: the identity that survives a re-issue.
    spki_sha256: str | None
    serial_hex: str | None
    subject_dn: str | None
    issuer_dn: str | None
    not_before: datetime | None
    not_after: datetime | None
    san_dns: list[str]
    key_algo: str | None
    #: Which kind of evidence created the row first: `our_probe`, `ct` or `provider`.
    origin: str
    first_seen_at: datetime
    last_seen_at: datetime
    sightings: list[TLSCertificateSightingResponse]
    foreign_sightings: int


class TLSCertificatePageResponse(PaginatedResponse[TLSCertificateResponse]):
    """A page of the review list with the counters the table pages by."""

    items: list[TLSCertificateResponse]


@router.get("/certificates", response_model=TLSCertificatePageResponse)
async def list_certificates(
    request: Request,
    verdict: str | None = Query(None, pattern="^(candidate|expected|shared_infrastructure|confirmed_foreign|rejected)$"),
    foreign_only: bool = Query(False),
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    """Certificates and the places each one was observed, with the review state."""
    from app.services.tls_identity_service import identities_payload

    items, total = await identities_payload(db, verdict=verdict, foreign_only=foreign_only, page=page, size=size)
    await AuditLogger.emit_background(db, action="dns_security.certificates.list", ip_address=extract_ip(request), user_id=user.id, details={"verdict": verdict, "foreign_only": foreign_only, "count": len(items), "total": total})
    # The projection stays the service's; what the boundary adds is the contract. A key
    # the composer drops is a failure here instead of a blank cell in the triage view.
    return TLSCertificatePageResponse(
        items=[TLSCertificateResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        size=size,
        pages=math.ceil(total / size) if size else 0,
    )


@router.patch("/certificates/sightings/{sighting_id}", response_model=TLSSightingReview)
async def review_certificate_sighting(
    sighting_id: uuid.UUID,
    payload: CertificateVerdict,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
):
    """Record what the operator decided about one sighting.

    A verdict other than ``candidate`` is what keeps the rules quiet about this
    sighting: the next sweep only queues for candidates, so a judgement survives
    every later scan.
    """
    from app.services.tls_identity_service import record_verdict

    sighting = await record_verdict(db, sighting_id=sighting_id, verdict=payload.verdict, user_id=user.id, note=payload.note)
    if sighting is None:
        raise NotFoundException("Certificate sighting not found")
    await AuditLogger.emit(db, action=f"tls.sighting.{payload.verdict}", ip_address=extract_ip(request), user_id=user.id, details={"sighting_id": str(sighting.id), "identity_id": str(sighting.identity_id), "ip": sighting.ip, "port": sighting.port, "source": sighting.source, "subject": sighting.subject, "note": payload.note}, require_persistence=True, commit=False)
    await db.commit()
    return TLSSightingReview(
        id=str(sighting.id),
        verdict=sighting.verdict,
        reviewed_at=sighting.reviewed_at,
    )


@router.get("/certificate-exceptions", response_model=list[CertificateScopeExceptionResponse])
async def list_certificate_exceptions(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    """Identities, keys, addresses, ASNs and issuers the rules must not alert on."""
    from app.services.tls_identity_service import exceptions_payload

    items = await exceptions_payload(db)
    await AuditLogger.emit_background(db, action="dns_security.certificate_exceptions.list", ip_address=extract_ip(request), user_id=user.id, details={"count": len(items)})
    return items


@router.post("/certificate-exceptions", status_code=201, response_model=CertificateScopeExceptionCreated)
async def create_certificate_exception(
    payload: CertificateExceptionCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Allow one certificate out of the scope rules, with a reason on the record."""
    from app.services.tls_identity_service import add_exception

    try:
        row = await add_exception(db, match_kind=payload.match_kind, match_value=payload.match_value, reason=payload.reason, user_id=user.id, expires_at=payload.expires_at)
    except ValueError as exc:
        from app.core.exceptions import BadRequestException

        raise BadRequestException(str(exc)) from exc
    await AuditLogger.emit(db, action="tls.exception.added", ip_address=extract_ip(request), user_id=user.id, details={"exception_id": str(row.id), "match_kind": row.match_kind, "match_value": row.match_value, "reason": row.reason, "expires_at": row.expires_at.isoformat() if row.expires_at else None}, require_persistence=True, commit=False)
    await db.commit()
    return {"id": str(row.id), "match_kind": row.match_kind, "match_value": row.match_value, "reason": row.reason, "expires_at": row.expires_at}


@router.delete("/certificate-exceptions/{exception_id}", status_code=204)
async def delete_certificate_exception(
    exception_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    from app.models.tls_certificate import CertificateScopeException

    row = (await db.execute(select(CertificateScopeException).where(CertificateScopeException.id == exception_id).with_for_update())).scalar_one_or_none()
    if row is None:
        raise NotFoundException("Certificate scope exception not found")
    details = {"exception_id": str(row.id), "match_kind": row.match_kind, "match_value": row.match_value}
    await db.delete(row)
    await AuditLogger.emit(db, action="tls.exception.removed", ip_address=extract_ip(request), user_id=user.id, details=details, require_persistence=True, commit=False)
    await db.commit()
    return None
