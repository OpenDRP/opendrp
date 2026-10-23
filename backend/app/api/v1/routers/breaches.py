import math
import uuid
from datetime import timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

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
from app.services.asset_matching import (
    POLICY_DISPLAY,
    asset_key_variants,
    asset_scope,
    key_variants,
    resolution_predicate,
)
from app.services.breach_severity import severity_rank_case
from app.services.ingestion_service import BREACH_EXPOSURE_KINDS
from app.services.scan_admission import NoEnabledConnector, ScanAdmissionUnavailable, ScanAlreadyRunning
from app.core.manual_rate_limit import SCOPE_ASSETS, enforce_manual_rate_limit
from app.models.asset import Asset, AssetType
from app.schemas.asset import (
    AssetCreate,
    PromotedAssetResponse,
    validate_and_normalize_asset_value,
)
from app.services.asset_service import AssetService, asset_type_value
from app.models.breach import Breach
from app.models.connector import Connector
from app.models.ingestion_event import IngestionEvent
from app.models.job import Job, JobStatus
from app.schemas.common import MAX_PAGE_SIZE, CleanupResponse
from app.schemas.connector import ScanStartResponse
from app.schemas.phishing import ThreatStatus
from app.schemas.breaches import (
    BreachDomainReadiness,
    BreachDomainVerificationReadiness,
    BreachDomainVerificationRequest,
    BreachFlag,
    BreachListResponse,
    BreachSeverity,
    BreachSortField,
    BreachProviderEntitlements,
    BreachProviderReadinessResponse,
    BreachResponse,
    BreachScanDomainRequest,
    BreachScanEmailRequest,
    SortDirection,
)

router = APIRouter(prefix="/breaches", tags=["Breaches"])

#: How many verification attempts are read back for the readiness card. Bounded, because
#: the page needs the newest attempt per domain and a source is verified a handful of times
#: in its life — not the whole job history (WI-20).
_VERIFICATION_HISTORY = 50

#: The verification outcomes a page may render, mirroring what the worker reports. A
#: value outside this set is a summary this core does not understand, which is left out
#: rather than presented as an attempt that said something it did not.
_VERIFICATION_STATUSES = ("generated", "verified", "not_verified", "failed")
_VERIFICATION_ACTIONS = ("generate", "verify")

#: A scan that has finished, whatever it concluded. A scan still running is not a
#: boundary "new since" can be measured against: its findings would be "old" the
#: moment it started, including the ones it has not reported yet.
_TERMINAL_JOB_STATUSES = (
    JobStatus.success.value,
    JobStatus.partial.value,
    JobStatus.error.value,
    JobStatus.cancelled.value,
    JobStatus.skipped.value,
)


async def _last_breach_scan_at(db: AsyncSession):
    """When the most recent breach scan finished, or ``None`` if none has.

    The module's connector-declared job types are ``breaches.<provider>``, which is
    the module's own namespace, so the prefix is the boundary rather than a list of
    provider names the core would have to keep in step with the registry.

    A verification step is a job in that namespace but not a scan (WI-20), so it is
    excluded: otherwise copying a TXT record would move the instant "new since the
    last scan" is measured from, and the findings the last real scan turned up would
    stop being new without a scan having run.
    """
    return (
        await db.execute(
            _without_verification_jobs(
                select(func.max(func.coalesce(Job.finished_at, Job.started_at, Job.created_at))).where(
                    Job.job_type.like("breaches.%"), Job.status.in_(_TERMINAL_JOB_STATUSES)
                )
            )
        )
    ).scalar()


async def _unannounced_count(db: AsyncSession) -> int:
    """Breach notifications that have arrived and not been delivered (F-06).

    Read from the outbox rather than from the findings: the finding is on the page
    either way, and what an operator needs to know is whether the *channel* has
    said anything about them. A row the noise policy consumed deliberately is not
    counted — it was answered, not lost — and a held one is, because it has not been
    announced to anybody yet.
    """
    return int(
        (
            await db.execute(
                select(func.count(IngestionEvent.id)).where(
                    IngestionEvent.kind == "notification",
                    IngestionEvent.module == "breach",
                    IngestionEvent.processed_at.is_(None),
                )
            )
        ).scalar()
        or 0
    )

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
    """Resolve breach rows to currently configured monitored assets.

    Uses the shared matching rule (``app.services.asset_matching``, WI-08) so a
    breach is named by the same asset the destructive cascade and orphan cleanup
    would link it to. Inactive assets still resolve: they explain why the finding
    exists (``POLICY_DISPLAY``).
    """
    def _candidates(breach: Breach) -> list[tuple[str, str]]:
        """Precedence: an exact *email-account* asset wins over the domain derived
        from that same address. When both a mailbox and its parent domain are
        monitored, the finding is about the mailbox, and naming the domain told the
        analyst nothing about which account was exposed. The domain candidate is
        still used when no email asset matches.
        """
        email = str(breach.matched_email or "").strip()
        domain = str(breach.matched_domain or "").strip()
        inferred_domain = email.rsplit("@", 1)[1] if "@" in email else ""
        candidates: list[tuple[str, str]] = []
        if email:
            candidates.extend(
                (AssetType.email_account.value, key) for key in sorted(key_variants(email))
            )
        domain_value = domain or inferred_domain
        if domain_value:
            candidates.extend(
                (AssetType.domain.value, key) for key in sorted(key_variants(domain_value))
            )
        return candidates

    by_breach = {breach.id: _candidates(breach) for breach in breaches}
    wanted = [candidate for candidates in by_breach.values() for candidate in candidates]
    if not wanted:
        return {}

    result = await db.execute(
        select(Asset.asset_type, Asset.asset_value).where(
            resolution_predicate(wanted), *asset_scope(POLICY_DISPLAY)
        )
    )
    assets = [
        (
            str(getattr(asset_type, "value", asset_type)),
            str(asset_value),
            asset_key_variants(asset_type, asset_value),
        )
        for asset_type, asset_value in result.all()
    ]
    resolved: dict[uuid.UUID, tuple[str, str]] = {}
    for breach in breaches:
        for asset_type, key in by_breach[breach.id]:
            matched = next(
                (
                    candidate_value
                    for candidate_type, candidate_value, variants in assets
                    if candidate_type == asset_type and key in variants
                ),
                None,
            )
            if matched is not None:
                resolved[breach.id] = (matched, asset_type)
                break
    return resolved


#: The column behind each sortable field (F-13). Keyed by exactly the literals the
#: schema declares, so a value outside the set is refused with a 422 before it can
#: reach ``ORDER BY``. ``severity`` is ordered by its rank rather than alphabetically:
#: the letters of "critical".."unknown" sort a leak of an address list above a leak of
#: passwords, which is the opposite of the question the list answers.
_BREACH_SORT_COLUMNS: dict[str, Any] = {
    "created_at": Breach.created_at,
    "breach_date": Breach.breach_date,
    "pwn_count": Breach.pwn_count,
    "severity": severity_rank_case(Breach.severity),
}

#: The attribute each flag filter reads. The flags are the reporting source's own
#: statements, so they are asked of the stored payload rather than invented by the core.
_BREACH_FLAG_ATTRIBUTES: dict[str, str] = {
    "verified": "is_verified",
    "spam": "is_spam_list",
    "fabricated": "is_fabricated",
    "sensitive": "is_sensitive",
}


def _breach_payload(
    breach: Breach,
    resolved_asset: tuple[str, str] | None = None,
    email_incident_count: int | None = None,
) -> dict:
    payload = {column.name: getattr(breach, column.name) for column in breach.__table__.columns}
    payload["matched_asset"] = resolved_asset[0] if resolved_asset else None
    payload["matched_asset_type"] = resolved_asset[1] if resolved_asset else None
    payload["email_incident_count"] = email_incident_count
    # Read from the model rather than from the column loop above: the flag is a
    # statement about the row (its date is the observation's, not the incident's),
    # and a response that omitted it would let the page print a made-up day as the
    # breach date (F-02).
    payload["metadata_incomplete"] = breach.metadata_incomplete
    return payload


async def _email_incident_counts(db: AsyncSession, breaches: list[Breach]) -> dict[str, int]:
    """How many incidents the platform holds about each address on this page (F-13).

    One row is one incident about one account, so an address that already appears in
    three others is a triage fact the list would otherwise hide: triaging each row as
    if it were the first is how the same account gets handled four times. Counted in
    one grouped query over the addresses actually shown (at most a page), and across
    the whole module rather than the current filter — the question is about the
    address, not about the view. An incident is identified by its source and its name,
    because two sources reporting the same incident are two rows by design.
    """
    emails = {
        (breach.matched_email or "").strip().lower()
        for breach in breaches
        if breach.matched_email
    }
    if not emails:
        return {}
    incident_key = Breach.source_id.concat(":").concat(Breach.breach_name)
    rows = (
        await db.execute(
            select(func.lower(Breach.matched_email), func.count(func.distinct(incident_key)))
            .where(func.lower(Breach.matched_email).in_(sorted(emails)))
            .group_by(func.lower(Breach.matched_email))
        )
    ).all()
    return {str(email): int(count or 0) for email, count in rows if email}


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
    finding_id: uuid.UUID | None = None,
    new_since_last_scan: bool = Query(
        False,
        description=(
            "Keep only findings that arrived at or after the most recent finished "
            "breach scan"
        ),
    ),
    exposure_kind: str | None = Query(
        None,
        # The vocabulary is the one ingestion validates against, so the filter can
        # never offer a class the core refuses to store (WI-21).
        pattern="^(" + "|".join(BREACH_EXPOSURE_KINDS) + ")$",
        description=(
            "Keep only findings of this class of exposure: a breach of an account, "
            "a paste it appeared in, or a stealer log a site was found in"
        ),
    ),
    severity: BreachSeverity | None = Query(
        None,
        description=(
            "Keep only findings of this severity, derived from the classes of data "
            "they exposed; `unknown` means the platform does not recognize them"
        ),
    ),
    flag: BreachFlag | None = Query(
        None,
        description=(
            "Keep only findings the source flagged: `verified`, `spam`, "
            "`fabricated` or `sensitive`"
        ),
    ),
    status: ThreatStatus | None = Query(
        None,
        description=(
            "Keep only findings an operator has triaged to this status: `active`, "
            "`investigating` or `resolved`"
        ),
    ),
    source: str | None = Query(
        None, max_length=100, description="Keep only findings reported by this source"
    ),
    domain: str | None = Query(
        None,
        max_length=255,
        description=(
            "Keep only findings about this domain: its matched domain, or an address "
            "at it"
        ),
    ),
    sort: BreachSortField = Query("created_at"),
    order: SortDirection = Query("desc"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    skip = (page - 1) * size
    stmt = select(Breach)
    count_stmt = select(func.count(Breach.id)).select_from(Breach)

    # Resolved once and reported back, so the filtered list can say what it was
    # filtered against instead of leaving an operator to guess (WI-09).
    new_since = await _last_breach_scan_at(db) if new_since_last_scan else None

    conditions = []
    if finding_id is not None:
        conditions.append(Breach.id == finding_id)
    if new_since is not None:
        # SQLite hands a stored instant back naive; the comparison is against UTC.
        cutoff = new_since if new_since.tzinfo else new_since.replace(tzinfo=timezone.utc)
        conditions.append(Breach.created_at >= cutoff)
    if exposure_kind:
        conditions.append(Breach.exposure_kind == exposure_kind)
    if severity:
        # The stored value, not a recomputation: the page's badge, this filter and the
        # sort all read the number ingestion wrote (F-13).
        conditions.append(Breach.severity == severity)
    if flag:
        # Asked of the source's own payload. ``as_boolean`` compiles to the same
        # question on both databases the platform runs on, unlike a text comparison.
        conditions.append(
            Breach.attributes[_BREACH_FLAG_ATTRIBUTES[flag]].as_boolean().is_(True)
        )
    if status:
        # The triage state an operator set, not something the source said: filtering
        # by it is how a shift hands over "what we are still working on".
        conditions.append(Breach.status == status)
    if source:
        conditions.append(Breach.source_id == source.strip())
    if domain:
        wanted = domain.strip().strip(".").lower()
        conditions.append(
            or_(
                func.lower(Breach.matched_domain) == wanted,
                func.lower(Breach.matched_email).like(f"%@{wanted}"),
            )
        )
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

    # `id` breaks ties, so a row cannot appear on two pages of one listing.
    direction = (
        _BREACH_SORT_COLUMNS[sort].desc()
        if order == "desc"
        else _BREACH_SORT_COLUMNS[sort].asc()
    )
    tie = Breach.id.asc() if order == "asc" else Breach.id.desc()
    stmt = stmt.order_by(direction, tie).offset(skip).limit(size)

    items_result = await db.execute(stmt)
    items = list(items_result.scalars().all())
    matched_assets = await _asset_matches_for_breaches(db, items)
    incidents_by_email = await _email_incident_counts(db, items)

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
            "new_since_last_scan": new_since_last_scan,
            "exposure_kind": exposure_kind,
            "severity": severity,
            "flag": flag,
            "status": status,
            "source": source,
            "domain": domain,
            "sort": sort,
            "order": order,
        },
    )
    return BreachListResponse(
        # Validated rather than handed over as the row's column dump: the payload is
        # built from the table's own columns, so what the response declares and what
        # it publishes are the same fields.
        items=[
            BreachResponse.model_validate(
                _breach_payload(
                    item,
                    matched_assets.get(item.id),
                    incidents_by_email.get((item.matched_email or "").lower())
                    if item.matched_email
                    else None,
                )
            )
            for item in items
        ],
        total=total,
        page=page,
        size=size,
        pages=pages,
        unannounced=await _unannounced_count(db),
        new_since=new_since,
    )


async def _data_class_labels(db: AsyncSession) -> dict[str, str]:
    """The classes of data this module's sources report, in the sources' own words (F-04).

    Merged over the enabled connectors of the module: an installation with two breach
    sources shows the label both of them published for a class they have in common, and a
    source that publishes none contributes nothing — the page then renders the stored
    name, which is what it showed before labels existed.
    """
    rows = (
        await db.execute(
            select(Connector.readiness).where(
                Connector.connector_type == "breaches", Connector.status == "enabled"
            )
        )
    ).scalars()
    labels: dict[str, str] = {}
    for readiness in rows:
        published = (readiness or {}).get("data_class_labels")
        if not isinstance(published, dict):
            continue
        for key, value in published.items():
            if isinstance(key, str) and isinstance(value, str) and key and value:
                labels.setdefault(key[:128], value[:256])
    return labels


def _optional_str(value, limit: int) -> str | None:
    return str(value)[:limit] if isinstance(value, str) and value else None


def _optional_int(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _optional_bool(value) -> bool | None:
    return value if isinstance(value, bool) else None


def _without_verification_jobs(statement):
    """A job query that ignores verification work (WI-20).

    A verification request is admitted through the same route, claimed by the same worker
    and reported the same way, so it is a ``breaches`` job — but it is not a scan, and
    reading it as "the last scan" would replace a real scan's readiness (domains, pace,
    entitlements) with a summary that has none of them on the strength of somebody copying
    a TXT record.
    """
    return statement.where(Job.params["domain_verification"].as_string().is_(None))


async def _domain_verifications(db: AsyncSession) -> list[BreachDomainVerificationReadiness]:
    """The newest verification attempt per domain, as the core read it back (WI-20).

    Read from the *jobs* rather than from a table of its own: the attempt is what the
    operator asked for, the result is what the worker answered, and the job is where both
    already live — with the audit trail naming who asked. Only terminal jobs are read, so a
    request still in flight does not hide the previous answer, and a summary this core does
    not understand is skipped rather than rendered as a verdict.
    """
    rows = (
        await db.execute(
            select(Job)
            .where(
                Job.job_type.like("breaches.%"),
                Job.status.in_(_TERMINAL_JOB_STATUSES),
                Job.params["domain_verification"].as_string().is_not(None),
            )
            .order_by(
                func.coalesce(Job.finished_at, Job.started_at, Job.created_at).desc(),
                Job.created_at.desc(),
            )
            .limit(_VERIFICATION_HISTORY)
        )
    ).scalars()
    latest: dict[str, BreachDomainVerificationReadiness] = {}
    for job in rows:
        summary = job.result_summary if isinstance(job.result_summary, dict) else {}
        request = job.params if isinstance(job.params, dict) else {}
        outcome = summary.get("domain_verification")
        asked = request.get("domain_verification")
        if not isinstance(outcome, dict) or not isinstance(asked, dict):
            continue
        domain = str(outcome.get("domain") or asked.get("domain") or "").strip().lower()
        action = str(outcome.get("action") or asked.get("action") or "").strip().lower()
        status = str(outcome.get("status") or "").strip().lower()
        if (
            not domain
            or action not in _VERIFICATION_ACTIONS
            or status not in _VERIFICATION_STATUSES
        ):
            continue
        if domain in latest:
            continue  # newest first: the first row for a domain is the latest attempt
        latest[domain] = BreachDomainVerificationReadiness(
            domain=domain,
            action=action,
            status=status,
            reason=_optional_str(outcome.get("reason"), 64),
            txt_record_value=_optional_str(outcome.get("txt_record_value"), 1024),
            job_id=job.id,
            requested_at=job.finished_at or job.started_at or job.created_at,
        )
    return [latest[domain] for domain in sorted(latest)]


@router.post("/domain-verification", status_code=202)
async def request_domain_verification(
    request: Request,
    payload: BreachDomainVerificationRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
):
    """Ask one source to enrol a monitored domain, or to check it (WI-20).

    The record is published in DNS by a person and the provider's answer is about an
    account's access to a domain, so this is an operator's step rather than a scan's: the
    request is explicit, audited whether or not it could be queued, and queued without the
    connector's scan slot — verifying a domain has to be possible while a scheduled scan is
    running, because that is exactly when an operator is waiting for the domain to become
    scannable.
    """
    from app.services.connector_service import ConnectorService, normalize_connector_name

    await enforce_manual_rate_limit(
        db=db,
        user=user,
        scope=_SCOPE_CONNECTOR,
        action="breach domain verification",
        ip_address=extract_ip(request),
    )

    service = ConnectorService(db)
    enabled = await service.list_enabled_by_type("breaches")
    if payload.connector:
        wanted = normalize_connector_name(payload.connector)
        enabled = [c for c in enabled if c.name == wanted or wanted in (c.aliases or [])]
    if len(enabled) > 1:
        # Which account enrols the domain is the operator's decision: a verification
        # belongs to one source's account, and asking every source would enrol it in each
        # of their dashboards.
        raise BadRequestException(
            "connector: name the source that should verify this domain — "
            + ", ".join(sorted(conn.name for conn in enabled))
        )
    status, error, jobs = "scheduled", None, []
    if not enabled:
        # Recorded as an attempt that could not be queued: "nobody verified this" and
        # "nobody asked" are different answers on the page, and only the audit row keeps
        # them apart.
        status = "no_connector"
        error = "No enabled breaches connector accepts a verification request"
    else:
        jobs = await service.enqueue_module_scan(
            connector_type="breaches",
            created_by=user.id,
            title=f"Domain verification ({payload.action}): {payload.domain}",
            connector_name=enabled[0].name,
            params={
                "trigger": "manual",
                "emails": [],
                "domains": [],
                "domain_verification": {
                    "action": payload.action,
                    "domain": payload.domain,
                },
            },
            admission=False,
        )
    await AuditLogger.emit(
        db,
        action="breach.domain_verification.requested",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "domain": payload.domain,
            "verification_action": payload.action,
            "connector": enabled[0].name if enabled else None,
            "status": status,
            "error": error,
            "jobs": [str(job.id) for job in jobs],
        },
    )
    body: dict = {
        "status": status,
        "domain": payload.domain,
        "action": payload.action,
        "job_ids": [str(job.id) for job in jobs],
    }
    if error:
        body["error"] = error
    return body


@router.get("/provider-readiness", response_model=BreachProviderReadinessResponse)
async def provider_readiness(
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_active_account),
):
    """What the last breach scan could ask, and what it was refused (F-04, WI-14).

    A breach list with nothing in it has two very different meanings: the provider was
    asked and had nothing, or the provider refused to be asked. The scan's own summary
    holds the difference — which domains it was refused and why, what the account is
    entitled to, and the pace it ran at — and this endpoint reports it beside the list
    so the page and the job history cannot disagree about the same scan.
    """
    scan = (
        await db.execute(
            _without_verification_jobs(
                select(Job).where(
                    Job.job_type.like("breaches.%"),
                    Job.status.in_(_TERMINAL_JOB_STATUSES),
                )
            )
            .order_by(
                func.coalesce(Job.finished_at, Job.started_at, Job.created_at).desc(),
                Job.created_at.desc(),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    labels = await _data_class_labels(db)
    verifications = await _domain_verifications(db)
    if scan is None:
        # No scan has finished, which is not "the last scan came back empty". A
        # verification attempt is still reported: it is the answer to a question an
        # operator asked, and it exists whether or not any scan ever ran (WI-20).
        return BreachProviderReadinessResponse(
            data_class_labels=labels, verifications=verifications
        )

    params = scan.params if isinstance(scan.params, dict) else {}
    summary = scan.result_summary if isinstance(scan.result_summary, dict) else {}
    provider = summary.get("provider_readiness")
    provider = provider if isinstance(provider, dict) else {}
    refused = {
        str(item.get("domain")): item.get("reason")
        for item in (summary.get("domains_unscanned") or [])
        if isinstance(item, dict) and item.get("domain")
    }
    #: A scan that stopped early cannot say the domains it never reached were asked
    #: about, and "we did not get there" is not "there was nothing to find".
    stopped_short = bool(summary.get("budget_exhausted"))
    domains = [
        BreachDomainReadiness(
            domain=str(domain),
            reason=refused[domain],
            status="unscanned",
        )
        if str(domain) in refused
        else BreachDomainReadiness(
            domain=str(domain),
            status="unknown" if stopped_short else "asked",
            reason="scan_stopped_short" if stopped_short else None,
        )
        for domain in (params.get("domains") or [])
    ]
    skipped = summary.get("skipped_reasons")
    reasons = {
        str(key): int(value)
        for key, value in (skipped.items() if isinstance(skipped, dict) else [])
        if isinstance(value, int) and not isinstance(value, bool)
    }
    #: The source the scan ran on, so a verification request from this page can name it
    #: instead of asking an operator to pick from a list they cannot see here. A job whose
    #: connector row is gone keeps ``None`` — the request then takes the unambiguous
    #: default or is refused with the names that are left.
    origin = await db.get(Connector, scan.connector_id) if scan.connector_id else None
    return BreachProviderReadinessResponse(
        scan_job_id=scan.id,
        connector=origin.name if origin is not None else None,
        scanned_at=scan.finished_at or scan.started_at or scan.created_at,
        status=scan.status,
        partial=scan.status == JobStatus.partial.value,
        reasons=reasons,
        entitlements=BreachProviderEntitlements(
            subscription=_optional_str(provider.get("subscription"), 64),
            requests_per_minute=_optional_int(provider.get("reported_requests_per_minute")),
            includes_stealer_logs=_optional_bool(provider.get("includes_stealer_logs")),
            includes_kanon=_optional_bool(provider.get("includes_kanon")),
            domains_verified=_optional_int(provider.get("subscribed_domains")),
        ),
        pacing={
            str(key): value
            for key, value in (
                (summary.get("pacing") or {}).items()
                if isinstance(summary.get("pacing"), dict)
                else []
            )
            if isinstance(value, (str, int, bool))
        },
        domains=domains,
        unscanned_total=len(refused),
        # The labels belong to the source rather than to one scan, so they are read from
        # the registry: a scan that ran before the connector published any still renders
        # the stored class names, and a later one does not have to re-teach the page.
        data_class_labels=labels,
        verifications=verifications,
    )


@router.post("/cleanup-orphans", response_model=CleanupResponse)
async def clean_orphan_breach_findings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """Delete breach findings that are not linked to any configured asset."""
    from app.services.asset_service import AssetService

    cleanup = await AssetService(db).clean_orphan_breach_findings()
    await AuditLogger.emit(
        db,
        action="breach.orphans.cleaned",
        ip_address=extract_ip(request),
        user_id=user.id,
        # The rows commit inside the service, so this row is the only record of
        # which findings went: the count alone cannot answer that (AUD-030).
        details={
            "deleted": cleanup.deleted,
            "sample_finding_ids": cleanup.sample,
        },
    )
    return {"status": "completed", "deleted": cleanup.deleted}


@router.get("/{breach_id}", response_model=BreachResponse)
async def get_breach(
    request: Request,
    breach_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
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
    user=Depends(require_analyse),
):
    result = await db.execute(select(Breach).where(Breach.id == breach_id))
    breach = result.scalar_one_or_none()
    if not breach:
        raise NotFoundException("Breach not found")
    # The status is mutable, so the trail has to carry both ends of the change: the
    # current value cannot reconstruct what an earlier operator did to this row. A
    # request that sets the status it already has is recorded as no change rather
    # than as one.
    previous = str(breach.status or "")
    breach.status = data.status
    await db.flush()
    await AuditLogger.emit(
        db,
        action="breach.update",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "breach_id": str(breach_id),
            "changed_fields": [] if previous == str(data.status) else ["status"],
            "previous_status": previous,
            "status": str(data.status),
        },
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    matched_assets = await _asset_matches_for_breaches(db, [breach])
    return _breach_payload(breach, matched_assets.get(breach.id))


@router.post("/scan", response_model=ScanStartResponse, response_model_exclude_none=True)
async def run_breach_scan(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
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


@router.post(
    "/scan-email",
    status_code=202,
    response_model=ScanStartResponse,
    response_model_exclude_none=True,
)
async def scan_email_breaches(
    request: Request,
    payload: BreachScanEmailRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
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


@router.post(
    "/scan-domain",
    status_code=202,
    response_model=ScanStartResponse,
    response_model_exclude_none=True,
)
async def scan_domain_breaches(
    request: Request,
    payload: BreachScanDomainRequest,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
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


@router.post(
    "/{breach_id}/asset",
    status_code=201,
    response_model=PromotedAssetResponse,
    response_model_exclude_none=True,
)
async def promote_breach_finding_to_asset(
    request: Request,
    breach_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
):
    """Take the mailbox a breach names under monitoring (AWI-13/U-1).

    A breach finding says an account was exposed; the next useful action is often
    "watch this mailbox", and until now that meant retyping the address on the
    assets page. The target is the exposed mailbox when the source named one and
    the affected domain otherwise — both are values the module itself matched, so
    this route cannot invent an asset from unrelated text.

    The promotion is a creation in every way that matters: it charges the assets
    throttle, writes an audit row for both the new and the already-monitored
    case, and answers the same shape as the DNS and exposure promotions.
    """
    breach = (
        await db.execute(select(Breach).where(Breach.id == breach_id))
    ).scalar_one_or_none()
    if breach is None:
        raise NotFoundException("Breach not found")

    if breach.matched_email:
        asset_type = AssetType.email_account
        target = breach.matched_email
    else:
        asset_type = AssetType.domain
        target = breach.matched_domain or breach.domain
    try:
        normalized = validate_and_normalize_asset_value(asset_type.value, target)
    except ValueError as exc:
        raise ConflictException(
            "This breach names a value that cannot be promoted as an asset"
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
        "breach_id": str(breach.id),
        "source_id": breach.source_id,
        "breach_name": breach.breach_name,
        "matched_email": breach.matched_email,
        "matched_domain": breach.matched_domain,
        "subject": target,
        "promoted_from": "breaches",
    }
    if existing is not None:
        await AuditLogger.emit(
            db,
            action="breaches.asset.already_exists",
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
        # The asset and its audit row are one transaction: an inventory change
        # nobody can trace back to the finding that prompted it is not a change
        # this platform makes.
        asset = await AssetService(db).create_asset(
            AssetCreate.model_validate(
                {"asset_type": asset_type.value, "asset_value": normalized}
            ),
            commit=False,
        )
    except ConflictException:
        # A concurrent promotion of the same value won the unique index; this
        # request still happened and still gets its own trail row.
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
        action="breaches.asset.promoted",
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


@router.delete("/{breach_id}", status_code=204)
async def delete_breach(
    request: Request,
    breach_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_analyse),
):
    result = await db.execute(select(Breach).where(Breach.id == breach_id))
    breach = result.scalar_one_or_none()
    if not breach:
        raise NotFoundException("Breach not found")
    details = _breach_audit_snapshot(breach, breach_id)
    await db.delete(breach)
    await AuditLogger.emit(
        db,
        action="breach.delete",
        ip_address=extract_ip(request),
        user_id=user.id,
        details=details,
        require_persistence=True,
        commit=False,
    )
    await db.commit()
    return None
