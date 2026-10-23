import math
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import ColumnElement, String, and_, cast, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_admin
from app.core.audit import AUDIT_ALLOWED_ACTIONS, AuditLogger
from app.core.config import settings
from app.models.audit import AuditArchive, AuditLog
from app.models.user import User
from app.schemas.common import MAX_PAGE_SIZE, PaginatedResponse

router = APIRouter(prefix="/audit", tags=["Audit"])

# Frontend-friendly label map for implemented audit actions.
# Keep this in sync with AUDIT_ALLOWED_ACTIONS used by the backend.
AUDIT_ACTION_LABELS: dict[str, str] = {
    "auth.login.success": "Successful login",
    "auth.login.failure": "Failed login attempt",
    "auth.login.locked": "Login rate limit lock",
    "auth.mfa.setup_started": "Second factor enrolment started",
    "auth.mfa.setup_failed": "Second factor enrolment refused",
    "auth.mfa.enrolled": "Second factor enabled",
    "auth.mfa.disabled": "Second factor disabled",
    "auth.mfa.success": "Second factor accepted",
    "auth.mfa.failure": "Second factor rejected",
    "auth.mfa.required": "Second factor required by policy",
    "auth.password.changed": "Password changed by the account holder",
    "auth.password.change_failed": "Password change refused",
    "auth.logout": "Logout",
    "auth.refresh.success": "Token refresh",
    "auth.refresh.failure": "Token refresh failed",
    "auth.session.revoked": "Session revoked",
    "auth.sessions.revoked_others": "Other sessions revoked",
    "auth.mfa.recovery_codes.rotated": "MFA recovery codes rotated",
    "authz.denied": "Access refused by a role gate",
    "asset.create": "Asset created",
    "asset.update": "Asset updated",
    "asset.delete": "Asset deleted",
    "asset.list": "Asset list viewed",
    "asset.view": "Asset viewed",
    "settings.update": "Settings updated",
    "settings.view": "Settings viewed",
    "settings.runtime.view": "Applied runtime configuration viewed",
    "settings.test_email_sent": "Test email sent",
    "settings.test_email_failed": "Test email failed",
    "report.generate": "Report generation started",
    "report.generate.failed": "Report generation failed",
    "report.list": "Report list viewed",
    "report.download": "Report downloaded",
    "report.download.missing": "Report artifact missing",
    "report.artifact.rejected": "Report artifact value refused",
    "report.delete": "Report deleted",
    "phishing.scan.dnstwist.start": "DNSTwist scan started",
    "phishing.scan.shodan.start": "Shodan scan started",
    "phishing.threat.list": "Phishing threats list viewed",
    "phishing.threat.view": "Phishing threat viewed",
    "phishing.threat.update": "Phishing threat updated",
    "phishing.threat.delete": "Phishing threat deleted",
    "phishing.scan.scheduled": "Scheduled scan started",
    "breach.list": "Breaches list viewed",
    "breach.view": "Breach viewed",
    "breach.update": "Breach updated",
    "breach.delete": "Breach deleted",
    "breach.orphans.cleaned": "Orphan breach findings cleaned",
    "breach.scan.scheduled": "Scheduled breach scan started",
    "breach.scan.start": "Breach scan started",
    "breach.scan.email": "Breach email scan completed",
    "breach.scan.domain": "Breach domain scan completed",
    "breach.domain_verification.requested": "Breach domain verification requested",
    "alert.dispatch.success": "Alert dispatched",
    "alert.dispatch.failed": "Alert dispatch failed",
    "task.started": "Background task started",
    "task.completed": "Background task completed",
    "task.failed": "Background task failed",
    "dashboard.view": "Dashboard viewed",
    "user.created": "User created",
    "user.deleted": "User deleted (purged)",
    "user.updated": "User updated",
    "user.password_reset": "User password reset",
    "user.mfa.reset": "User second factor reset by an administrator",
    "user.onboarding.cleared": "User released from credential onboarding by hand",
    "user.locked": "User lockout set / account deactivated",
    "user.unlocked": "User lockout released / account activated",
    "audit.log.view": "Audit log viewed",
    "audit.retention.purged": "Expired audit history purged",
    "audit.chain.verified": "Audit hash chain verified",
    "audit.chain.progress": "Audit full-verification chunk completed",
    "audit.chain.broken": "Audit hash chain verification failed",
    "audit.integrity.view": "Audit integrity status viewed",
    "outbound.blocked": "Outbound destination refused",
    "settings.telegram.validate": "Telegram chats validated",
    "settings.telegram.validate_failed": "Telegram chat validation failed",
    "connectors.health.view": "Connector health viewed",
    "alerts.health.view": "Alert channels health viewed",
    "connectors.list": "Connectors listed",
    "connector.registered": "Connector registered",
    "connector.findings.ingested": "Connector findings ingested",
    "connector.catalogue.ingested": "Incident catalogue ingested",
    "connector.scan.completed": "Connector scan completed",
    "connector.scan.failed": "Connector scan failed",
    "connector.status.updated": "Connector status updated",
    "connector.config.updated": "Connector config updated",
    "users.list": "Users list viewed",
    "users.view": "User viewed",
    "jobs.list": "Jobs list viewed",
    "dns_security.certificates.list": "Certificate review list viewed",
    "dns_security.certificate_exceptions.list": "Certificate scope exceptions viewed",
    "tls.sighting.candidate": "Certificate sighting reopened for review",
    "tls.sighting.expected": "Certificate deployment marked expected",
    "tls.sighting.shared_infrastructure": "Certificate deployment marked shared infrastructure",
    "tls.sighting.confirmed_foreign": "Certificate deployment confirmed foreign",
    "tls.sighting.rejected": "Certificate deployment evidence rejected",
    "tls.exception.added": "Certificate scope exception added",
    "tls.exception.removed": "Certificate scope exception removed",
}


class AuditActionGroup(BaseModel):
    """One prefix segment's actions, in the order the filter menu lists them."""

    category: str
    actions: list[str]


class AuditActionsCatalog(BaseModel):
    """The filter catalogue: grouped for the menu, flat for the query, labelled for print.

    All four keys are always sent, even though the client marks them optional: the
    route builds every one of them, and a filter menu that guessed which keys arrived
    would have to branch per answer. What this model does not claim is the invariant
    the catalogue keeps — that the groups partition the flat list and that every label
    names an action — because that belongs to the composer and the allowed-action set,
    not to a response shape.
    """

    groups: list[AuditActionGroup]
    total: int
    actions: list[str]
    labels: dict[str, str]


class AuditFullVerification(BaseModel):
    """How far the full pass has walked, and what stopped it when it stopped.

    `at` is the chain state's timestamp passed straight through, so an aware value
    serializes as the rest of the API serializes instants; `last_verification.at`
    below is text because that composer converts it itself. The asymmetry is the
    route's, and the models keep it rather than inventing one convention.
    """

    upper_seq: int
    cursor: int
    in_progress: bool
    at: datetime | None
    failure_seq: int | None
    failure_reason: str | None


class AuditChainMark(BaseModel):
    """A chain position and the hash it ends on.

    Used for both ends of the chain: what it has committed, and what retention has
    retired. One model because the two blocks are one idea — the highest position, and
    the hash the next entry links back to — and two declarations of it would drift.
    """

    through_seq: int
    tip_hash: str | None


class AuditArchiveState(BaseModel):
    """What the archive is configured to do, and the last segment it holds."""

    configured: bool
    #: When set, retention stops instead of deleting rows it could not archive.
    hold: bool
    last_seq: int | None
    retired: bool


class AuditRetainedRange(BaseModel):
    """The retained history's size and position, counted before this view is logged."""

    rows: int
    first_seq: int
    last_seq: int


class AuditLastVerification(BaseModel):
    """The last successful verification, as the ISO text the composer publishes."""

    through_seq: int
    at: str | None


class AuditKeyState(BaseModel):
    """How many signing keys this process holds — a count, never the material."""

    configured: int


class AuditIntegrity(BaseModel):
    """Where the audit hash chain stands, and when it was last verified.

    Nulls are answers here: an empty chain has no tip hash, a healthy one has no
    failure sequence, and an archive that never ran has no last segment. The route
    therefore declares this model without `exclude_none`.
    """

    full_verification: AuditFullVerification
    committed: AuditChainMark
    archive: AuditArchiveState
    retained: AuditRetainedRange
    retired: AuditChainMark
    last_verification: AuditLastVerification
    keys: AuditKeyState


class AuditLogRowResponse(BaseModel):
    """One entry of the trail, as the audit page reads it.

    `user_email` is nullable because it is a snapshot: the writer records
    `details.actor_email` when it knows who acted, the listing falls back to a
    lookup in `users`, and a row written by a writer that had neither sends `null`.

    `key_id` is declared although the page does not read it. The payload sends it,
    the column is non-nullable, and a model that omitted it would answer a narrower
    row than the route's own SELECT — rule 2 is one-way by design, so a client may
    model the half it uses but a model may not silently drop a field.
    """

    id: str
    timestamp: datetime
    user_id: str | None
    user_email: str | None
    #: `snapshot` when the row carries the actor's email, `current_user_lookup`
    #: when it was resolved against the account table at read time.
    actor_identity_source: str
    seq: int
    entry_hash: str
    key_id: int
    action: str
    ip_address: str
    details: dict[str, Any]


class AuditLogPageResponse(PaginatedResponse[AuditLogRowResponse]):
    """A page of the trail with the counters the table pages by."""

    items: list[AuditLogRowResponse]


def _group_actions_by_prefix() -> list[dict[str, Any]]:
    groups: "OrderedDict[str, list[str]]" = OrderedDict()
    for action in sorted(AUDIT_ALLOWED_ACTIONS):
        if "." in action:
            prefix = action.split(".", 1)[0]
        else:
            prefix = "other"
        groups.setdefault(prefix, []).append(action)
    return [{"category": cat, "actions": sorted(acts)} for cat, acts in groups.items()]


@router.get("/actions", response_model=AuditActionsCatalog)
async def list_audit_actions(
    current_user: User = Depends(require_admin),
):
    return AuditActionsCatalog(
        groups=[AuditActionGroup.model_validate(group) for group in _group_actions_by_prefix()],
        total=len(AUDIT_ALLOWED_ACTIONS),
        actions=sorted(AUDIT_ALLOWED_ACTIONS),
        labels=AUDIT_ACTION_LABELS,
    )


@router.get("/integrity", response_model=AuditIntegrity)
async def audit_integrity(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Where the audit hash chain stands, and when it was last verified.

    Deliberately a *status* endpoint rather than a verification trigger: a full
    pass over a year of audit history has no place in a request that a browser
    can repeat, and the scheduled task is what performs the check. An operator
    who needs a pass right now runs `python -m scripts.verify_audit_chain`.
    """
    from app.core.audit_chain import chain_state

    state = await chain_state(db)
    aggregate = (
        await db.execute(
            select(
                func.count(AuditLog.id),
                func.min(AuditLog.seq),
                func.max(AuditLog.seq),
            )
        )
    ).one()
    retained_rows = int(aggregate[0] or 0)

    retained = {
        "rows": retained_rows,
        "first_seq": int(aggregate[1] or 0),
        "last_seq": int(aggregate[2] or 0),
    }
    # Kept as a named local rather than nested inline: the audit record below
    # quotes the same two numbers the response carries, so it must read them
    # from the same place instead of repeating the expressions.
    retired = {
        "through_seq": int(state.retired_through_seq or 0),
        "tip_hash": state.retired_tip_hash,
    }

    await AuditLogger.emit(
        db,
        action="audit.integrity.view",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={
            "retained_rows": retained_rows,
            "retired_through_seq": retired["through_seq"],
        },
    )

    archive = (await db.execute(select(AuditArchive).order_by(AuditArchive.last_seq.desc()).limit(1))).scalar_one_or_none()
    return AuditIntegrity(
        full_verification=AuditFullVerification(
            upper_seq=state.full_verify_upper_seq,
            cursor=state.full_verify_cursor,
            in_progress=bool(state.full_verify_upper_hash),
            at=state.last_full_verified_at,
            failure_seq=state.last_failure_seq,
            failure_reason=state.last_failure_reason,
        ),
        committed=AuditChainMark(
            through_seq=state.committed_seq, tip_hash=state.committed_tip_hash
        ),
        archive=AuditArchiveState(
            configured=bool(settings.AUDIT_ARCHIVE_DIR),
            hold=settings.AUDIT_RETENTION_HOLD,
            last_seq=archive.last_seq if archive else None,
            retired=bool(archive and archive.retired_at),
        ),
        retained=AuditRetainedRange(**retained),
        retired=AuditChainMark.model_validate(retired),
        last_verification=AuditLastVerification(
            through_seq=int(state.last_verified_seq or 0),
            at=state.last_verified_at.isoformat() if state.last_verified_at else None,
        ),
        keys=AuditKeyState(configured=len(settings.audit_chain_keys)),
    )


@router.get("/logs", response_model=AuditLogPageResponse)
async def list_audit_logs(
    request: Request,
    action: str | None = Query(None, max_length=120),
    after_seq: int | None = Query(None, ge=0),
    request_id: str | None = Query(None, max_length=128),
    job_id: uuid.UUID | None = None,
    outcome: str | None = Query(None, pattern="^(success|failure)$"),
    user_id: uuid.UUID | None = None,
    user_email: str | None = None,
    search: str | None = None,
    from_date: datetime | None = None,
    to_date: datetime | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    skip = (page - 1) * size
    conditions: list[ColumnElement[bool]] = []

    if after_seq is not None:
        conditions.append(AuditLog.seq > after_seq)
    if request_id:
        conditions.append(AuditLog.details["request_id"].as_string() == request_id)
    if job_id:
        conditions.append(AuditLog.details["job_id"].as_string() == str(job_id))
    if outcome:
        failure = or_(AuditLog.action.like("%.failed"), AuditLog.action.like("%.failure"), AuditLog.action == "audit.chain.broken")
        conditions.append(failure if outcome == "failure" else ~failure)
    if action:
        allowed = [a for a in AUDIT_ALLOWED_ACTIONS if a.lower() == action.lower()]
        if allowed:
            conditions.append(AuditLog.action == allowed[0])
        else:
            conditions.append(AuditLog.action == action)

    if user_id is not None:
        conditions.append(AuditLog.user_id == user_id)
    elif user_email:
        raw_email = user_email.strip()[:255]
        escaped_email = raw_email.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        like = f"%{escaped_email}%"
        # Correlate against the audit row explicitly. An EXISTS predicate is
        # portable across PostgreSQL and SQLite and avoids relying on the
        # dialect's treatment of an uncorrelated IN subquery when the audit row
        # contains a nullable user_id.
        conditions.append(
            or_(AuditLog.details["actor_email"].as_string().ilike(like, escape="\\"), exists(
                select(1)
                .select_from(User)
                .where(
                    User.id == AuditLog.user_id,
                    User.email.ilike(like, escape="\\"),
                )
                .correlate(AuditLog)
            ))
        )

    if from_date:
        if from_date.tzinfo is None:
            from_date = from_date.replace(tzinfo=timezone.utc)
        conditions.append(AuditLog.timestamp >= from_date)
    if to_date:
        if to_date.tzinfo is None:
            to_date = to_date.replace(tzinfo=timezone.utc)
        conditions.append(AuditLog.timestamp <= to_date)

    if search:
        raw_search = search.strip()[:100]
        escaped = raw_search.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        like = f"%{escaped}%"
        conditions.append(
            or_(
                AuditLog.action.ilike(like, escape="\\"),
                AuditLog.ip_address.ilike(like, escape="\\"),
                cast(AuditLog.details, String).ilike(like, escape="\\"),
            )
        )

    # and_() with no arguments yields a true() clause, preserving the old
    # unfiltered-listing behavior while keeping the predicate well-typed.
    where_clause = and_(*conditions)

    count_stmt = select(func.count(AuditLog.id)).select_from(AuditLog).where(where_clause)
    total = int((await db.execute(count_stmt)).scalar() or 0)

    stmt = (
        select(AuditLog, User.email.label("user_email"))
        .outerjoin(User, AuditLog.user_id == User.id)
        .where(where_clause)
        .order_by(AuditLog.seq.asc() if after_seq is not None else AuditLog.timestamp.desc(), AuditLog.id.desc())
        .offset(skip)
        .limit(size)
    )
    rows = (await db.execute(stmt)).all()
    items: list[AuditLogRowResponse] = []
    for log_row, email in rows:
        items.append(
            AuditLogRowResponse(
                id=str(log_row.id),
                timestamp=log_row.timestamp,
                user_id=str(log_row.user_id) if log_row.user_id else None,
                user_email=(log_row.details or {}).get("actor_email") or email,
                actor_identity_source=(
                    "snapshot"
                    if (log_row.details or {}).get("actor_email")
                    else "current_user_lookup"
                ),
                seq=log_row.seq,
                entry_hash=log_row.entry_hash,
                key_id=log_row.key_id,
                action=log_row.action,
                ip_address=log_row.ip_address,
                details=log_row.details or {},
            )
        )

    pages = math.ceil(total / size) if size > 0 else 0
    await AuditLogger.emit_background(
        db,
        action="audit.log.view",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={
            "action_filter": action,
            "user_id_filter": str(user_id) if user_id else None,
            "user_email_filter": bool(user_email),
            "search_used": bool(search),
            "from_date": from_date.isoformat() if from_date else None,
            "to_date": to_date.isoformat() if to_date else None,
            "page": page,
            "size": size,
            "results": total,
        },
    )
    return AuditLogPageResponse(
        items=items, total=total, page=page, size=size, pages=pages
    )
