import math
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import ColumnElement, String, and_, cast, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_admin
from app.core.audit import AUDIT_ALLOWED_ACTIONS, AuditLogger
from app.core.config import settings
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.common import PaginatedResponse

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
    "user.locked": "User locked / deactivated",
    "user.unlocked": "User unlocked / activated",
    "audit.log.view": "Audit log viewed",
    "audit.retention.purged": "Expired audit history purged",
    "audit.chain.verified": "Audit hash chain verified",
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
    "connector.scan.completed": "Connector scan completed",
    "connector.scan.failed": "Connector scan failed",
    "connector.status.updated": "Connector status updated",
    "connector.config.updated": "Connector config updated",
    "users.list": "Users list viewed",
    "users.view": "User viewed",
    "jobs.list": "Jobs list viewed",
}


def _group_actions_by_prefix() -> list[dict[str, Any]]:
    groups: "OrderedDict[str, list[str]]" = OrderedDict()
    for action in sorted(AUDIT_ALLOWED_ACTIONS):
        if "." in action:
            prefix = action.split(".", 1)[0]
        else:
            prefix = "other"
        groups.setdefault(prefix, []).append(action)
    return [{"category": cat, "actions": sorted(acts)} for cat, acts in groups.items()]


@router.get("/actions")
async def list_audit_actions(
    current_user: User = Depends(require_admin),
):
    return {
        "groups": _group_actions_by_prefix(),
        "total": len(AUDIT_ALLOWED_ACTIONS),
        "actions": sorted(AUDIT_ALLOWED_ACTIONS),
        "labels": AUDIT_ACTION_LABELS,
    }


@router.get("/integrity")
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

    return {
        "retained": retained,
        "retired": retired,
        "last_verification": {
            "through_seq": int(state.last_verified_seq or 0),
            "at": state.last_verified_at.isoformat() if state.last_verified_at else None,
        },
        "keys": {"configured": len(settings.audit_chain_keys)},
    }


@router.get("/logs", response_model=PaginatedResponse[Any])
async def list_audit_logs(
    request: Request,
    action: str | None = None,
    user_id: uuid.UUID | None = None,
    user_email: str | None = None,
    search: str | None = None,
    from_date: datetime | None = None,
    to_date: datetime | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    skip = (page - 1) * size
    conditions: list[ColumnElement[bool]] = []

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
            exists(
                select(1)
                .select_from(User)
                .where(
                    User.id == AuditLog.user_id,
                    User.email.ilike(like, escape="\\"),
                )
                .correlate(AuditLog)
            )
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
        .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
        .offset(skip)
        .limit(size)
    )
    rows = (await db.execute(stmt)).all()
    items: list[dict] = []
    for log_row, email in rows:
        items.append(
            {
                "id": str(log_row.id),
                "timestamp": log_row.timestamp,
                "user_id": str(log_row.user_id) if log_row.user_id else None,
                "user_email": email,
                "action": log_row.action,
                "ip_address": log_row.ip_address,
                "details": log_row.details or {},
            }
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
    return PaginatedResponse(items=items, total=total, page=page, size=size, pages=pages)
