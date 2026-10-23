import csv
import io
import math
import secrets
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, Response, status
from pydantic import SecretStr
from sqlalchemy import (
    ColumnElement,
    and_,
    delete as sa_delete,
    func,
    or_,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from app.api.deps import extract_ip, get_db, require_admin
from app.core.audit import AuditLogger
from app.core.exceptions import BadRequestException, ConflictException, NotFoundException
from app.core.security import hash_password_async
from app.models.token import RefreshTokenFamily
from app.models.user import User, role_name
from app.schemas.common import MAX_PAGE_SIZE, PaginatedResponse, RevokedSessionsResponse
from app.services.admin_invariants import (
    LastActiveAdminError,
    count_active_admins,
    ensure_active_admin_remains,
    lock_active_admin_set,
)
from app.services.refresh_sessions import revoke_refresh_families
from app.services.invitations import issue_invitation
from app.services.user_notifications import notify_invitation, notify_owner
from app.schemas.user import (
    SessionResponse,
    UserBulkRequest,
    UserBriefResponse,
    UserBulkResponse,
    UserCreate,
    UserInviteRequest,
    UserInviteResponse,
    UserResponse,
    UserRole,
    UserUpdate,
)

router = APIRouter(prefix="/users", tags=["Users"])

#: An export is a file an operator opens, not a report generator. The list itself
#: is paged; the cap keeps one request from materialising an installation's whole
#: user table, and a larger one is refused by name instead of truncated silently.
USER_EXPORT_MAX_ROWS = 10_000


def _user_list_conditions(
    *,
    search: str | None,
    role: UserRole | None,
    is_active: bool | None,
    signed_in: bool | None,
    requires_onboarding: bool | None,
    mfa_enrolled: bool | None,
    locked: bool | None,
) -> list[ColumnElement[bool]]:
    """The list and the export answer the same question, so they share the query.

    Kept in one function because two copies drift: an operator who filters the
    table and then exports it must get the file they were looking at, and the
    only way to make that true is for both to be built from the same clauses.
    """
    conditions: list[ColumnElement[bool]] = []
    if role is not None:
        conditions.append(User.role == role)
    if is_active is not None:
        conditions.append(User.is_active.is_(is_active))
    if signed_in is not None:
        conditions.append(
            User.last_login_at.is_not(None) if signed_in else User.last_login_at.is_(None)
        )
    if requires_onboarding is not None:
        onboarding = or_(
            User.must_change_password.is_(True), User.must_enrol_mfa.is_(True)
        )
        conditions.append(onboarding if requires_onboarding else ~onboarding)
    if mfa_enrolled is not None:
        conditions.append(
            User.totp_enabled_at.is_not(None) if mfa_enrolled else User.totp_enabled_at.is_(None)
        )
    if locked is not None:
        # A lockout is the pair "a deadline exists and it is in the future".
        # ``locked_until IS NOT NULL`` alone would keep reporting accounts whose
        # window has passed, which is exactly the state support cannot see.
        active_lock = and_(
            User.locked_until.is_not(None),
            User.locked_until > datetime.now(timezone.utc),
        )
        conditions.append(active_lock if locked else ~active_lock)
    if search:
        raw_search = search.strip()[:100]
        escaped = raw_search.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        like = f"%{escaped}%"
        # A NULL full_name simply never matches ILIKE. The previous
        # ``(User.full_name or "")`` operand was dead code: the attribute
        # object is always truthy, and it only confused type checkers.
        conditions.append(or_(User.email.ilike(like), User.full_name.ilike(like)))
    return conditions


async def _count_active_admins(db: AsyncSession, exclude_id: uuid.UUID | None = None) -> int:
    """The router's spelling of the shared active-admin predicate."""
    return await count_active_admins(db, exclude_id=exclude_id)


async def _ensure_active_admin_remains(
    db: AsyncSession,
    target: User,
    *,
    final_role: str | None = None,
    final_active: bool | None = None,
) -> None:
    """Refuse a change that would leave no active admin, as a 409.

    The rule itself lives in ``app/services/admin_invariants.py`` so the admin
    CLI applies the same one; the exception type is the only difference, and it
    is translated here rather than raised from the service.
    """
    try:
        await ensure_active_admin_remains(
            db, target, final_role=final_role, final_active=final_active
        )
    except LastActiveAdminError as exc:
        raise ConflictException(str(exc)) from exc


def _is_email_conflict(exc: IntegrityError) -> bool:
    """Whether a constraint failure is the ``users.email`` uniqueness rule.

    PostgreSQL names the constraint (``users_email_key``); SQLite, which the
    test and development runs use, names the column (``users.email``). Matching
    only the PostgreSQL spelling made a duplicate address on SQLite answer the
    generic "constraint violation" — the one case the caller can fix.
    """
    message = str(exc).lower()
    return (
        "users_email_key" in message
        or "users.email" in message
        or "duplicate" in message
    )


@router.get("/brief", response_model=list[UserBriefResponse])
async def list_users_brief(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Lightweight list of active users for alert-recipient checkboxes.

    Settings (admin-only UI) needs id/email/role only; the full listing
    endpoint stays unchanged for user management.
    """
    result = await db.execute(
        select(User.id, User.email, User.role, User.is_active)
        .where(User.is_active.is_(True))
        .order_by(User.email)
    )
    rows = result.all()
    await AuditLogger.emit_background(
        db,
        action="users.list",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={"brief": True, "results": len(rows)},
    )
    return [
        {"id": str(r.id), "email": r.email, "role": getattr(r.role, "value", r.role), "is_active": r.is_active}
        for r in rows
    ]


@router.get("", response_model=PaginatedResponse[UserResponse])
async def list_users(
    request: Request,
    search: str | None = None,
    role: UserRole | None = None,
    is_active: bool | None = None,
    # ``signed_in=false`` is the access-review question — accounts that exist but
    # have never completed a sign-in — and it is answered by the database rather
    # than by the page the client happens to be showing. NULL is the only value
    # that means "never": the column is written at sign-in, not at creation.
    signed_in: bool | None = None,
    # The three support views (U-3). Each is a property of the account at the
    # moment of the read, so the count and the page agree with the rows.
    requires_onboarding: bool | None = None,
    mfa_enrolled: bool | None = None,
    locked: bool | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=MAX_PAGE_SIZE),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    skip = (page - 1) * size
    conditions = _user_list_conditions(
        search=search,
        role=role,
        is_active=is_active,
        signed_in=signed_in,
        requires_onboarding=requires_onboarding,
        mfa_enrolled=mfa_enrolled,
        locked=locked,
    )
    # and_() with no arguments yields a true() clause, preserving the old
    # unfiltered behavior.
    where_clause = and_(*conditions)

    count_stmt = select(func.count(User.id)).select_from(User).where(where_clause)
    total = int((await db.execute(count_stmt)).scalar() or 0)

    stmt = select(User).where(where_clause).order_by(User.created_at.desc(), User.id.desc()).offset(skip).limit(size)
    items = list((await db.execute(stmt)).scalars().all())
    pages = math.ceil(total / size) if size > 0 else 0

    await AuditLogger.emit_background(
        db,
        action="users.list",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={
            "search_used": bool(search),
            "role": role_name(role) if role else None,
            "is_active": is_active,
            "signed_in": signed_in,
            "requires_onboarding": requires_onboarding,
            "mfa_enrolled": mfa_enrolled,
            "locked": locked,
            "page": page,
            "size": size,
            "results": total,
        },
    )
    return PaginatedResponse(items=items, total=total, page=page, size=size, pages=pages)


@router.get("/export")
async def export_users(
    request: Request,
    search: str | None = None,
    role: UserRole | None = None,
    is_active: bool | None = None,
    signed_in: bool | None = None,
    requires_onboarding: bool | None = None,
    mfa_enrolled: bool | None = None,
    locked: bool | None = None,
    format: Literal["csv", "json"] = Query("csv"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """The user list behind the current filter, as a file for access review (U-1).

    The columns are the facts a quarterly review asks for — role, activity,
    whether a second factor exists, when the account last signed in, and which
    onboarding step it still owes. They are deliberately *not* a dump of the
    model: nothing here is a credential, a hash, a TOTP secret or a recovery
    code, and no future column can arrive in this file without being named here.

    Declared before ``/{user_id}`` so the literal path wins the match; otherwise
    "export" is parsed as a UUID and the route answers 422.
    """
    conditions = _user_list_conditions(
        search=search,
        role=role,
        is_active=is_active,
        signed_in=signed_in,
        requires_onboarding=requires_onboarding,
        mfa_enrolled=mfa_enrolled,
        locked=locked,
    )
    where_clause = and_(*conditions)
    total = int(
        (
            await db.execute(
                select(func.count(User.id)).select_from(User).where(where_clause)
            )
        ).scalar()
        or 0
    )
    if total > USER_EXPORT_MAX_ROWS:
        raise BadRequestException(
            f"This filter matches {total} accounts; an export carries at most "
            f"{USER_EXPORT_MAX_ROWS}. Narrow the filter and export in parts."
        )
    items = list(
        (
            await db.execute(
                select(User)
                .where(where_clause)
                .order_by(User.created_at.desc(), User.id.desc())
                .limit(USER_EXPORT_MAX_ROWS)
            )
        ).scalars().all()
    )
    await AuditLogger.emit_background(
        db,
        action="users.export",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={
            "search_used": bool(search),
            "role": role_name(role) if role else None,
            "is_active": is_active,
            "signed_in": signed_in,
            "requires_onboarding": requires_onboarding,
            "mfa_enrolled": mfa_enrolled,
            "locked": locked,
            "format": format,
            "rows": total,
        },
    )

    def _row(user: User) -> dict:
        return {
            "email": user.email,
            "full_name": user.full_name,
            "role": role_name(user.role),
            "is_active": user.is_active,
            "mfa_enrolled": user.totp_enabled_at is not None,
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
            "must_change_password": bool(user.must_change_password),
            "must_enrol_mfa": bool(user.must_enrol_mfa),
            "locked_until": user.locked_until.isoformat() if user.locked_until else None,
            "rate_limit_minutes": user.rate_limit_minutes,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        }

    rows = [_row(user) for user in items]
    if format == "json":
        return {"items": rows, "total": total}

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "email",
            "full_name",
            "role",
            "is_active",
            "mfa_enrolled",
            "last_login_at",
            "must_change_password",
            "must_enrol_mfa",
            "locked_until",
            "rate_limit_minutes",
            "created_at",
        ]
    )
    for row in rows:
        writer.writerow(["" if value is None else value for value in row.values()])
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="users.csv"'},
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise NotFoundException("User not found")
    await AuditLogger.emit_background(
        db,
        action="users.view",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={"target_user_id": str(user_id), "target_email": user.email},
    )
    return user


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: Request,
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    new_user = User(
        email=payload.email.lower().strip(),
        role=payload.role,
        is_active=True,
        full_name=(payload.full_name.strip() if payload.full_name else None),
        rate_limit_minutes=payload.rate_limit_minutes,
        password_hash=await hash_password_async(payload.password.get_secret_value()),
        # The administrator typed this password, so it is shared from the moment
        # it exists — it is in a chat message, a ticket or a shell history. The
        # account holder replaces it at first sign-in; see app/api/deps.py for
        # what that gate refuses in the meantime.
        must_change_password=True,
    )
    try:
        if role_name(new_user.role) == "admin":
            # Entering the active-admin set takes the same lock as leaving it:
            # otherwise two writers can each count the other as the survivor.
            await lock_active_admin_set(db)
        db.add(new_user)
        await db.flush()
        await AuditLogger.emit(
            db,
            action="user.created",
            ip_address=extract_ip(request),
            user_id=current_user.id,
            details={
                "target_user_id": str(new_user.id),
                "target_email": new_user.email,
                "role": role_name(new_user.role),
                "rate_limit_minutes": new_user.rate_limit_minutes,
                "created_by": str(current_user.id),
                "onboarding_required": ["password"],
            },
            require_persistence=True,
            commit=False,
        )
        await db.commit()
        await db.refresh(new_user)
    except IntegrityError as exc:
        await db.rollback()
        if _is_email_conflict(exc):
            raise ConflictException("A user with this email already exists") from exc
        raise ConflictException("Could not create user due to constraint violation") from exc
    except Exception:
        await db.rollback()
        raise

    return new_user


@router.post("/invite", response_model=UserInviteResponse, status_code=status.HTTP_201_CREATED)
async def invite_user(
    request: Request,
    payload: UserInviteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Create an account whose password only its owner will ever know (U-7).

    No temporary password is generated for the administrator to pass on. The
    account starts with an unguessable random password (so nothing can sign in
    before acceptance) and a single-use invitation token; the owner chooses the
    real password from the link. The plaintext token appears in this response
    only — the database keeps its digest — so the UI can offer it for copying
    when mail is not configured or the administrator prefers another channel.
    """
    email = payload.email.lower().strip()
    existing = (
        await db.execute(select(User.id).where(User.email == email).limit(1))
    ).scalar_one_or_none()
    if existing:
        raise ConflictException("A user with this email already exists")

    new_user = User(
        email=email,
        role=payload.role,
        is_active=True,
        full_name=(payload.full_name.strip() if payload.full_name else None),
        rate_limit_minutes=payload.rate_limit_minutes,
        # A real hash of a value nobody holds, not a NULL: the column is part of
        # the sign-in path, and a nullable password would be a second "no
        # credential" state for every caller to remember.
        password_hash=await hash_password_async(secrets.token_urlsafe(32)),
        must_change_password=False,
    )
    try:
        if role_name(new_user.role) == "admin":
            await lock_active_admin_set(db)
        db.add(new_user)
        await db.flush()
        token, expires_at = issue_invitation(new_user)
        await AuditLogger.emit(
            db,
            action="user.invited",
            ip_address=extract_ip(request),
            user_id=current_user.id,
            details={
                "target_user_id": str(new_user.id),
                "target_email": new_user.email,
                "role": role_name(new_user.role),
                "expires_at": expires_at.isoformat(),
                "method": "api_invite",
            },
            require_persistence=True,
            commit=False,
        )
        await db.commit()
        await db.refresh(new_user)
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictException("A user with this email already exists") from exc
    except Exception:
        await db.rollback()
        raise

    email_scheduled = await notify_invitation(
        db,
        target_email=new_user.email,
        token=token,
        expires_at=expires_at,
        actor_email=current_user.email,
        ip_address=extract_ip(request),
    )
    return UserInviteResponse(
        user=UserResponse.model_validate(new_user),
        invitation_token=token,
        expires_at=expires_at,
        email_scheduled=email_scheduled,
    )


@router.post("/{user_id}/invitation", response_model=UserInviteResponse)
async def reissue_invitation(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Replace a lost or expired invitation with a new link (U-7).

    The old link stops working the moment the digest is replaced. This is also
    the recovery path for an account that never accepted: no password has to be
    invented and handed over.
    """
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise NotFoundException("User not found")

    token, expires_at = issue_invitation(user)
    await AuditLogger.emit(
        db,
        action="user.invited",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={
            "target_user_id": str(user_id),
            "target_email": user.email,
            "expires_at": expires_at.isoformat(),
            "method": "api_reinvite",
            "reissued": True,
        },
        require_persistence=True,
        commit=False,
    )
    try:
        await db.commit()
        await db.refresh(user)
    except Exception:
        await db.rollback()
        raise

    email_scheduled = await notify_invitation(
        db,
        target_email=user.email,
        token=token,
        expires_at=expires_at,
        actor_email=current_user.email,
        ip_address=extract_ip(request),
    )
    return UserInviteResponse(
        user=UserResponse.model_validate(user),
        invitation_token=token,
        expires_at=expires_at,
        email_scheduled=email_scheduled,
    )


@router.post("/bulk", response_model=UserBulkResponse)
async def bulk_update_users(
    request: Request,
    payload: UserBulkRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """One activation change over a selection, in one transaction and one row (U-5).

    Deactivation is what an off-boarding is: the same change N times, with the
    same session revocation and the same guard against removing the last active
    administrator. Doing it one dialog at a time made the operation slow and the
    trail a run of near-identical rows. The batch still fails as a batch — a
    selection that would remove the last active administrator, or that names the
    caller, is refused before anything is written — so "partly applied" is not
    a state an operator has to reason about.
    """
    unique_ids = list(dict.fromkeys(payload.user_ids))
    if str(current_user.id) in {str(value) for value in unique_ids}:
        raise ConflictException(
            "You cannot change your own activation in a bulk action; use the account menu."
        )

    users = list(
        (
            await db.execute(
                select(User).where(User.id.in_(unique_ids)).execution_options(
                    populate_existing=True
                )
            )
        ).scalars().all()
    )
    found = {str(user.id) for user in users}
    missing = sorted({str(value) for value in unique_ids} - found)
    if missing:
        raise BadRequestException(
            f"Unknown user ids: {', '.join(missing[:5])}"
            + ("…" if len(missing) > 5 else "")
        )

    deactivating = payload.operation == "deactivate"
    if deactivating:
        await lock_active_admin_set(db)
        active_admins = set(
            (
                await db.execute(
                    select(User.id).where(
                        User.role == "admin", User.is_active.is_(True)
                    )
                )
            ).scalars().all()
        )
        remaining = active_admins - {user.id for user in users}
        if not remaining:
            raise ConflictException(
                "This selection would leave no active administrator."
            )

    desired_active = not deactivating
    changed_users: list[User] = []
    for user in users:
        if user.is_active == desired_active:
            # Already in the requested state: reported as skipped, not written,
            # so the count answers "what did this action change".
            continue
        user.is_active = desired_active
        # A lockout belongs to signing in, not to being active, so both
        # directions clear it: a revived account must not come back with the
        # counters it collected while it was off (the single-account route
        # clears them for the same reason), and a deactivated one has no window
        # left to wait out.
        user.failed_login_attempts = 0
        user.locked_until = None
        changed_users.append(user)

    revoked = 0
    if deactivating and changed_users:
        for user in changed_users:
            revoked += await revoke_refresh_families(
                db, user.id, reason="bulk_deactivate"
            )

    await AuditLogger.emit(
        db,
        action="users.bulk",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={
            "method": "api_bulk",
            "operation": payload.operation,
            "target_user_ids": [str(user.id) for user in users],
            "target_emails": [user.email for user in users],
            "changed": len(changed_users),
            "skipped": len(users) - len(changed_users),
            "refresh_families_revoked": revoked,
        },
        require_persistence=True,
        commit=False,
    )
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictException("Could not apply the bulk action") from exc
    except Exception:
        await db.rollback()
        raise

    return UserBulkResponse(
        operation=payload.operation,
        changed=len(changed_users),
        skipped=len(users) - len(changed_users),
        revoked_sessions=revoked,
    )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    request: Request,
    user_id: uuid.UUID,
    payload: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise NotFoundException("User not found")

    update_fields = payload.model_dump(exclude_unset=True)
    details: dict = {"target_user_id": str(user_id), "target_email": user.email}
    changed: list[str] = []
    changes: dict[str, dict[str, object]] = {}
    old_value: object

    def record_change(field: str, old: object, new: object) -> None:
        if old != new:
            changed.append(field)
            changes[field] = {"from": old, "to": new}

    if "full_name" in update_fields:
        val = update_fields["full_name"]
        stripped = val.strip() if isinstance(val, str) else val
        old_value = user.full_name
        user.full_name = stripped or None
        record_change("full_name", old_value, user.full_name)
    if "email" in update_fields and update_fields["email"]:
        candidate = update_fields["email"].lower().strip()
        existing = (
            await db.execute(select(User.id).where(User.email == candidate, User.id != user_id).limit(1))
        ).scalar_one_or_none()
        if existing:
            raise ConflictException("A user with this email already exists")
        old_value = user.email
        user.email = candidate
        record_change("email", old_value, user.email)
    if "rate_limit_minutes" in update_fields and update_fields["rate_limit_minutes"] is not None:
        new_limit = int(update_fields["rate_limit_minutes"])
        if new_limit != user.rate_limit_minutes:
            old_value = user.rate_limit_minutes
            user.rate_limit_minutes = new_limit
            record_change("rate_limit_minutes", old_value, new_limit)
    if "role" in update_fields and update_fields["role"]:
        await _ensure_active_admin_remains(
            db, user, final_role=role_name(update_fields["role"]), final_active=user.is_active
        )
        old_value = role_name(user.role)
        user.role = update_fields["role"]
        record_change("role", old_value, role_name(user.role))

    password_reset = False
    # One notice per operation, scheduled after the commit. The list is built here
    # because the facts that decide it (which field changed, to what) are only
    # known before the row is written back (RWI-15).
    notifications: list[str] = []
    revoked_families = 0
    if "new_password" in update_fields and isinstance(payload.new_password, SecretStr):
        new_pw = payload.new_password.get_secret_value()
        if new_pw:
            user.password_hash = await hash_password_async(new_pw)
            # A support-triggered reset must also clear brute-force lockout state,
            # otherwise the account stays locked and the new password is useless.
            user.failed_login_attempts = 0
            user.locked_until = None
            # The reset is only half a recovery if the password the administrator
            # just chose stays valid indefinitely: they know it, and so does
            # anything that recorded the request. The account holder replaces it
            # at the next sign-in.
            user.must_change_password = True
            password_reset = True

    active_changed = False
    if "is_active" in update_fields and update_fields["is_active"] is not None:
        new_active = bool(update_fields["is_active"])
        if new_active != user.is_active:
            if str(user_id) == str(current_user.id) and new_active is False:
                raise ConflictException("You cannot deactivate your own account")
            await _ensure_active_admin_remains(
                db, user, final_role=role_name(user.role), final_active=new_active
            )
            old_value = user.is_active
            user.is_active = new_active
            record_change("is_active", old_value, new_active)
            if new_active:
                # Reviving an account must not restore stale lock state.
                user.failed_login_attempts = 0
                user.locked_until = None
            active_changed = True

    if password_reset:
        notifications.append("password_reset")
    if active_changed and not user.is_active:
        # Reactivation is not on the list: the owner has just been let back in by
        # the administrator they were already talking to, so the mail adds nothing.
        notifications.append("deactivated")

    try:
        if password_reset:
            revoked_families = await revoke_refresh_families(db, user.id, reason="password_reset")
        if active_changed and not user.is_active:
            revoked_families += await revoke_refresh_families(db, user.id, reason="user_deactivated")

        audit_events: list[tuple[str, dict]] = []
        if password_reset:
            audit_events.append((
                "user.password_reset",
                {
                    "target_user_id": str(user_id),
                    "target_email": user.email,
                    "refresh_families_revoked": revoked_families,
                    "onboarding_required": ["password"],
                },
            ))
        if active_changed:
            lock_action = "user.locked" if not user.is_active else "user.unlocked"
            # ``method`` names the path that changed the state. Every writer of
            # these two actions carries one — the API here, the admin CLI under
            # its own method — so a SIEM rule keyed on `details.method` matches
            # whatever route an operator actually used (RWI-04).
            audit_events.append((
                lock_action,
                {
                    "target_user_id": str(user_id),
                    "target_email": user.email,
                    "method": "api_update",
                },
            ))
        if changed or password_reset:
            details["changed_fields"] = changed
            details["changes"] = changes
            audit_events.append(("user.updated", details))
        for action, event_details in audit_events:
            await AuditLogger.emit(
                db,
                action=action,
                ip_address=extract_ip(request),
                user_id=current_user.id,
                details=event_details,
                require_persistence=True,
                commit=False,
            )
        await db.commit()
        await db.refresh(user)
    except IntegrityError as exc:
        await db.rollback()
        if _is_email_conflict(exc):
            raise ConflictException("A user with this email already exists") from exc
        raise ConflictException("Could not update user") from exc
    except Exception:
        await db.rollback()
        raise

    # After the commit, never inside it: a mail that cannot be scheduled must not
    # undo a reset that succeeded (D11).
    for notification in notifications:
        await notify_owner(
            db,
            event=notification,
            target_email=user.email,
            target_user_id=str(user_id),
            actor_email=current_user.email,
            ip_address=extract_ip(request),
        )

    return user


@router.post("/{user_id}/unlock", response_model=UserResponse)
async def unlock_user(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Release a brute-force lockout, and only that.

    Refusing to guess is what makes the sign-in lockout work, so an operator needs
    a way to undo it for the real person behind it — someone who mistyped a
    password five times at 9 a.m. does not have to wait out the window, and does
    not need a support password reset either. Until this route existed the only
    ways out were a password reset (which also clears the counters) or direct SQL.

    What it does *not* touch is the point of it being a separate operation:

    * the password, the role and the active flag are unchanged — a lockout is not
      a credential problem, and the previous shape of ``unlock`` in the admin CLI
      (which reactivated the account) is why that is spelled out;
    * the second factor and its own counter are unchanged. ``user.mfa.reset`` is
      the route for that, and releasing an MFA lockout here would hand extra
      guesses at the code to whoever already has the password (D8);
    * sessions are not touched: no cookie was revoked by the lockout, so none is
      restored here.
    """
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise NotFoundException("User not found")

    now = datetime.now(timezone.utc)
    locked_until = user.locked_until
    if locked_until is not None and locked_until.tzinfo is None:
        # SQLite hands back a naive value for an aware column; comparing the two
        # directly raises. The stored instant is UTC either way.
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    still_locked = locked_until is not None and locked_until > now
    attempts = int(user.failed_login_attempts or 0)
    if not still_locked and attempts == 0:
        raise ConflictException("This account is not locked")

    user.failed_login_attempts = 0
    user.locked_until = None
    try:
        await AuditLogger.emit(
            db,
            action="user.unlocked",
            ip_address=extract_ip(request),
            user_id=current_user.id,
            details={
                "target_user_id": str(user_id),
                "target_email": user.email,
                "method": "brute_force_unlock",
                "failed_login_attempts_cleared": attempts,
                "locked_until_was": locked_until.isoformat() if locked_until else None,
                "mfa_lockout_untouched": True,
            },
            require_persistence=True,
            commit=False,
        )
        await db.commit()
        await db.refresh(user)
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictException("Could not unlock the account") from exc
    except Exception:
        await db.rollback()
        raise

    return user


@router.get("/{user_id}/sessions", response_model=list[SessionResponse])
async def list_user_sessions(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """The sessions a user account can still be used through (U-2).

    Same shape as the account's own ``GET /auth/sessions`` — an id that only
    addresses a row, when it was created and when it was last refreshed — and
    never a token. Administrators need it for the case deactivation does not
    cover: an account that must stay active while one lost phone is signed out.
    """
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise NotFoundException("User not found")
    rows = (
        await db.execute(
            select(RefreshTokenFamily)
            .where(
                RefreshTokenFamily.user_id == user_id,
                RefreshTokenFamily.revoked.is_(False),
            )
            .order_by(
                RefreshTokenFamily.last_issued_at.desc(),
                RefreshTokenFamily.created_at.desc(),
            )
        )
    ).scalars().all()
    # The same read `GET /users/{id}` records as `users.view`: the session list
    # answers which devices the account can still be used through, which is the
    # administrator read most worth being able to explain later. `view` names
    # which of the account's surfaces was read, the way `method` names the path
    # that changed a state.
    await AuditLogger.emit_background(
        db,
        action="users.view",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={
            "target_user_id": str(user_id),
            "target_email": user.email,
            "view": "sessions",
            "results": len(rows),
        },
    )
    return [
        SessionResponse(
            id=row.family_id,
            created_at=row.created_at,
            last_used_at=row.last_issued_at,
            # The caller is an administrator looking at somebody else's account;
            # "this browser" is a fact about the account holder, not about them.
            current=False,
        )
        for row in rows
    ]


@router.delete(
    "/{user_id}/sessions",
    status_code=status.HTTP_200_OK,
    response_model=RevokedSessionsResponse,
)
async def revoke_user_sessions(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Sign every session of another account out, and record the decision (U-2).

    Refused for the caller's own account: an administrator who wants to end their
    own sessions has ``POST /auth/sessions/revoke-others``, which keeps the
    browser they are using. Routine self-revocation through the admin surface
    would also make "an administrator ended someone's sessions" ambiguous in the
    trail.

    Deactivation already revokes everything; this exists for the account that has
    to stay active (a shared mailbox, a colleague on leave) while one device is
    lost.
    """
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise NotFoundException("User not found")
    if str(user_id) == str(current_user.id):
        raise ConflictException(
            "Use the sessions page to end your own sessions: it keeps the browser you are using."
        )

    revoked = await revoke_refresh_families(db, user.id, reason="admin_revoked")
    await AuditLogger.emit(
        db,
        action="user.sessions.revoked",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={
            "target_user_id": str(user_id),
            "target_email": user.email,
            "revoked_count": revoked,
            "method": "admin_revoke",
        },
        require_persistence=True,
        commit=False,
    )
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    return RevokedSessionsResponse(revoked=revoked)


@router.post("/{user_id}/mfa/reset", response_model=UserResponse)
async def reset_user_mfa(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Clear another user's TOTP factor — the account-recovery path.

    An administrator needs this because the alternative is an operator with a
    lost phone being permanently locked out. Two limits keep it from becoming a
    bypass:

    * it never applies to the caller's own account. A session that can remove its
      own second factor is not a second factor, and the case this would otherwise
      cover — an administrator who lost their own device — is served by
      ``python -m scripts.manage_admin mfa-off``, which requires access to the
      deployment rather than to a browser;
    * it is audited as its own action (``user.mfa.reset``) rather than folded into
      ``user.updated``, because removing a factor from an account you do not own
      is exactly the action that has to be findable later.
    """
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise NotFoundException("User not found")
    if str(user_id) == str(current_user.id):
        raise ConflictException(
            "Use `python -m scripts.manage_admin mfa-off -e <your email>` to clear your own "
            "second factor: recovering an account from a live session would defeat the factor."
        )
    if user.totp_enabled_at is None and not user.totp_secret:
        raise ConflictException("No second factor is configured for this account")

    was_enabled = user.totp_enabled_at is not None
    user.totp_secret = None
    user.totp_enabled_at = None
    user.totp_last_used_step = None
    user.mfa_recovery_codes = None
    user.mfa_failed_attempts = 0
    user.mfa_locked_until = None
    # Recovery must not be a downgrade. Without this flag, clearing a factor for
    # an operator who lost their phone would leave the account permanently
    # password-only — the exact outcome the request was meant to undo. The next
    # sign-in asks for a new device before the rest of the platform opens.
    user.must_enrol_mfa = True
    try:
        revoked_families = await revoke_refresh_families(
            db, user.id, reason="mfa_reset"
        )
        await AuditLogger.emit(
            db,
            action="user.mfa.reset",
            ip_address=extract_ip(request),
            user_id=current_user.id,
            details={
                "target_user_id": str(user_id),
                "target_email": user.email,
                "was_enabled": was_enabled,
                "refresh_families_revoked": revoked_families,
                "method": "admin_reset",
                "onboarding_required": ["mfa"],
            },
            require_persistence=True,
            commit=False,
        )
        await db.commit()
        await db.refresh(user)
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictException("Could not reset the second factor") from exc
    except Exception:
        await db.rollback()
        raise

    await notify_owner(
        db,
        event="mfa_reset",
        target_email=user.email,
        target_user_id=str(user_id),
        actor_email=current_user.email,
        ip_address=extract_ip(request),
    )
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Permanently purge a user account (real DELETE, not deactivation).

    - The schema owns what survives: ``User.reports`` is mapped with
      ``passive_deletes``, so the database's ``ON DELETE SET NULL`` keeps the
      reports and only clears their ``created_by``. The deletes below are issued
      explicitly rather than left to an ORM cascade, so nothing the model does can
      turn a purge into a report wipe.
    - The email address is freed, so the account can be re-created later.
    - Refresh-token families are removed and audit rows are preserved.
    - For a reversible off-boarding, use PUT ``is_active=false`` instead — that
      keeps the row and lets the account be reactivated. It is the only route
      that changes activation: the ``toggle-active`` shorthand was removed so one
      operation has one path and one audit shape (RWI-04).
    """
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise NotFoundException("User not found")
    if str(user_id) == str(current_user.id):
        raise ConflictException("You cannot delete your own account")

    await _ensure_active_admin_remains(
        db,
        user,
        final_role="deleted",
        final_active=False,
    )

    target_email = user.email
    try:
        await db.execute(sa_delete(RefreshTokenFamily).where(RefreshTokenFamily.user_id == user.id))
        await db.execute(sa_delete(User).where(User.id == user.id))
        await AuditLogger.emit(
            db,
            action="user.deleted",
            ip_address=extract_ip(request),
            user_id=current_user.id,
            details={
                "target_user_id": str(user_id),
                "target_email": target_email,
                "method": "purge",
            },
            require_persistence=True,
            commit=False,
        )
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictException("Could not delete user: account is referenced by other records") from exc
    except Exception:
        await db.rollback()
        raise

    # The row is gone, so the address comes from the copy taken before the delete.
    # Telling someone their account was removed is not optional merely because the
    # record that would have told us their address no longer exists.
    await notify_owner(
        db,
        event="deleted",
        target_email=target_email,
        target_user_id=str(user_id),
        actor_email=current_user.email,
        ip_address=extract_ip(request),
    )
    return None
