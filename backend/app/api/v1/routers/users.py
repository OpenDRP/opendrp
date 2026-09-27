import math
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, status
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
from app.core.exceptions import ConflictException, NotFoundException
from app.core.security import hash_password
from app.models.token import RefreshTokenFamily
from app.models.user import User, role_name
from app.schemas.common import PaginatedResponse
from app.services.refresh_sessions import revoke_refresh_families
from app.schemas.user import (
    ToggleActiveResponse,
    UserCreate,
    UserResponse,
    UserRole,
    UserUpdate,
)

router = APIRouter(prefix="/users", tags=["Users"])


async def _count_active_admins(db: AsyncSession, exclude_id: uuid.UUID | None = None) -> int:
    stmt = select(func.count(User.id)).where(User.role == "admin", User.is_active.is_(True))
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    result = await db.execute(stmt)
    return int(result.scalar_one() or 0)


async def _ensure_active_admin_remains(
    db: AsyncSession,
    target: User,
    *,
    final_role: str | None = None,
    final_active: bool | None = None,
) -> None:
    """Lock the admin set before changing a user's effective admin status."""
    role = getattr(target.role, "value", target.role)
    resulting_role = final_role if final_role is not None else str(role)
    resulting_active = target.is_active if final_active is None else final_active
    is_losing_admin = role == "admin" and target.is_active and (
        resulting_role != "admin" or not resulting_active
    )
    if not is_losing_admin:
        return
    # PostgreSQL serializes competing demotion/deactivation operations here.
    # SQLite ignores FOR UPDATE, but the invariant remains covered by the
    # application transaction in the supported single-process test/development DB.
    await db.execute(
        select(User.id)
        .where(User.role == "admin", User.is_active.is_(True))
        .with_for_update()
    )
    if await _count_active_admins(db, exclude_id=target.id) < 1:
        raise ConflictException("Cannot remove the last active admin")


@router.get("/brief", response_model=list[dict])
async def list_users_brief(
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
        ip_address="internal:users-brief",
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
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    skip = (page - 1) * size
    conditions: list[ColumnElement[bool]] = []
    if role is not None:
        conditions.append(User.role == role)
    if is_active is not None:
        conditions.append(User.is_active.is_(is_active))
    if search:
        raw_search = search.strip()[:100]
        escaped = raw_search.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        like = f"%{escaped}%"
        # A NULL full_name simply never matches ILIKE. The previous
        # ``(User.full_name or "")`` operand was dead code: the attribute
        # object is always truthy, and it only confused type checkers.
        conditions.append(or_(User.email.ilike(like), User.full_name.ilike(like)))
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
            "page": page,
            "size": size,
            "results": total,
        },
    )
    return PaginatedResponse(items=items, total=total, page=page, size=size, pages=pages)


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
        password_hash=hash_password(payload.password.get_secret_value()),
        # The administrator typed this password, so it is shared from the moment
        # it exists — it is in a chat message, a ticket or a shell history. The
        # account holder replaces it at first sign-in; see app/api/deps.py for
        # what that gate refuses in the meantime.
        must_change_password=True,
    )
    db.add(new_user)
    try:
        await db.commit()
        await db.refresh(new_user)
    except IntegrityError as exc:
        await db.rollback()
        if "users_email_key" in str(exc) or "duplicate" in str(exc).lower():
            raise ConflictException("A user with this email already exists") from exc
        raise ConflictException("Could not create user due to constraint violation") from exc

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
    )
    return new_user


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

    if "full_name" in update_fields:
        val = update_fields["full_name"]
        stripped = val.strip() if isinstance(val, str) else val
        user.full_name = stripped or None
        changed.append("full_name")
    if "email" in update_fields and update_fields["email"]:
        candidate = update_fields["email"].lower().strip()
        existing = (
            await db.execute(select(User.id).where(User.email == candidate, User.id != user_id).limit(1))
        ).scalar_one_or_none()
        if existing:
            raise ConflictException("A user with this email already exists")
        user.email = candidate
        changed.append("email")
    if "rate_limit_minutes" in update_fields and update_fields["rate_limit_minutes"] is not None:
        new_limit = int(update_fields["rate_limit_minutes"])
        if new_limit != user.rate_limit_minutes:
            user.rate_limit_minutes = new_limit
            changed.append("rate_limit_minutes")
            details["rate_limit_minutes"] = new_limit
    if "role" in update_fields and update_fields["role"]:
        await _ensure_active_admin_remains(
            db, user, final_role=str(update_fields["role"]), final_active=user.is_active
        )
        user.role = update_fields["role"]
        changed.append("role")

    password_reset = False
    revoked_families = 0
    if "new_password" in update_fields and isinstance(payload.new_password, SecretStr):
        new_pw = payload.new_password.get_secret_value()
        if new_pw:
            user.password_hash = hash_password(new_pw)
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
                db, user, final_role=str(getattr(user.role, "value", user.role)), final_active=new_active
            )
            user.is_active = new_active
            if new_active:
                # Reviving an account must not restore stale lock state.
                user.failed_login_attempts = 0
                user.locked_until = None
            active_changed = True
            changed.append("is_active")

    try:
        if password_reset:
            revoked_families = await revoke_refresh_families(db, user.id, reason="password_reset")
        if active_changed and not user.is_active:
            revoked_families += await revoke_refresh_families(db, user.id, reason="user_deactivated")
        await db.commit()
        await db.refresh(user)
    except IntegrityError as exc:
        await db.rollback()
        if "users_email_key" in str(exc):
            raise ConflictException("A user with this email already exists") from exc
        raise ConflictException("Could not update user") from exc

    if changed or password_reset:
        details["changed_fields"] = changed
        if password_reset:
            details["password_reset"] = True
            details["refresh_families_revoked"] = revoked_families
            await AuditLogger.emit(
                db,
                action="user.password_reset",
                ip_address=extract_ip(request),
                user_id=current_user.id,
                details={
                    "target_user_id": str(user_id),
                    "target_email": user.email,
                    "refresh_families_revoked": revoked_families,
                    "onboarding_required": ["password"],
                },
            )
        if active_changed:
            lock_action = "user.locked" if not user.is_active else "user.unlocked"
            await AuditLogger.emit(
                db,
                action=lock_action,
                ip_address=extract_ip(request),
                user_id=current_user.id,
                details={"target_user_id": str(user_id), "target_email": user.email},
            )
        await AuditLogger.emit(
            db,
            action="user.updated",
            ip_address=extract_ip(request),
            user_id=current_user.id,
            details=details,
        )
    return user


@router.patch("/{user_id}/toggle-active", response_model=ToggleActiveResponse)
async def toggle_active(
    request: Request,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise NotFoundException("User not found")
    if str(user_id) == str(current_user.id):
        raise ConflictException("You cannot toggle your own account")

    new_active = not user.is_active
    await _ensure_active_admin_remains(
        db, user, final_role=str(getattr(user.role, "value", user.role)), final_active=new_active
    )

    user.is_active = new_active
    if not new_active:
        await revoke_refresh_families(db, user.id, reason="user_deactivated")
    if new_active:
        user.failed_login_attempts = 0
        user.locked_until = None
    await db.commit()
    await db.refresh(user)

    action_str = "user.locked" if not new_active else "user.unlocked"
    label: Literal["locked", "unlocked"] = "locked" if not new_active else "unlocked"
    await AuditLogger.emit(
        db,
        action=action_str,
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={"target_user_id": str(user_id), "target_email": user.email, "method": "toggle-active"},
    )
    return ToggleActiveResponse(id=user.id, is_active=user.is_active, action=label)


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
    # Recovery must not be a downgrade. Without this flag, clearing a factor for
    # an operator who lost their phone would leave the account permanently
    # password-only — the exact outcome the request was meant to undo. The next
    # sign-in asks for a new device before the rest of the platform opens.
    user.must_enrol_mfa = True
    try:
        await db.commit()
        await db.refresh(user)
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictException("Could not reset the second factor") from exc

    await AuditLogger.emit(
        db,
        action="user.mfa.reset",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={
            "target_user_id": str(user_id),
            "target_email": user.email,
            "was_enabled": was_enabled,
            "method": "admin_reset",
            "onboarding_required": ["mfa"],
        },
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

    - Uses core-level DELETEs on purpose: ORM ``delete-orphan`` cascades on
      ``User.reports`` would silently destroy the user's reports, whereas the
      database-level ``ON DELETE SET NULL`` keeps reports/jobs and only clears
      their ``created_by``.
    - The email address is freed, so the account can be re-created later.
    - Refresh-token families are removed and audit rows are preserved.
    - For a reversible off-boarding, use PUT ``is_active=false`` / toggle-active
      instead — that keeps the row and lets the account be reactivated.
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
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise ConflictException("Could not delete user: account is referenced by other records") from exc

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
    )
    return None
