import asyncio
from datetime import datetime, timedelta, timezone
from typing import NoReturn, Optional
import uuid as _uuid_mod
import secrets

import structlog
from fastapi import APIRouter, Body, Cookie, Depends, Header, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import Response as FastAPIResponse
import qrcode
from qrcode.image.svg import SvgPathImage
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_current_user, get_db
from app.core import totp
from app.core.audit import AuditLogger
from app.core.config import settings
from app.core.crypto import decrypt_value, encrypt_value
from app.core.exceptions import ConflictException, UnauthorizedException
from app.core.rate_limit import RateLimiter
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.audit import AuditLog
from app.models.token import RefreshTokenFamily
from app.models.user import User, role_name
from app.schemas.user import (
    LoginRequest,
    MfaCodeRequest,
    MfaSetupRequest,
    MfaEnableResponse,
    MfaRecoveryCodesResponse,
    MfaSetupResponse,
    MfaStatusResponse,
    PasswordChangeRequest,
    SecurityActivityResponse,
    SessionResponse,
    RefreshTokenRequest,
    TokenResponse,
    UserResponse,
)
from app.services.refresh_sessions import revoke_refresh_families

router = APIRouter(prefix="/auth", tags=["Authentication"])

log = structlog.get_logger()

_LOCK_WINDOW = timedelta(minutes=15)
_MAX_DB_FAILED_ATTEMPTS = 5
_rate_limiter = RateLimiter(lock_window=_LOCK_WINDOW)
_REFRESH_COOKIE = "opendrp_refresh"
_CSRF_COOKIE = "opendrp_csrf"

# The single lockout answer, shared by the Redis limiter and the database
# counter so the two paths cannot be told apart. Status, detail and
# ``Retry-After`` must stay identical on both branches.
_LOCKOUT_DETAIL = "Too many failed login attempts. Please try again later."

_DUMMY_HASH: str | None = None
_MFA_MAX_FAILED_ATTEMPTS = 5
_MFA_LOCK_WINDOW = timedelta(minutes=15)
_RECOVERY_CODE_COUNT = 10


def _mfa_is_locked(user: User, now: datetime) -> bool:
    locked_until = user.mfa_locked_until
    if locked_until is None:
        return False
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > now


async def _record_mfa_failure(user: User, db: AsyncSession) -> None:
    user.mfa_failed_attempts = (user.mfa_failed_attempts or 0) + 1
    if user.mfa_failed_attempts >= _MFA_MAX_FAILED_ATTEMPTS:
        user.mfa_locked_until = datetime.now(timezone.utc) + _MFA_LOCK_WINDOW
    await db.commit()


async def _clear_mfa_failures(user: User, db: AsyncSession) -> None:
    user.mfa_failed_attempts = 0
    user.mfa_locked_until = None


def _new_recovery_codes() -> tuple[list[str], list[str]]:
    """Return fixed-length plaintext codes and their one-way bcrypt hashes."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    plain = ["".join(secrets.choice(alphabet) for _ in range(12)) for _ in range(_RECOVERY_CODE_COUNT)]
    return plain, [hash_password(code) for code in plain]


async def _consume_recovery_code(user: User, supplied: str) -> bool:
    hashes = list(user.mfa_recovery_codes or [])
    for index, stored_hash in enumerate(hashes):
        if verify_password(supplied.strip().upper(), stored_hash):
            hashes.pop(index)
            user.mfa_recovery_codes = hashes
            return True
    return False


def _dummy_password_hash() -> str:
    """A real bcrypt hash used only to keep failed-login timing uniform.

    Computed once per process. Nothing authenticates against it; it exists so
    that a login attempt for an unknown address still pays the cost of a bcrypt
    comparison, which would otherwise reveal whether the account exists.
    """
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(32))
    return _DUMMY_HASH


async def _record_failed_login(email_key: str, ip: str) -> None:
    """Best-effort Redis failure counters for brute-force protection.

    Awaited (not fire-and-forget) so failures are observable; never fatal to
    the login request itself.
    """
    try:
        await asyncio.gather(
            _rate_limiter.incr_failure(f"email:{email_key}"),
            _rate_limiter.incr_failure(f"ip:{ip}"),
        )
    except Exception as exc:
        log.warning("login_failure_counter_error", error=str(exc)[:200])


async def _clear_login_rate_limit(email_key: str, ip: str) -> None:
    try:
        await asyncio.gather(
            _rate_limiter.reset(f"email:{email_key}"),
            _rate_limiter.reset(f"ip:{ip}"),
        )
    except Exception as exc:
        log.warning("login_rate_limit_reset_error", error=str(exc)[:200])


async def _issue_session(
    response: Response, user: User, db: AsyncSession, now: datetime
) -> tuple[TokenResponse, str]:
    """Mint one browser session: access token, refresh cookie, CSRF cookie, family.

    Extracted from the sign-in handler because replacing a password issues a
    session too, and the two must be indistinguishable in what they hand out: a
    password change that left the caller holding a revoked refresh cookie, or no
    CSRF token, would be a session that breaks a minute later for reasons the
    operator cannot see.

    The audit event is deliberately *not* written here. Only the caller knows
    whether this session came from signing in or from changing a credential, and
    the two belong in the trail under their own names.

    Returns the response and the new family id, which the sign-in handler has
    always recorded alongside the login: it is what ties a session on the wire to
    the row whose revocation ends it.
    """
    data = {"sub": str(user.id), "role": str(user.role)}
    refresh_token, _, refresh_jti, refresh_fid = create_refresh_token(data)
    access_token, expires_in = create_access_token(
        {**data, "family_id": refresh_fid},
        expires_delta=timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    response.set_cookie(
        _REFRESH_COOKIE, refresh_token, httponly=True, secure=settings.AUTH_COOKIE_SECURE,
        samesite="lax", max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/api/v1/auth",
    )
    response.set_cookie(
        _CSRF_COOKIE, secrets.token_urlsafe(32), httponly=False, secure=settings.AUTH_COOKIE_SECURE,
        samesite="lax", max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60, path="/",
    )
    db.add(
        RefreshTokenFamily(
            id=_uuid_mod.uuid4(),
            family_id=_uuid_mod.UUID(refresh_fid),
            user_id=user.id,
            last_jti=refresh_jti,
            last_issued_at=now,
            revoked=False,
        )
    )
    try:
        await db.commit()
    except Exception:
        await db.rollback()

    return (
        TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=expires_in,
            user=UserResponse.model_validate(user),
        ),
        refresh_fid,
    )


def _user_is_db_locked(user: User, now: datetime) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    if locked_until.tzinfo is None:
        # The column is ``DateTime(timezone=True)``, but backends without a
        # real timezone type (SQLite) hand back naive values. Comparing those
        # with an aware ``now`` raises TypeError and would turn every login of a
        # locked account into a 500 instead of a refusal.
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > now


@router.post("/login", response_model=TokenResponse, status_code=200)
async def login(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    form_data: Optional[OAuth2PasswordRequestForm] = Depends(lambda: None),
    body: Optional[LoginRequest] = Body(default=None),
) -> TokenResponse:
    email: Optional[str] = None
    password: Optional[str] = None

    if form_data is not None:
        email = form_data.username
        password = form_data.password
    elif body is not None:
        email = body.email
        password = body.password.get_secret_value()

    ip = extract_ip(request)
    now = datetime.now(timezone.utc)

    if not email or not password:
        await AuditLogger.emit(
            db, action="auth.login.failure", ip_address=ip,
            details={"reason": "missing_credentials", "email_provided": bool(email)},
        )
        raise HTTPException(status_code=400, detail="Email and password are required")

    email_key = email.lower()

    email_locked = await _rate_limiter.is_locked(f"email:{email_key}")
    ip_locked = await _rate_limiter.is_locked(f"ip:{ip}")
    if email_locked or ip_locked:
        await AuditLogger.emit(
            db, action="auth.login.locked", ip_address=ip,
            details={"reason": "rate_limit_lock", "email": email_key,
                     "email_locked": email_locked, "ip_locked": ip_locked,
                     "lock_window_seconds": _rate_limiter.lock_window_seconds},
        )
        retry_after = _rate_limiter.lock_window_seconds
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_LOCKOUT_DETAIL,
            headers={"Retry-After": str(retry_after)},
        )

    result = await db.execute(select(User).where(User.email == email_key))
    user: User | None = result.scalar_one_or_none()

    if user is None:
        # Verify against a dummy hash and discard the result: skipping bcrypt
        # for unknown addresses would make them answer far faster than a wrong
        # password and expose which accounts exist.
        verify_password(password, _dummy_password_hash())
        password_ok = False
    else:
        password_ok = verify_password(password, user.password_hash)
    user_active = bool(user and user.is_active)
    user_db_locked = bool(user and _user_is_db_locked(user, now))

    if not password_ok or not user_active or user_db_locked:
        await _record_failed_login(email_key, ip)
        if user is not None:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= _MAX_DB_FAILED_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + _LOCK_WINDOW
        if user is None:
            details_reason = "invalid_credentials"
        elif user_db_locked:
            details_reason = "account_locked"
        elif not user.is_active:
            details_reason = "account_disabled"
        else:
            details_reason = "invalid_credentials"
        await AuditLogger.emit(
            db, action="auth.login.failure", ip_address=ip,
            user_id=user.id if user else None,
            details={"email": email_key, "reason": details_reason},
        )
        if user is not None:
            try:
                await db.commit()
            except Exception:
                await db.rollback()
        # A database-level lock must answer exactly like any other credential
        # failure. The Redis limiter above covers existing and unknown
        # addresses alike, so it can safely answer 429 — but it is fail-open,
        # and this counter only exists for accounts that do exist. Answering
        # "locked" here would therefore confirm the address whenever Redis is
        # unavailable (and in tests). The lock still denies access; only the
        # reason stays in the audit trail.
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Narrowing guard: the failure branch above always raises, so a valid,
    # active, unlocked account is guaranteed here. Explicit raise (not a bare
    # ``assert``) keeps the 401 semantics intact even under ``python -O``.
    if user is None:  # pragma: no cover - unreachable by construction
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # --- Second factor --------------------------------------------------------
    # Checked here, after the password and before any token is issued, and never
    # earlier: demanding a code before the password is verified would answer
    # "this account has MFA" to anyone who asks, which is a directory of
    # interesting accounts. The response below therefore tells an attacker with a
    # correct password only what they already know.
    if user.totp_enabled_at is not None:
        supplied_code = (
            body.totp_code.get_secret_value()
            if body is not None and body.totp_code is not None
            else ""
        )
        supplied_recovery = (
            body.recovery_code.get_secret_value()
            if body is not None and body.recovery_code is not None
            else ""
        )
        if _mfa_is_locked(user, now):
            raise HTTPException(status_code=429, detail="Too many MFA attempts. Please try again later.")
        secret = _decrypted_totp_secret(user)
        step = totp.verify(secret, supplied_code) if secret and supplied_code else None
        replayed = (
            step is not None
            and user.totp_last_used_step is not None
            and step <= user.totp_last_used_step
        )
        recovery_ok = bool(supplied_recovery) and await _consume_recovery_code(user, supplied_recovery)

        if (step is None or replayed) and not recovery_ok:
            if not supplied_code and not supplied_recovery:
                # A missing code is not a password failure, but it is still
                # throttled in the dedicated MFA budget so an attacker cannot use
                # empty requests to probe or exhaust the authentication path.
                await _record_mfa_failure(user, db)
                await AuditLogger.emit(
                    db, action="auth.mfa.failure", ip_address=ip, user_id=user.id,
                    details={"email": email_key, "reason": "code_missing"},
                )
                raise HTTPException(status_code=401, detail="MFA code required")

            # A wrong code does count. Six digits is a small space, so the same
            # counters that bound password guessing have to bound this too.
            await _record_failed_login(email_key, ip)
            await _record_mfa_failure(user, db)
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= _MAX_DB_FAILED_ATTEMPTS:
                user.locked_until = datetime.now(timezone.utc) + _LOCK_WINDOW
            await AuditLogger.emit(
                db, action="auth.mfa.failure", ip_address=ip, user_id=user.id,
                details={
                    "email": email_key,
                    "reason": "replay_detected" if replayed else "invalid_code",
                    "failed_login_attempts": user.failed_login_attempts,
                },
            )
            try:
                await db.commit()
            except Exception:
                await db.rollback()
            raise HTTPException(status_code=401, detail="Invalid MFA code")

        # Remember the step, not the code: TOTP accepts a ±1 step window for
        # clock skew, and a strictly increasing step is what makes a code
        # single-use inside it. The assignment is committed by the audit write
        # below, so a code cannot be replayed even if a later step fails.
        if not recovery_ok:
            user.totp_last_used_step = step
        await _clear_mfa_failures(user, db)
        await AuditLogger.emit(
            db, action="auth.mfa.success", ip_address=ip, user_id=user.id,
            details={"email": email_key, "step": step, "method": "recovery_code" if recovery_ok else "totp"},
        )

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    try:
        await db.commit()
    except Exception:
        await db.rollback()

    await _clear_login_rate_limit(email_key, ip)

    session, refresh_fid = await _issue_session(response, user, db, now)
    await AuditLogger.emit(
        db, action="auth.login.success", ip_address=ip, user_id=user.id,
        details={"email": email_key, "role": role_name(user.role),
                 "refresh_family_id": refresh_fid},
    )
    return session


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.post("/password", response_model=TokenResponse)
async def change_password(
    request: Request,
    response: Response,
    payload: PasswordChangeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> TokenResponse:
    """Replace the signed-in account's own password.

    This is the only way an account holder can set a password: an administrator
    can assign one, but only the owner can choose one. It exists because the
    alternative is worse in a way that is easy to miss — without it, a password
    chosen by somebody else stays valid forever, since the person who is supposed
    to change it has no endpoint to change it with.

    It also ends every other session (``password_change``), which is the point of
    changing a credential: whatever made the old one untrustworthy — a shared
    initial password, a support reset, a suspicion — is what the other sessions
    were authorised by. A caller who changes their password because they think it
    leaked gets the leak closed in the same request, and only the fresh session
    below survives.
    """
    ip = extract_ip(request)
    now = datetime.now(timezone.utc)

    if not verify_password(
        payload.current_password.get_secret_value(), current_user.password_hash
    ):
        await AuditLogger.emit(
            db, action="auth.password.change_failed", ip_address=ip,
            user_id=current_user.id,
            details={"email": current_user.email, "reason": "invalid_current_password"},
        )
        raise UnauthorizedException("Current password is incorrect")

    new_password = payload.new_password.get_secret_value()
    if verify_password(new_password, current_user.password_hash):
        # Rotating onto the same value is not a rotation; refusing it keeps the
        # promise the account was given ("a password only you know") honest
        # instead of proceeding and clearing the flag regardless.
        raise ConflictException(
            "The new password must be different from the current one"
        )

    was_required = current_user.must_change_password
    current_user.password_hash = hash_password(new_password)
    current_user.must_change_password = False
    # A password change is also the moment to clear a stale lockout: the account
    # just proved it knows the current credential, so the counters that exist to
    # bound guessing have nothing left to protect.
    current_user.failed_login_attempts = 0
    current_user.locked_until = None

    revoked = await revoke_refresh_families(db, current_user.id, reason="password_change")
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    session, _refresh_fid = await _issue_session(response, current_user, db, now)
    await AuditLogger.emit(
        db, action="auth.password.changed", ip_address=ip, user_id=current_user.id,
        details={
            "email": current_user.email,
            "refresh_families_revoked": revoked,
            "was_required": was_required,
        },
    )
    return session


def _current_family_id(
    refresh_cookie: str | None, request: Request | None = None
) -> _uuid_mod.UUID | None:
    """Identify the current browser from its cookie, with an access-token fallback.

    Some ASGI clients and reverse proxies do not retain a cookie whose path is
    narrower than the public API prefix. The access token is already required by
    this endpoint and carries the same family identifier, so using it as a
    read-only fallback keeps session management correct without widening the
    refresh-cookie path.
    """
    token = refresh_cookie
    if not token and request is not None:
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
    if not token:
        return None
    payload = decode_token(token)
    try:
        family_id = payload.get("family_id")
        return _uuid_mod.UUID(str(family_id)) if family_id else None
    except (ValueError, TypeError):
        return None


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(
    request: Request,
    refresh_cookie: str | None = Cookie(default=None, alias=_REFRESH_COOKIE),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[SessionResponse]:
    """List the sessions this account can still be used through, and nothing else.

    A signed-out session is not a session: it can never act again, and listing it
    here made the sessions a person had already closed read as devices they did
    not recognise — the page is titled "active sessions", and a dead row under
    that title is the page telling its reader something untrue. What *ended* a
    session is in the audit trail (`auth.password.changed` carries how many
    other sessions it signed out, `auth.session.revoked` names a single one) and
    the security page renders those events right below this list, so the answer
    is one card away rather than a second copy here. Revoked families are swept
    once their tokens have expired (see `app/tasks/retention_tasks.py`), so the
    table does not keep them forever either.

    Token material is never part of a response: `family_id` is an opaque
    identifier that only addresses a row for deletion.
    """
    current_family = _current_family_id(refresh_cookie, request)
    rows = (
        await db.execute(
            select(RefreshTokenFamily)
            .where(
                RefreshTokenFamily.user_id == current_user.id,
                RefreshTokenFamily.revoked.is_(False),
            )
            .order_by(desc(RefreshTokenFamily.last_issued_at), desc(RefreshTokenFamily.created_at))
        )
    ).scalars().all()
    return [
        SessionResponse(
            id=row.family_id,
            created_at=row.created_at,
            last_used_at=row.last_issued_at,
            current=row.family_id == current_family,
        )
        for row in rows
    ]


@router.delete("/sessions/{family_id}", status_code=204)
async def revoke_session(
    family_id: _uuid_mod.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """Revoke one of the caller's sessions; tokens are never returned."""
    family = (
        await db.execute(
            select(RefreshTokenFamily).where(
                RefreshTokenFamily.family_id == family_id,
                RefreshTokenFamily.user_id == current_user.id,
            )
        )
    ).scalar_one_or_none()
    if family is not None and not family.revoked:
        family.revoked = True
        family.revoked_at = datetime.now(timezone.utc)
        family.revoked_reason = "user_revoked"
        await db.commit()
        await AuditLogger.emit(
            db,
            action="auth.session.revoked",
            ip_address="authenticated-session",
            user_id=current_user.id,
            details={"family_id": str(family_id), "scope": "single"},
        )
    return None


@router.post("/sessions/revoke-others", status_code=200)
async def revoke_other_sessions(
    request: Request,
    refresh_cookie: str | None = Cookie(default=None, alias=_REFRESH_COOKIE),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, int]:
    """Revoke every session except the browser currently presenting the cookie."""
    current_family = _current_family_id(refresh_cookie, request)
    if current_family is None:
        raise UnauthorizedException("The current browser session could not be identified")
    result = await db.execute(
        select(RefreshTokenFamily).where(
            RefreshTokenFamily.user_id == current_user.id,
            RefreshTokenFamily.revoked.is_(False),
            RefreshTokenFamily.family_id != current_family,
        )
    )
    rows = list(result.scalars().all())
    now = datetime.now(timezone.utc)
    for family in rows:
        family.revoked = True
        family.revoked_at = now
        family.revoked_reason = "user_revoked_others"
    await db.commit()
    await AuditLogger.emit(
        db,
        action="auth.sessions.revoked_others",
        ip_address=extract_ip(request),
        user_id=current_user.id,
        details={"revoked_count": len(rows)},
    )
    return {"revoked": len(rows)}


@router.get("/security-activity", response_model=list[SecurityActivityResponse])
async def security_activity(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[SecurityActivityResponse]:
    """Show recent security events for this account, with secrets excluded."""
    security_actions = (
        "auth.login.success", "auth.login.failure", "auth.login.locked",
        "auth.mfa.success", "auth.mfa.failure", "auth.mfa.enrolled",
        "auth.mfa.disabled", "auth.password.changed", "auth.password.change_failed",
        "auth.session.revoked", "auth.sessions.revoked_others", "auth.logout",
        "auth.refresh.failure",
    )
    rows = (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.user_id == current_user.id, AuditLog.action.in_(security_actions))
            .order_by(desc(AuditLog.timestamp))
            .limit(50)
        )
    ).scalars().all()
    return [
        SecurityActivityResponse(
            id=row.id,
            timestamp=row.timestamp,
            action=row.action,
            ip_address=row.ip_address,
            details={
                key: value for key, value in (row.details or {}).items()
                if key not in {"email", "password", "secret", "code", "recovery_code", "audit_hash", "audit_prev_hash"}
            },
        )
        for row in rows
    ]


@router.post("/mfa/recovery-codes/rotate", response_model=MfaRecoveryCodesResponse)
async def rotate_recovery_codes(
    request: Request,
    payload: MfaCodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MfaRecoveryCodesResponse:
    """Replace recovery codes after re-authentication with password and TOTP."""
    if current_user.totp_enabled_at is None:
        raise ConflictException("Enable a second factor before creating recovery codes")
    if not verify_password(payload.password.get_secret_value(), current_user.password_hash):
        await AuditLogger.emit(db, action="auth.mfa.failure", ip_address=extract_ip(request), user_id=current_user.id, details={"reason": "invalid_password_on_recovery_codes"})
        raise UnauthorizedException("Invalid password")
    secret = _decrypted_totp_secret(current_user)
    step = totp.verify(secret, payload.code.get_secret_value()) if secret and payload.code else None
    if step is None or (current_user.totp_last_used_step is not None and step <= current_user.totp_last_used_step):
        raise UnauthorizedException("Invalid MFA code")
    current_user.totp_last_used_step = step
    plain, hashed = _new_recovery_codes()
    current_user.mfa_recovery_codes = hashed
    await db.commit()
    await AuditLogger.emit(db, action="auth.mfa.recovery_codes.rotated", ip_address=extract_ip(request), user_id=current_user.id, details={"count": len(plain)})
    return MfaRecoveryCodesResponse(codes=plain)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    body: RefreshTokenRequest | None = Body(default=None),
    refresh_cookie: str | None = Cookie(default=None, alias=_REFRESH_COOKIE),
    csrf_cookie: str | None = Cookie(default=None, alias=_CSRF_COOKIE),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    ip = extract_ip(request)
    refresh_value = body.refresh_token if body and body.refresh_token else refresh_cookie
    # Whether the browser's cookie is what is being validated. A token in the body
    # belongs to a caller that holds it deliberately (a script, an integration),
    # so refusing that one is no reason to sign this browser out.
    cookie_presented = bool(refresh_cookie) and not (body and body.refresh_token)
    if cookie_presented and (not csrf_cookie or not csrf_header or not secrets.compare_digest(csrf_cookie, csrf_header)):
        raise UnauthorizedException("CSRF validation failed")
    if not refresh_value:
        raise UnauthorizedException("Refresh token is required")

    def refuse(detail: str) -> NoReturn:
        """Refuse this refresh, and tell the browser to stop presenting the token.

        Deleting the cookie is part of refusing it. The client cannot read an
        ``HttpOnly`` cookie, so it asks this endpoint on every load whether it is
        still signed in (see the SPA store): a token that will never be accepted
        again would otherwise be presented — and audited as ``auth.refresh.failure``
        — once per page load until it expires, turning one refusal into an
        unbounded run of rows in the trail. The two refusals above deliberately do
        not come through here: a missing token has no cookie to clear, and a failed
        CSRF check is about the request rather than the token, which is still good.
        """
        headers = None
        if cookie_presented:
            # Built on a throwaway response and attached to the exception: the 401
            # is rendered by an exception handler, so a header set on this route's
            # injected response would never reach the browser.
            clearing = Response()
            clearing.delete_cookie(_REFRESH_COOKIE, path="/api/v1/auth")
            headers = {"set-cookie": clearing.headers["set-cookie"]}
        raise UnauthorizedException(detail, headers=headers)

    payload = decode_token(refresh_value)
    if not payload:
        await AuditLogger.emit(db, action="auth.refresh.failure", ip_address=ip,
                               details={"reason": "invalid_token"})
        refuse("Invalid refresh token")
    if payload.get("type") != "refresh":
        await AuditLogger.emit(db, action="auth.refresh.failure", ip_address=ip,
                               details={"reason": "bad_token_type", "got": payload.get("type")})
        refuse("Invalid token type")
    user_id_str = payload.get("sub")
    family_id_str = payload.get("family_id")
    jti = payload.get("jti")
    user_id = None
    try:
        user_id = _uuid_mod.UUID(user_id_str) if user_id_str else None
    except (ValueError, TypeError):
        refuse("Invalid token payload")
    if not user_id or not family_id_str:
        refuse("Invalid token payload")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        await AuditLogger.emit(db, action="auth.refresh.failure", ip_address=ip,
                               user_id=user_id,
                               details={"reason": "user_missing_or_inactive"})
        refuse("User not found or inactive")

    now = datetime.now(timezone.utc)
    try:
        family_uuid = _uuid_mod.UUID(family_id_str)
    except (ValueError, TypeError):
        refuse("Invalid refresh token payload")

    fam = (
        await db.execute(
            select(RefreshTokenFamily).where(RefreshTokenFamily.family_id == family_uuid)
        )
    ).scalar_one_or_none()

    if fam is None:
        await AuditLogger.emit(
            db, action="auth.refresh.failure", ip_address=ip, user_id=user_id,
            details={"reason": "family_not_found", "family_id": family_id_str},
        )
        refuse("Refresh token family unknown")

    if fam.revoked:
        await AuditLogger.emit(
            db, action="auth.refresh.failure", ip_address=ip, user_id=user_id,
            details={"reason": "family_revoked", "family_id": family_id_str,
                     "revoked_reason": fam.revoked_reason},
        )
        refuse("Refresh token has been revoked")

    if fam.user_id != user.id:
        await AuditLogger.emit(
            db, action="auth.refresh.failure", ip_address=ip, user_id=user_id,
            details={"reason": "family_user_mismatch"},
        )
        refuse("Refresh token does not match user")

    if fam.last_jti and fam.last_jti != jti:
        fam.revoked = True
        fam.revoked_at = now
        fam.revoked_reason = "reuse_detected"
        try:
            await db.commit()
        except Exception:
            await db.rollback()
        await AuditLogger.emit(
            db, action="auth.refresh.failure", ip_address=ip, user_id=user_id,
            details={"reason": "reuse_detected", "family_id": family_id_str,
                     "old_jti": fam.last_jti, "presented_jti": jti},
        )
        refuse("Refresh token reuse detected; family revoked")

    data = {"sub": str(user.id), "role": str(user.role)}
    access_token, expires_in = create_access_token(
        {**data, "family_id": family_id_str},
        expires_delta=timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    new_refresh, new_refresh_expires, new_jti, _ = create_refresh_token(data, family_id=family_id_str)
    response.set_cookie(
        _REFRESH_COOKIE, new_refresh, httponly=True, secure=settings.AUTH_COOKIE_SECURE,
        samesite="lax", max_age=new_refresh_expires, path="/api/v1/auth",
    )
    response.set_cookie(
        _CSRF_COOKIE, secrets.token_urlsafe(32), httponly=False, secure=settings.AUTH_COOKIE_SECURE,
        samesite="lax", max_age=new_refresh_expires, path="/",
    )
    fam.last_jti = new_jti
    fam.last_issued_at = now
    try:
        await db.commit()
    except Exception:
        await db.rollback()

    await AuditLogger.emit(
        db, action="auth.refresh.success", ip_address=ip, user_id=user_id,
        details={"family_id": family_id_str, "new_jti": new_jti},
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in,
        user=UserResponse.model_validate(user),
    )


@router.post("/logout", status_code=204)
async def logout(
    request: Request,
    response: Response,
    body: RefreshTokenRequest | None = Body(default=None),
    refresh_cookie: str | None = Cookie(default=None, alias=_REFRESH_COOKIE),
    csrf_cookie: str | None = Cookie(default=None, alias=_CSRF_COOKIE),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
    db: AsyncSession = Depends(get_db),
) -> None:
    refresh_value = body.refresh_token if body and body.refresh_token else refresh_cookie
    if refresh_cookie and not (body and body.refresh_token) and (not csrf_cookie or not csrf_header or not secrets.compare_digest(csrf_cookie, csrf_header)):
        raise UnauthorizedException("CSRF validation failed")
    if refresh_value:
        refresh_payload = decode_token(refresh_value)
        family_id = refresh_payload.get("family_id") if refresh_payload else None
        if family_id:
            try:
                family = (await db.execute(select(RefreshTokenFamily).where(RefreshTokenFamily.family_id == _uuid_mod.UUID(family_id)))).scalar_one_or_none()
                if family:
                    family.revoked = True
                    family.revoked_at = datetime.now(timezone.utc)
                    family.revoked_reason = "logout"
                    await db.commit()
            except (ValueError, TypeError):
                pass
    response.delete_cookie(_REFRESH_COOKIE, path="/api/v1/auth")
    response.delete_cookie(_CSRF_COOKIE, path="/")

    current_user: Optional[User] = None
    try:
        from app.api.deps import reusable_oauth2
        token = await reusable_oauth2(request)
        if token:
            payload = decode_token(token)
            if payload and payload.get("type") == "access":
                user_id_str = payload.get("sub")
                if user_id_str:
                    user_id = _uuid_mod.UUID(user_id_str)
                    result = await db.execute(select(User).where(User.id == user_id))
                    u = result.scalar_one_or_none()
                    if u and u.is_active:
                        current_user = u
    except Exception:
        current_user = None

    if current_user is not None:
        try:
            await AuditLogger.emit(
                db,
                action="auth.logout",
                ip_address=extract_ip(request),
                user_id=current_user.id,
                details={"email": current_user.email},
            )
        except Exception:
            pass
    return None


# ==============================================================================
# Second factor (TOTP)
# ==============================================================================
# Enrolment is self-service; recovery is not. The only way back into an account
# whose authenticator was lost is an administrator clearing the factor
# (POST /users/{id}/mfa/reset, audited as `user.mfa.reset`). That asymmetry is the
# point: a self-service reset path is a bypass of the second factor, so the second
# factor would only stop attackers who had not thought about it.


def _decrypted_totp_secret(user: User) -> str | None:
    """The user's TOTP secret, or None when the stored value cannot be read.

    `decrypt_value` raises in production for a value no configured key can read.
    Catching it here keeps that from becoming a 500 inside the authentication
    path: the safe answer to "can this account prove possession" is no.
    """
    if not user.totp_secret:
        return None
    try:
        return decrypt_value(user.totp_secret)
    except RuntimeError:
        log.error("mfa_secret_undecryptable", user_id=str(user.id))
        return None


@router.get("/mfa", response_model=MfaStatusResponse)
async def mfa_status(
    current_user: User = Depends(get_current_user),
) -> MfaStatusResponse:
    """Whether this account has a second factor, and since when.

    Deliberately not audited: it is a read of the caller's own account performed
    on every visit to the security page, and an audit row per page view is how an
    audit table becomes unreadable.
    """
    return MfaStatusResponse(
        enabled=current_user.totp_enabled_at is not None,
        enabled_at=current_user.totp_enabled_at,
    )


@router.post("/mfa/setup", response_model=MfaSetupResponse)
async def setup_mfa(
    request: Request,
    payload: MfaSetupRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MfaSetupResponse:
    """Generate a candidate secret for this account. Nothing is enabled yet.

    The password is re-checked even though the caller already holds a valid
    access token. A stolen token then buys the thief nothing here: without the
    password they cannot attach an authenticator, which is what would otherwise
    turn a 15-minute session theft into permanent access to the account.
    """
    ip = extract_ip(request)

    if current_user.totp_enabled_at is not None:
        # Replacing a factor that is already active is a different operation
        # (disable, then enrol again), and it must not be possible to silently
        # swap someone's second factor from a live session.
        raise ConflictException(
            "A second factor is already enabled. Disable it before enrolling a new one."
        )

    if _mfa_is_locked(current_user, datetime.now(timezone.utc)):
        raise HTTPException(status_code=429, detail="Too many MFA attempts. Please try again later.")
    if not verify_password(payload.password.get_secret_value(), current_user.password_hash):
        await _record_mfa_failure(current_user, db)
        await AuditLogger.emit(
            db, action="auth.mfa.setup_failed", ip_address=ip, user_id=current_user.id,
            details={"email": current_user.email, "reason": "invalid_password"},
        )
        raise UnauthorizedException("Invalid password")

    secret = totp.generate_secret()
    current_user.totp_secret = encrypt_value(secret)
    # An unfinished enrolment must not lock the account: the factor only becomes
    # real once a code generated from this secret has been verified.
    current_user.totp_enabled_at = None
    current_user.totp_last_used_step = None
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    await AuditLogger.emit(
        db, action="auth.mfa.setup_started", ip_address=ip, user_id=current_user.id,
        details={"email": current_user.email},
    )
    return MfaSetupResponse(
        secret=secret,
        otpauth_uri=totp.provisioning_uri(
            secret, account=current_user.email, issuer=settings.MFA_ISSUER
        ),
    )


@router.get("/mfa/qr")
async def mfa_qr(
    current_user: User = Depends(get_current_user),
) -> FastAPIResponse:
    """Render the pending otpauth URI as an SVG QR code without exposing it in JSON."""
    if current_user.totp_enabled_at is not None or not current_user.totp_secret:
        raise ConflictException("Start MFA enrolment before requesting its QR code")
    secret = _decrypted_totp_secret(current_user)
    if not secret:
        raise ConflictException("The pending MFA secret cannot be read")
    uri = totp.provisioning_uri(secret, account=current_user.email, issuer=settings.MFA_ISSUER)
    image = qrcode.make(uri, image_factory=SvgPathImage)
    import io
    buffer = io.BytesIO()
    image.save(buffer)
    return FastAPIResponse(content=buffer.getvalue(), media_type="image/svg+xml")


@router.post("/mfa/enable", response_model=MfaEnableResponse)
async def enable_mfa(
    request: Request,
    payload: MfaCodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MfaStatusResponse:
    """Enable the second factor once a code from the pending secret verifies."""
    ip = extract_ip(request)

    if current_user.totp_enabled_at is not None:
        raise ConflictException("A second factor is already enabled for this account")
    if payload.code is None or not payload.code.get_secret_value().strip():
        raise HTTPException(status_code=400, detail="A code from the authenticator app is required")

    # The password is checked again at the second step as well. The enrolment
    # secret is only in the hands of whoever completed step one, so this is not
    # what makes the flow safe — it is what makes the endpoint honest about the
    # field it demands, and it means neither step can be completed by a session
    # that no longer belongs to someone who knows the password.
    if _mfa_is_locked(current_user, datetime.now(timezone.utc)):
        raise HTTPException(status_code=429, detail="Too many MFA attempts. Please try again later.")
    if not verify_password(payload.password.get_secret_value(), current_user.password_hash):
        await _record_mfa_failure(current_user, db)
        await AuditLogger.emit(
            db, action="auth.mfa.setup_failed", ip_address=ip, user_id=current_user.id,
            details={"email": current_user.email, "reason": "invalid_password"},
        )
        raise UnauthorizedException("Invalid password")

    secret = _decrypted_totp_secret(current_user)
    if not secret:
        raise ConflictException("Start the enrolment before confirming it")

    now = datetime.now(timezone.utc)
    if _mfa_is_locked(current_user, now):
        raise HTTPException(status_code=429, detail="Too many MFA attempts. Please try again later.")
    step = totp.verify(secret, payload.code.get_secret_value())
    if step is None:
        await _record_mfa_failure(current_user, db)
        await AuditLogger.emit(
            db, action="auth.mfa.setup_failed", ip_address=ip, user_id=current_user.id,
            details={"email": current_user.email, "reason": "invalid_code"},
        )
        raise UnauthorizedException(
            "That code does not match. Check the device clock and try the current code."
        )

    enabled_at = datetime.now(timezone.utc)
    current_user.totp_enabled_at = enabled_at
    # The code that proved possession is spent: recording its step means it cannot
    # be used to sign in during the rest of its window, which is what an observer
    # of the enrolment screen would otherwise be able to do.
    current_user.totp_last_used_step = step
    await _clear_mfa_failures(current_user, db)
    plain_recovery_codes, hashed_recovery_codes = _new_recovery_codes()
    current_user.mfa_recovery_codes = hashed_recovery_codes
    # A factor was proven, so whatever recovery put this account here is finished.
    # The flag is cleared by evidence, not by intent: an enrolment that was
    # started and abandoned leaves it set, and the next sign-in asks again.
    was_required = current_user.must_enrol_mfa
    current_user.must_enrol_mfa = False
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    await AuditLogger.emit(
        db, action="auth.mfa.enrolled", ip_address=ip, user_id=current_user.id,
        details={
            "email": current_user.email,
            "enabled_at": enabled_at.isoformat(),
            "was_required": was_required,
        },
    )
    return MfaEnableResponse(
        enabled=True,
        enabled_at=enabled_at,
        recovery_codes=plain_recovery_codes,
    )


@router.post("/mfa/disable", response_model=MfaStatusResponse)
async def disable_mfa(
    request: Request,
    payload: MfaCodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MfaStatusResponse:
    """Remove the second factor. Requires the password *and* a live code.

    Both, not either. A password alone must not remove a factor that exists
    precisely to survive a leaked password, and a session alone must not remove
    the factor that survives a stolen session. An operator who has lost the
    device uses the administrator path instead, which is audited separately.
    """
    ip = extract_ip(request)

    if current_user.totp_enabled_at is None:
        raise ConflictException("No second factor is enabled for this account")

    if _mfa_is_locked(current_user, datetime.now(timezone.utc)):
        raise HTTPException(status_code=429, detail="Too many MFA attempts. Please try again later.")
    if not verify_password(payload.password.get_secret_value(), current_user.password_hash):
        await _record_mfa_failure(current_user, db)
        await AuditLogger.emit(
            db, action="auth.mfa.failure", ip_address=ip, user_id=current_user.id,
            details={"email": current_user.email, "reason": "invalid_password_on_disable"},
        )
        raise UnauthorizedException("Invalid password")

    if payload.code is None or not payload.code.get_secret_value().strip():
        raise HTTPException(status_code=400, detail="A code from the authenticator app is required")

    secret = _decrypted_totp_secret(current_user)
    step = totp.verify(secret, payload.code.get_secret_value()) if secret else None
    replayed = (
        step is not None
        and current_user.totp_last_used_step is not None
        and step <= current_user.totp_last_used_step
    )
    if secret is None or step is None or replayed:
        await AuditLogger.emit(
            db, action="auth.mfa.failure", ip_address=ip, user_id=current_user.id,
            details={
                "email": current_user.email,
                "reason": "secret_unreadable" if secret is None else (
                    "replay_detected" if replayed else "invalid_code"
                ),
            },
        )
        raise UnauthorizedException("Invalid MFA code")

    current_user.totp_secret = None
    current_user.totp_enabled_at = None
    current_user.totp_last_used_step = None
    current_user.mfa_recovery_codes = None
    await _clear_mfa_failures(current_user, db)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise

    await AuditLogger.emit(
        db, action="auth.mfa.disabled", ip_address=ip, user_id=current_user.id,
        details={"email": current_user.email},
    )
    return MfaStatusResponse(enabled=False, enabled_at=None)
