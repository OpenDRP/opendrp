import ipaddress
import uuid
from typing import AsyncGenerator

import structlog
from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditLogger
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.exceptions import ForbiddenException, RateLimitException, UnauthorizedException
from app.core.mfa_policy import mfa_required_by_policy
from app.core.request_rate_limit import RequestRateLimiter
from app.core.security import decode_token
from app.models.user import User, role_name

log = structlog.get_logger()

reusable_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# The endpoints that put a credential in order, and the only ones reachable while
# one is out of order — whichever reason put the account there. `/auth/me` is how a
# client learns which step is pending, `/auth/password` performs the password step,
# and `GET /auth/mfa` reports whether a factor already exists. Sign-in, refresh and
# sign-out do not appear here: they never resolve this dependency in the first
# place, and a session that cannot be refreshed or ended would be a worse trap than
# the one this gate exists to close.
_ONBOARDING_ALWAYS_ALLOWED = frozenset(
    {
        "/api/v1/auth/me",
        "/api/v1/auth/password",
        "/api/v1/auth/mfa",
    }
)

# The second-factor step, reachable only once the password step is done. The
# ordering is enforced here rather than in the client because both enrolment calls
# re-check the password: if a temporary password were still in force, the new
# factor would be bound to the credential its owner is about to replace — and the
# administrator who chose that password would have been present at the enrolment.
_ONBOARDING_MFA_ALLOWED = frozenset(
    {
        "/api/v1/auth/mfa/setup",
        "/api/v1/auth/mfa/enable",
    }
)


def pending_credential_steps(user: User) -> list[str]:
    """The credential steps this account owes on its own account, in order.

    Only the per-account facts: a password assigned *for* the holder, and a second
    factor removed *for* them. The deployment-wide policy
    (``REQUIRE_MFA_FOR_ADMINS``) produces a similar-looking step but is not one of
    these, and the difference is not cosmetic: this list is what gets *written* into
    audit details when an administrator creates the situation (``onboarding_required``
    on ``user.password_reset`` / ``user.mfa.reset``), and the policy writes nothing
    to the account at all. ``_enforce_credential_onboarding`` checks the policy
    separately, which is what lets the two keep different markers and different
    audit rows while sharing one gate.
    """
    steps: list[str] = []
    if getattr(user, "must_change_password", False):
        steps.append("password")
    if getattr(user, "must_enrol_mfa", False):
        steps.append("mfa")
    return steps


def _onboarding_detail(steps: list[str]) -> str:
    pending = " and ".join(
        "set a password of your own" if step == "password" else "enrol a second factor"
        for step in steps
    )
    return (
        f"Credential onboarding required (onboarding_required): this account must "
        f"{pending} before the rest of the platform is available. "
        f"Open the account onboarding page to continue."
    )


# The single answer for the deployment policy, shared by both places that refuse
# it (see `_audit_missing_policy_factor`). The marker stays: the client routes on
# the token rather than on the prose.
_MFA_POLICY_DETAIL = (
    "Second factor required (mfa_required): this deployment requires administrators "
    "to enable MFA. Enrol an authenticator app on the account onboarding page to "
    "continue."
)


async def _audit_missing_policy_factor(
    request: Request, user: User, db: AsyncSession
) -> None:
    """Record that an administrator account acted without its second factor.

    This is the security signal the deployment-wide policy exists to produce: an
    account that can create users, read the audit trail and change settings, in use
    without a second factor. It is written per refused request — unlike the
    credential-onboarding refusal, which is a state an administrator deliberately
    created and already audited when they created it — because the account cannot
    reach anything but the enrolment page, so anything that lands here is either a
    stale client or something that is not the application.

    Best-effort by design: a refusal must not turn into a 500 because the audit
    write failed.
    """
    try:
        await AuditLogger.emit(
            db,
            action="auth.mfa.required",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={
                "path": str(request.url.path),
                "role": role_name(user.role),
                "reason": "require_mfa_for_admins",
            },
        )
    except Exception:
        pass


async def _enforce_credential_onboarding(
    request: Request, user: User, db: AsyncSession
) -> None:
    """Refuse everything but the endpoints that put a credential in order.

    Placed next to the rate limiter inside ``get_current_user`` for the same
    reason it is there: this is the one dependency every authenticated route
    resolves, so an endpoint written later inherits the refusal instead of having
    to remember it. A credential that somebody else chose is a shared secret, and
    "shared" is not a property of one router.

    Three situations arrive here, and they share one gate because they share one
    answer — the account owes something before the rest of the platform opens:

    * a password assigned *for* the account (``must_change_password``);
    * a second factor cleared *for* it (``must_enrol_mfa``);
    * a second factor the *installation* requires and this account does not have
      (``REQUIRE_MFA_FOR_ADMINS``, administrators only).

    The third is why this gate is no longer only about flags. It used to be refused
    on admin routes by ``require_admin``, which left every other page open — so an
    administrator who turned the policy on was asked for a factor only when they
    happened to open an admin screen. It is the same obligation, so it is the same
    gate and the same page, and the answer arrives at sign-in rather than as a
    refusal on the way into a page.

    The two reasons keep different markers and different audit: the first two are
    already in the trail (``user.password_reset`` / ``user.mfa.reset`` carry
    ``onboarding_required`` in their details), so a row per refused request would
    only add noise from a client that is following instructions — they are a
    structured log line instead. The policy refusal is audited, because an
    administrator acting without a second factor is the fact that setting exists to
    make visible.
    """
    steps = pending_credential_steps(user)
    policy_factor = not steps and mfa_required_by_policy(user.role, user.totp_enabled_at)
    if not steps and not policy_factor:
        return

    path = str(request.url.path)
    allowed = _ONBOARDING_ALWAYS_ALLOWED
    if not steps or steps == ["mfa"]:
        # The password step is already done (or was never owed), so the enrolment
        # endpoints are the way out rather than a detour around the gate. With no
        # credential step pending, the password endpoint stays on the allowlist as
        # well: changing a password voluntarily is never what the gate is about.
        allowed = allowed | _ONBOARDING_MFA_ALLOWED
    if path in allowed:
        return

    if policy_factor:
        await _audit_missing_policy_factor(request, user, db)
        raise ForbiddenException(_MFA_POLICY_DETAIL)

    log.info(
        "credential_onboarding_required",
        user_id=str(user.id),
        ip_address=extract_ip(request),
        details={
            "path": path,
            "method": request.method,
            "steps": steps,
            "role": role_name(user.role),
        },
    )
    raise ForbiddenException(_onboarding_detail(steps))


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def get_current_user(
    request: Request,
    token: str = Depends(reusable_oauth2),
    db: AsyncSession = Depends(get_db),
) -> User:
    payload = decode_token(token)
    if not payload:
        raise UnauthorizedException("Could not validate credentials")
    token_type = payload.get("type")
    if token_type != "access":
        raise UnauthorizedException("Invalid token type")
    user_id_str = payload.get("sub")
    if not user_id_str:
        raise UnauthorizedException("Invalid token payload")
    try:
        user_id = uuid.UUID(user_id_str)
    except (ValueError, TypeError):
        raise UnauthorizedException("Invalid token payload")
    if not user_id:
        raise UnauthorizedException("Invalid token payload")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise UnauthorizedException("User not found")
    if not user.is_active:
        raise UnauthorizedException("User is inactive")
    await _enforce_request_rate_limit(request, user, db)
    await _enforce_credential_onboarding(request, user, db)
    return user


async def _enforce_request_rate_limit(request: Request, user: User, db: AsyncSession) -> None:
    """Bound one account's request rate, auditing the first block of a window.

    Applied here — the single dependency every authenticated route resolves —
    rather than per router, so a new endpoint cannot forget it. Unauthenticated
    traffic is unaffected: an invalid token is rejected above, before any Redis
    work, and login/refresh/connector routes never reach this function.
    """
    verdict = await RequestRateLimiter.check(
        user.id,
        limit_per_minute=settings.AUTHENTICATED_RATE_LIMIT_PER_MINUTE,
    )
    if verdict.allowed:
        return

    details = {
        "path": str(request.url.path),
        "method": request.method,
        "limit_per_minute": settings.AUTHENTICATED_RATE_LIMIT_PER_MINUTE,
        "retry_after_seconds": verdict.retry_after,
    }
    log.warning(
        "request_rate_limited",
        user_id=str(user.id),
        action="rate_limit.request_blocked",
        ip_address=extract_ip(request),
        details=details,
    )
    if verdict.first_block_in_window:
        # Once per window: auditing every rejected request would amplify the
        # very load this check exists to bound.
        await AuditLogger.emit(
            db,
            action="rate_limit.request_blocked",
            ip_address=extract_ip(request),
            user_id=user.id,
            details=details,
        )
    raise RateLimitException(
        detail=(
            f"Too many requests: this account is limited to "
            f"{settings.AUTHENTICATED_RATE_LIMIT_PER_MINUTE} requests per minute. "
            f"Retry in about {verdict.retry_after} second(s)."
        ),
        retry_after=verdict.retry_after,
    )


def _normalize_ip(value: str | None) -> str | None:
    """Parse a single forwarded-header entry into a bare IP address.

    Returns ``None`` for anything that is not an address, so a malformed hop is
    skipped instead of being recorded in the audit trail.
    """
    candidate = (value or "").strip().strip('"')
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    # Proxies sometimes append a source port: "198.51.100.7:41234", or wrap
    # IPv6 in brackets: "[2001:db8::1]:41234".
    if candidate.startswith("["):
        host, _sep, _port = candidate[1:].partition("]")
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return None
    host, sep, port = candidate.rpartition(":")
    if sep and port.isdigit():
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return None
    return None


def _forwarded_candidates(request: Request) -> list[str]:
    """Flatten ``X-Forwarded-For`` (left to right) plus ``X-Real-IP``."""
    candidates: list[str] = []
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        candidates.extend(forwarded.split(","))
    real = request.headers.get("x-real-ip")
    if real:
        candidates.append(real)
    return candidates


def extract_ip(request: Request | None) -> str:
    if request is None:
        return "unknown"
    try:
        client_host = request.client.host if request.client else None
    except Exception:
        client_host = None
    trusted: list[ipaddress.IPv4Network | ipaddress.IPv6Network | ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        from app.core.config import settings

        for item in settings.TRUSTED_PROXY_IPS.split(","):
            value = item.strip()
            if not value:
                continue
            try:
                trusted.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                try:
                    trusted.append(ipaddress.ip_address(value))
                except ValueError:
                    continue
    except Exception:
        trusted = []

    def _is_trusted_proxy(host: str | None) -> bool:
        if not host:
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(
            (address in item if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else address == item)
            for item in trusted
        )

    if _is_trusted_proxy(client_host):
        # Walk the chain from the hop nearest to us. Every entry to the left of a
        # trusted proxy is client-supplied — nginx appends the peer address via
        # ``$proxy_add_x_forwarded_for``, so the *leftmost* value is attacker
        # controlled and can be forged to attribute an action to any address.
        # The first untrusted hop we reach is the closest one we can believe.
        for raw in reversed(_forwarded_candidates(request)):
            candidate = _normalize_ip(raw)
            if candidate is None or _is_trusted_proxy(candidate):
                continue
            return candidate
    try:
        client = request.client
        if client and client.host:
            return str(client.host)
    except Exception:
        pass
    return "unknown"


async def require_admin(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Admin-only gate, with the second-factor policy on top when enabled.

    The second factor is optional by design — an installation must not be able to
    lock its own administrator out because a phone was lost — so a deployment that
    wants it enforced sets ``REQUIRE_MFA_FOR_ADMINS=true``. When it is set, an
    administrator who has not enrolled is refused.

    That refusal now normally happens one layer earlier: the credential gate in
    ``get_current_user`` refuses the account on *every* route but the enrolment
    page, so the policy is a step at sign-in rather than a surprise on the first
    admin screen, and the sign-in response says so (`mfa_required_by_policy` on the
    user payload). The check is kept here as the second line of defence, with the
    same audit and the same marker: a route that reaches this function has already
    been through the gate, and if that ever stops being true — a dependency wired
    differently, a policy that comes to depend on something the gate cannot see —
    the refusal and its trail must not be the thing that quietly went missing.
    """
    if current_user.role != "admin":
        raise ForbiddenException("Admin role required")

    if mfa_required_by_policy(current_user.role, current_user.totp_enabled_at):
        await _audit_missing_policy_factor(request, current_user, db)
        raise ForbiddenException(_MFA_POLICY_DETAIL)
    return current_user


def require_analyst_or_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.role not in {"admin", "analyst"}:
        raise ForbiddenException("Analyst or Admin role required")
    return current_user


def require_viewer_plus(
    current_user: User = Depends(get_current_user),
) -> User:
    if not current_user.is_active:
        raise UnauthorizedException("User is inactive")
    if current_user.role not in {"admin", "analyst", "viewer"}:
        raise ForbiddenException("Insufficient permissions")
    return current_user
