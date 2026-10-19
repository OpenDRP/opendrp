"""Invitations: an account whose first password only its owner ever sees (U-7).

The administrator creates the account and the platform keeps a *digest* of a
single-use token. The owner opens the link, chooses a password, and the token is
spent. Nothing shared travels through a chat, a ticket or a mail thread — which
is the actual way temporary passwords leak — and the administrator never knows
the credential they created.

The token is high-entropy and only its SHA-256 digest is stored: a database copy
does not contain a usable link, and there is no secret to guess. The link can be
mailed by the platform or copied by the administrator and passed on by whatever
channel they already trust; both are the same token with the same expiry.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.user import User

#: Long enough to survive a weekend and a holiday; short enough that a link
#: forwarded by mistake is not a standing key.
INVITATION_TTL = timedelta(days=7)

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def token_digest(token: str) -> str:
    """The stored form of an invitation token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_invitation(user: User, *, now: datetime | None = None) -> tuple[str, datetime]:
    """Put a fresh token on ``user`` and return the plaintext once.

    Rotation is the same operation as issue: an invitation that expired or was
    lost is replaced by a new link, and the old link stops working because the
    digest changed.
    """
    token = secrets.token_urlsafe(32)
    expires_at = (now or datetime.now(timezone.utc)) + INVITATION_TTL
    user.invitation_token_hash = token_digest(token)
    user.invitation_expires_at = expires_at
    return token, expires_at


def clear_invitation(user: User) -> None:
    user.invitation_token_hash = None
    user.invitation_expires_at = None


def is_expired(user: User, *, now: datetime | None = None) -> bool:
    expires_at = user.invitation_expires_at
    if expires_at is None:
        return True
    if expires_at.tzinfo is None:  # SQLite hands back a naive value
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= (now or datetime.now(timezone.utc))


async def find_by_token(db: AsyncSession, token: str) -> User | None:
    return (
        await db.execute(
            select(User).where(User.invitation_token_hash == token_digest(token))
        )
    ).scalar_one_or_none()


def public_origin() -> str | None:
    """The origin an invitation link should point at, or ``None``.

    Same rule as an alert link: the first configured origin that is a real
    http(s) address and not loopback. A link to ``localhost`` in a mail is a link
    to the reader's own machine, so the platform mails nothing rather than
    mailing that; the administrator can still copy the link, and their browser
    knows the origin they are actually using.
    """
    for candidate in getattr(settings, "CORS_ORIGINS", None) or []:
        text = str(candidate).strip().rstrip("/")
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        if (parsed.hostname or "").lower() in _LOOPBACK_HOSTS:
            continue
        return text
    return None


def invitation_url(token: str) -> str | None:
    origin = public_origin()
    if origin is None:
        return None
    return f"{origin}/accept-invitation?token={token}"
