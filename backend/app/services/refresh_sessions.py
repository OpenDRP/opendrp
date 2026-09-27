"""Refresh-token families: the revocation half of session control.

Every credential change has to answer the same question — *which sessions die
now?* — and the answer is the same everywhere: all of them, because the reason
for the change is that the old credential is no longer trustworthy. A password
that an administrator reset may have been read off a screen; a factor that was
cleared may be in the hands of whoever took the device. Leaving a refresh family
alive across either event would keep the very session the change was meant to
end.

It lives here rather than in the router that used to own it because three callers
now need it (the users router, the auth router and the admin CLI), and because a
router importing another router to reuse a helper is the shape that eventually
grows an import cycle.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.token import RefreshTokenFamily


async def revoke_refresh_families(
    db: AsyncSession, user_id: uuid.UUID, reason: str = "password_reset"
) -> int:
    """Revoke every non-revoked refresh-token family of ``user_id``.

    Returns how many rows changed, which callers record in the audit trail: a
    password reset that revoked nothing and one that revoked three sessions are
    different events, even though the audit action is the same.

    ``reason`` lands in ``revoked_reason`` and is what the next refresh attempt
    reports back, so it is written for an operator reading a log line rather than
    for a machine: ``password_reset``, ``password_change``, ``password_reset_cli``.
    """
    now = datetime.now(timezone.utc)
    result = await db.execute(
        sa_update(RefreshTokenFamily)
        .where(
            RefreshTokenFamily.user_id == user_id,
            RefreshTokenFamily.revoked.is_(False),
        )
        .values(revoked=True, revoked_at=now, revoked_reason=reason)
    )
    return result.rowcount or 0
