"""The "at least one active administrator" invariant, decided in one place.

The platform may not lock itself out: the last account that can create users,
read the trail and change settings cannot be demoted, deactivated or deleted —
and it cannot be demoted by hand either, which is why this lives outside the
users router. Two callers change the active-admin set (the HTTP router and
``scripts/manage_admin.py``) and both have to apply the same rule with the same
serialization, or the invariant is only as strong as the caller that remembered
it.

Why a predicate check is not enough
-----------------------------------
Under ``READ COMMITTED`` a row lock over the rows currently satisfying
``role = 'admin' AND is_active`` does not block a concurrent ``INSERT`` that
adds another administrator, so a check-then-write alone can let two sessions
each believe the other is the survivor. A transaction-scoped advisory lock over
a fixed key serializes every operation that *enters or leaves* the set —
including account creation, which takes the same lock — so the count and the
change that depends on it cannot be interleaved. On SQLite the lock is skipped:
the test engine is single-writer, so the count is already serialized by the
database.

The refusal is raised as :class:`LastActiveAdminError` rather than as an HTTP
exception, so the caller decides how to say it: the router answers ``409`` and
the CLI prints a line and exits non-zero.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, role_name

#: The one key every writer of the active-admin set takes. It is a constant here
#: rather than written at each call site: two spellings of the same lock are two
#: locks, and the invariant would look enforced while holding nothing.
ACTIVE_ADMIN_LOCK_KEY = 0x4F445250


class LastActiveAdminError(RuntimeError):
    """The requested change would leave no active administrator."""

    def __init__(self, message: str = "Cannot remove the last active admin") -> None:
        super().__init__(message)


async def lock_active_admin_set(db: AsyncSession) -> None:
    """Serialize this transaction against every other writer of the admin set."""
    if db.get_bind().dialect.name == "postgresql":
        await db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": ACTIVE_ADMIN_LOCK_KEY},
        )


async def count_active_admins(
    db: AsyncSession, exclude_id: uuid.UUID | None = None
) -> int:
    stmt = select(func.count(User.id)).where(
        User.role == "admin", User.is_active.is_(True)
    )
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    result = await db.execute(stmt)
    return int(result.scalar_one() or 0)


def _is_losing_admin(
    target: User, *, final_role: str | None, final_active: bool | None
) -> bool:
    role = role_name(target.role)
    resulting_role = final_role if final_role is not None else role
    resulting_active = target.is_active if final_active is None else final_active
    return bool(
        role == "admin"
        and target.is_active
        and (resulting_role != "admin" or not resulting_active)
    )


async def ensure_active_admin_remains(
    db: AsyncSession,
    target: User,
    *,
    final_role: str | None = None,
    final_active: bool | None = None,
) -> None:
    """Refuse a change that would leave the platform without an administrator.

    ``target`` carries the *current* role and activity; ``final_role`` and
    ``final_active`` describe the state the caller is about to write (``None``
    means "unchanged"). Raises :class:`LastActiveAdminError` when the change
    would empty the set.
    """
    if not _is_losing_admin(target, final_role=final_role, final_active=final_active):
        return
    await lock_active_admin_set(db)
    if await count_active_admins(db, exclude_id=target.id) < 1:
        raise LastActiveAdminError()


def admin_state_summary(target: Any) -> dict[str, Any]:
    """The role/activity pair as it will be written down by an audit row."""
    return {
        "role": role_name(target.role),
        "is_active": bool(target.is_active),
    }


__all__ = [
    "ACTIVE_ADMIN_LOCK_KEY",
    "LastActiveAdminError",
    "ensure_active_admin_remains",
    "count_active_admins",
    "lock_active_admin_set",
    "admin_state_summary",
]
