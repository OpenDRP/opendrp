"""Releasing a brute-force lock, and everything it must leave alone.

RWI-13/USR-09. The lockout works by refusing to guess, so it has to be releasable
for the person behind it — and the release has to be *only* that. A recovery
operation that changes more than it says is how a support call becomes a privilege
change, which is why this file asserts the negative half: the password hash, the
role, the active flag, the second factor and its own lockout counter are all
unchanged by ``POST /api/v1/users/{id}/unlock``, and one audit row records the
release with the method that produced it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog

PASSWORD = "TestPass123!"
UNLOCK = "/api/v1/users/{user_id}/unlock"


async def _lock(db_session, user, *, attempts: int = 8, minutes: int = 15) -> None:
    """Put the account in the state eight wrong passwords leave behind."""
    user.failed_login_attempts = attempts
    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    await db_session.commit()


async def _login(client, email: str, password: str = PASSWORD):
    return await client.post("/api/v1/auth/login", json={"email": email, "password": password})


@pytest.mark.asyncio
async def test_a_locked_account_signs_in_after_one_call(
    client, db_session, test_admin, test_viewer, auth_headers_admin
):
    await _lock(db_session, test_viewer)
    assert (await _login(client, test_viewer.email)).status_code == 401

    response = await client.post(
        UNLOCK.format(user_id=test_viewer.id), headers=auth_headers_admin
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["locked_until"] is None
    assert body["failed_login_attempts"] == 0
    # The failure prompt counted here is the *password* one: logging in now is the
    # property the operator asked for.
    assert (await _login(client, test_viewer.email)).status_code == 200


@pytest.mark.asyncio
async def test_it_changes_nothing_but_the_lockout(
    client, db_session, test_admin, test_viewer, auth_headers_admin
):
    test_viewer.totp_secret = "encrypted-secret-placeholder"
    test_viewer.totp_enabled_at = datetime.now(timezone.utc)
    test_viewer.mfa_failed_attempts = 4
    test_viewer.mfa_locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
    await db_session.commit()

    def _fingerprint(user) -> tuple:
        # SQLite hands back a naive datetime for an aware column, so the instant is
        # compared without its tzinfo rather than as the driver returned it.
        enabled_at = user.totp_enabled_at
        if enabled_at is not None and enabled_at.tzinfo is not None:
            enabled_at = enabled_at.replace(tzinfo=None)
        return (
            user.password_hash,
            str(user.role),
            user.is_active,
            user.totp_secret,
            enabled_at,
        )

    before = _fingerprint(test_viewer)
    await _lock(db_session, test_viewer)

    response = await client.post(
        UNLOCK.format(user_id=test_viewer.id), headers=auth_headers_admin
    )
    assert response.status_code == 200, response.text

    await db_session.refresh(test_viewer)
    assert _fingerprint(test_viewer) == before, (
        "unlocking an account must not be a credential change"
    )
    # The MFA counter is a different credential: releasing it here would hand extra
    # guesses at the code to whoever already has the password (D8).
    assert test_viewer.mfa_failed_attempts == 4
    assert test_viewer.mfa_locked_until is not None

    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "user.unlocked")
        )
    ).scalars().all()
    assert len(rows) == 1, "one operation, one row"
    assert rows[0].details["method"] == "brute_force_unlock"
    assert rows[0].details["target_user_id"] == str(test_viewer.id)
    assert rows[0].details["failed_login_attempts_cleared"] == 8


@pytest.mark.asyncio
async def test_an_account_that_is_not_locked_is_refused(
    client, db_session, test_admin, test_viewer, auth_headers_admin
):
    response = await client.post(
        UNLOCK.format(user_id=test_viewer.id), headers=auth_headers_admin
    )
    assert response.status_code == 409, response.text
    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "user.unlocked")
        )
    ).scalars().all()
    assert rows == [], "a refusal is not a release"


@pytest.mark.asyncio
async def test_only_an_administrator_can_release_a_lockout(
    client, db_session, test_viewer, auth_headers_analyst, auth_headers_viewer
):
    await _lock(db_session, test_viewer)
    for headers in (auth_headers_analyst, auth_headers_viewer):
        response = await client.post(UNLOCK.format(user_id=test_viewer.id), headers=headers)
        assert response.status_code == 403, response.text
    await db_session.refresh(test_viewer)
    assert test_viewer.locked_until is not None


@pytest.mark.asyncio
async def test_an_unknown_account_is_a_404(client, auth_headers_admin):
    import uuid

    response = await client.post(
        UNLOCK.format(user_id=uuid.uuid4()), headers=auth_headers_admin
    )
    assert response.status_code == 404
