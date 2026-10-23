"""Auth mutations and their audit row must share one transaction.

Each endpoint below used to commit the credential change, the revoked session or
the MFA switch first and only then write the event that records it. A crash — or
a failing audit write — in between left a security-relevant change with no trail.
These tests pin the repaired behaviour from both sides: when the trail cannot be
written the request is refused with ``503``, and nothing about the account moved.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.core import totp
from app.core.security import verify_password
from app.models.audit import AuditLog
from app.models.token import RefreshTokenFamily

PASSWORD = "TestPass123!"


def _code_for(secret: str, step_offset: int = 0) -> str:
    return totp.code_at(secret, totp.current_step() + step_offset)


def _unavailable_audit(monkeypatch) -> None:
    async def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr("app.core.audit.prepare_entry", fail)


@pytest.mark.asyncio
async def test_login_is_refused_when_the_trail_is_unavailable(
    client, db_session, test_viewer, monkeypatch
):
    """A session is a state change: it must not exist without its sign-in row.

    The route used to commit the refresh family and then write
    ``auth.login.success``, so a failing audit write left a usable session no log
    line mentions — the one event a SIEM uses to notice an account in use.
    """
    _unavailable_audit(monkeypatch)
    # Read the id before the request: the refusal rolls the shared session back,
    # which expires the instance and would make this access lazy IO.
    viewer_id = test_viewer.id
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": test_viewer.email, "password": PASSWORD},
    )
    assert response.status_code == 503, response.text
    assert "set-cookie" not in response.headers

    families = (
        await db_session.execute(
            select(RefreshTokenFamily).where(RefreshTokenFamily.user_id == viewer_id)
        )
    ).scalars().all()
    assert families == [], "no refresh family may survive an unrecorded sign-in"

    await db_session.refresh(test_viewer)
    assert test_viewer.last_login_at is None

    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.login.success")
        )
    ).scalars().all()
    assert rows == []


@pytest.mark.asyncio
async def test_password_change_is_refused_when_the_trail_is_unavailable(
    client, db_session, auth_headers_admin, test_admin, monkeypatch
):
    _unavailable_audit(monkeypatch)
    response = await client.post(
        "/api/v1/auth/password",
        headers=auth_headers_admin,
        json={"current_password": PASSWORD, "new_password": "BrandNew123!"},
    )
    assert response.status_code == 503
    await db_session.refresh(test_admin)
    assert verify_password(PASSWORD, test_admin.password_hash)


@pytest.mark.asyncio
async def test_mfa_enrolment_is_refused_when_the_trail_is_unavailable(
    client, db_session, auth_headers_admin, test_admin, monkeypatch
):
    _unavailable_audit(monkeypatch)
    response = await client.post(
        "/api/v1/auth/mfa/setup", headers=auth_headers_admin, json={"password": PASSWORD}
    )
    assert response.status_code == 503
    await db_session.refresh(test_admin)
    # No pending enrolment secret was left behind for the next attempt to confirm.
    assert test_admin.totp_secret is None


@pytest.mark.asyncio
async def test_session_revocation_is_refused_when_the_trail_is_unavailable(
    client, db_session, auth_headers_admin, test_admin, monkeypatch
):
    family = RefreshTokenFamily(
        id=uuid.uuid4(),
        family_id=uuid.uuid4(),
        user_id=test_admin.id,
        last_jti="current-jti",
        last_issued_at=datetime.now(timezone.utc),
        revoked=False,
    )
    db_session.add(family)
    await db_session.commit()

    _unavailable_audit(monkeypatch)
    response = await client.delete(
        f"/api/v1/auth/sessions/{family.family_id}", headers=auth_headers_admin
    )
    assert response.status_code == 503
    await db_session.refresh(family)
    assert family.revoked is False
    assert family.revoked_reason is None


@pytest.mark.asyncio
async def test_disabling_mfa_is_refused_when_the_trail_is_unavailable(
    client, db_session, auth_headers_admin, test_admin, monkeypatch
):
    setup = await client.post(
        "/api/v1/auth/mfa/setup", headers=auth_headers_admin, json={"password": PASSWORD}
    )
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    enabled = await client.post(
        "/api/v1/auth/mfa/enable",
        headers=auth_headers_admin,
        json={"password": PASSWORD, "code": _code_for(secret)},
    )
    assert enabled.status_code == 200, enabled.text

    _unavailable_audit(monkeypatch)
    response = await client.post(
        "/api/v1/auth/mfa/disable",
        headers=auth_headers_admin,
        # The enrolment code is spent; the next step's code is the live one.
        json={"password": PASSWORD, "code": _code_for(secret, 1)},
    )
    assert response.status_code == 503
    await db_session.refresh(test_admin)
    assert test_admin.totp_enabled_at is not None
    assert test_admin.totp_secret is not None


@pytest.mark.asyncio
async def test_refresh_rotation_is_refused_when_the_trail_is_unavailable(
    client, db_session, test_viewer, monkeypatch
):
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": test_viewer.email, "password": PASSWORD},
    )
    assert login.status_code == 200, login.text
    refresh = login.cookies.get("opendrp_refresh")
    assert refresh
    family = (
        await db_session.execute(
            select(RefreshTokenFamily).where(RefreshTokenFamily.user_id == test_viewer.id)
        )
    ).scalar_one()
    current_jti = family.last_jti

    _unavailable_audit(monkeypatch)
    response = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert response.status_code == 503
    # The token the browser already holds is still the current one: rotation was
    # refused, not half-applied, and no successor token was handed out.
    await db_session.refresh(family)
    assert family.last_jti == current_jti
