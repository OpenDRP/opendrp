"""An account whose first password only its owner knows (U-7).

The property under test is the absence of a shared secret: the administrator gets
a single-use link, the database keeps only its digest, and the password is chosen
on the acceptance page. The negative halves are the interesting ones — an
expired link, a link that was replaced, and the same answer for an unknown one —
because a difference there would turn a public endpoint into an oracle.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.user import User

PASSWORD = "TestPass123!"


async def _invite(client, headers, *, email="invited@example.com", role="viewer"):
    response = await client.post(
        "/api/v1/users/invite",
        json={"email": email, "role": role},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _accept(client, token: str, password: str = "InvitedPass123!"):
    return await client.post(
        "/api/v1/auth/accept-invitation",
        json={"token": token, "new_password": password},
    )


@pytest.mark.asyncio
async def test_the_invitation_stores_only_a_digest_and_says_it_mailed_nothing(
    client, db_session, auth_headers_admin
):
    body = await _invite(client, auth_headers_admin)
    token = body["invitation_token"]
    assert token
    assert body["email_scheduled"] is False  # no SMTP in the suite

    user = (
        await db_session.execute(
            select(User).where(User.email == "invited@example.com")
        )
    ).scalar_one()
    # The link is not in the database in a usable form, and the account cannot
    # be signed into with anything an administrator knows.
    assert user.invitation_token_hash != token
    assert len(user.invitation_token_hash or "") == 64
    assert user.invitation_expires_at is not None
    assert user.must_change_password is False

    invited = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "user.invited")
        )
    ).scalars().all()
    assert len(invited) == 1
    assert token not in str(invited[0].details)


@pytest.mark.asyncio
async def test_accepting_sets_the_password_and_clears_the_invitation(
    client, db_session, auth_headers_admin
):
    body = await _invite(client, auth_headers_admin)
    token = body["invitation_token"]

    response = await _accept(client, token)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "accepted"

    user = (
        await db_session.execute(
            select(User).where(User.email == "invited@example.com")
        )
    ).scalar_one()
    await db_session.refresh(user)
    assert user.invitation_token_hash is None
    assert user.invitation_expires_at is None

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "invited@example.com", "password": "InvitedPass123!"},
    )
    assert login.status_code == 200, login.text

    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "auth.invitation.accepted")
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].user_id == user.id


@pytest.mark.asyncio
async def test_accepting_a_reissued_link_ends_the_sessions_that_predate_it(
    client, auth_headers_admin
):
    """Acceptance is a credential change, so it also ends what the old one authorised.

    An account can be re-invited after it has been used — a lost device, a
    password nobody trusts any more — and a refresh family that survived the new
    password would keep the very session the re-invitation was meant to end.
    """
    body = await _invite(client, auth_headers_admin)
    first = await _accept(client, body["invitation_token"])
    assert first.status_code == 200, first.text

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "invited@example.com", "password": "InvitedPass123!"},
    )
    assert login.status_code == 200, login.text
    stale = login.cookies.get("opendrp_refresh")
    assert stale

    reissued = await client.post(
        f"/api/v1/users/{body['user']['id']}/invitation", headers=auth_headers_admin
    )
    assert reissued.status_code == 200, reissued.text
    second = await _accept(
        client, reissued.json()["invitation_token"], "SecondPass123!"
    )
    assert second.status_code == 200, second.text

    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": stale})
    assert r.status_code == 401, r.text
    assert "revoked" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_a_second_use_of_the_same_link_is_refused(
    client, auth_headers_admin
):
    body = await _invite(client, auth_headers_admin)
    first = await _accept(client, body["invitation_token"])
    assert first.status_code == 200, first.text

    second = await _accept(client, body["invitation_token"])
    assert second.status_code == 401


@pytest.mark.asyncio
async def test_an_expired_link_and_an_unknown_one_answer_the_same(
    client, db_session, auth_headers_admin
):
    body = await _invite(client, auth_headers_admin)
    user = (
        await db_session.execute(
            select(User).where(User.email == "invited@example.com")
        )
    ).scalar_one()
    user.invitation_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db_session.commit()

    expired = await _accept(client, body["invitation_token"])
    unknown = await _accept(client, "not-a-real-token")
    assert expired.status_code == unknown.status_code == 401
    assert expired.json()["detail"] == unknown.json()["detail"]


@pytest.mark.asyncio
async def test_reissuing_replaces_the_previous_link(
    client, db_session, auth_headers_admin
):
    body = await _invite(client, auth_headers_admin)
    user = (
        await db_session.execute(
            select(User).where(User.email == "invited@example.com")
        )
    ).scalar_one()

    reissued = await client.post(
        f"/api/v1/users/{user.id}/invitation", headers=auth_headers_admin
    )
    assert reissued.status_code == 200, reissued.text
    new_token = reissued.json()["invitation_token"]
    assert new_token != body["invitation_token"]

    stale = await _accept(client, body["invitation_token"])
    assert stale.status_code == 401
    fresh = await _accept(client, new_token)
    assert fresh.status_code == 200, fresh.text

    rows = (
        await db_session.execute(
            select(AuditLog)
            .where(AuditLog.action == "user.invited")
            .order_by(AuditLog.timestamp)
        )
    ).scalars().all()
    assert [row.details.get("reissued") for row in rows] == [None, True]


@pytest.mark.asyncio
async def test_a_weak_password_is_refused_before_the_token_is_spent(
    client, db_session, auth_headers_admin
):
    body = await _invite(client, auth_headers_admin)
    response = await _accept(client, body["invitation_token"], password="short")
    assert response.status_code == 422

    user = (
        await db_session.execute(
            select(User).where(User.email == "invited@example.com")
        )
    ).scalar_one()
    await db_session.refresh(user)
    # Still open: a rejected password must not consume the link.
    assert user.invitation_token_hash is not None
