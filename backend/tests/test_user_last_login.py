"""When an account last signed in, and the filter that finds the ones that never did.

RWI-14/USR-10. An administrator cannot tell an unused licence from a colleague who
was told the account exists without this fact, and ``/auth/me`` is where the owner
reads the same answer. The property worth pinning is that ``NULL`` is reported as
``NULL`` rather than omitted, because a missing field and "never" look identical in
a table and mean different things, and that the filter is answered by the database
instead of by whichever page the client is showing.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models.user import User

PASSWORD = "TestPass123!"
USERS = "/api/v1/users"


async def _make_user(db, email: str, *, last_login_at=None) -> User:
    from app.core.security import hash_password

    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(PASSWORD),
        role="viewer",
        is_active=True,
        last_login_at=last_login_at,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def _by_email(rows: list[dict], email: str) -> dict:
    return next(row for row in rows if row["email"] == email)


@pytest.mark.asyncio
async def test_the_list_reports_the_stored_instant(
    client, db_session, auth_headers_admin, test_admin
):
    """The column the API returns is the column the database holds."""
    signed_in = datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
    test_admin.last_login_at = signed_in
    await db_session.commit()

    response = await client.get(USERS, headers=auth_headers_admin)
    assert response.status_code == 200, response.text

    row = _by_email(response.json()["items"], test_admin.email)
    returned = datetime.fromisoformat(row["last_login_at"].replace("Z", "+00:00"))
    assert returned == signed_in


@pytest.mark.asyncio
async def test_never_signed_in_is_null_and_not_a_missing_field(
    client, db_session, auth_headers_admin, test_viewer
):
    """A missing key cannot be told apart from "never"; both must be a real answer."""
    assert test_viewer.last_login_at is None

    response = await client.get(USERS, headers=auth_headers_admin)
    assert response.status_code == 200, response.text

    row = _by_email(response.json()["items"], test_viewer.email)
    assert "last_login_at" in row
    assert row["last_login_at"] is None


@pytest.mark.asyncio
async def test_the_owner_reads_the_same_field(
    client, db_session, test_viewer, auth_headers_viewer
):
    """`/auth/me` is not a different answer from the admin list (D12)."""
    signed_in = datetime(2026, 4, 5, 6, 7, 8, tzinfo=timezone.utc)
    test_viewer.last_login_at = signed_in
    await db_session.commit()

    response = await client.get("/api/v1/auth/me", headers=auth_headers_viewer)
    assert response.status_code == 200, response.text
    returned = datetime.fromisoformat(
        response.json()["last_login_at"].replace("Z", "+00:00")
    )
    assert returned == signed_in


@pytest.mark.asyncio
async def test_a_successful_sign_in_records_the_instant(
    client, db_session, test_viewer
):
    """The column is written by sign-in, which is what makes the filter meaningful."""
    before = datetime.now(timezone.utc)
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": test_viewer.email, "password": PASSWORD},
    )
    assert response.status_code == 200, response.text

    await db_session.refresh(test_viewer)
    stored = test_viewer.last_login_at
    assert stored is not None
    if stored.tzinfo is None:  # SQLite hands back a naive value for an aware column
        stored = stored.replace(tzinfo=timezone.utc)
    assert stored >= before.replace(microsecond=0)


@pytest.mark.asyncio
async def test_the_filter_returns_exactly_the_accounts_without_a_sign_in(
    client, db_session, auth_headers_admin
):
    """`signed_in=false` is the access-review question, answered by the database."""
    await _make_user(db_session, "never-1@example.com")
    await _make_user(db_session, "never-2@example.com")
    await _make_user(
        db_session,
        "signed-in@example.com",
        last_login_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
    )

    response = await client.get(
        USERS, params={"signed_in": "false", "size": 100}, headers=auth_headers_admin
    )
    assert response.status_code == 200, response.text
    emails = {row["email"] for row in response.json()["items"]}

    assert {"never-1@example.com", "never-2@example.com"} <= emails
    assert "signed-in@example.com" not in emails
    # Every returned row is actually NULL, not merely sorted to the front.
    assert all(row["last_login_at"] is None for row in response.json()["items"])

    response = await client.get(
        USERS, params={"signed_in": "true", "size": 100}, headers=auth_headers_admin
    )
    assert response.status_code == 200, response.text
    emails = {row["email"] for row in response.json()["items"]}

    assert "signed-in@example.com" in emails
    assert "never-1@example.com" not in emails
    assert all(row["last_login_at"] is not None for row in response.json()["items"])


@pytest.mark.asyncio
async def test_the_filter_is_audited_with_the_rest_of_the_query(
    client, db_session, auth_headers_admin
):
    """A list is a read, but which list was read is what an access review needs."""
    from app.models.audit import AuditLog

    await _make_user(db_session, "audited-never@example.com")

    response = await client.get(
        USERS, params={"signed_in": "false"}, headers=auth_headers_admin
    )
    assert response.status_code == 200, response.text

    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action == "users.list")
        )
    ).scalars().all()
    assert rows
    assert any(row.details.get("signed_in") is False for row in rows)
