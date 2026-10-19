"""Regression tests: users router read, update, and admin invariant paths.

These tests cover the user-list read paths and admin invariants that must not
regress:

* ``GET /users/brief``        — admin-only active-user checklist payload.
* ``GET /users``              — pagination, email search, ``users.list`` audit.
* ``GET /users/{user_id}``    — fetch + ``users.view`` audit, 404 branch.
* ``PUT /users/{id}``         — activation is changed here and nowhere else
  (RWI-04): lock/unlock semantics, the self-guard, the last-admin guard,
  stale-lockout cleanup on revive, and the ``user.locked`` / ``user.unlocked``
  audit shape both directions share.
* ``PUT`` / ``DELETE`` 404 branches for missing users.

The PostgreSQL-only concurrency test is skipped on SQLite because SQLite ignores
``SELECT FOR UPDATE``; it must run against an isolated PostgreSQL ``*_test`` DB.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.user import User

PASSWORD = "Characterize123!"


async def _make_user(db, email: str, *, role: str = "viewer", active: bool = True) -> User:
    from app.core.security import hash_password

    u = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(PASSWORD),
        role=role,
        is_active=active,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


class TestListUsersBrief:
    @pytest.mark.asyncio
    async def test_brief_lists_only_active_users_ordered_by_email(
        self, client, auth_headers_admin, db_session
    ):
        await _make_user(db_session, "brief-active@example.com", role="analyst")
        await _make_user(db_session, "brief-inactive@example.com", active=False)

        r = await client.get("/api/v1/users/brief", headers=auth_headers_admin)
        assert r.status_code == 200, r.text
        rows = r.json()
        emails = [row["email"] for row in rows]

        assert "brief-active@example.com" in emails
        assert "brief-inactive@example.com" not in emails
        # Ordered by email for stable checkbox rendering.
        assert emails == sorted(emails)
        # Shape: id/email/role/is_active only.
        active_row = next(row for row in rows if row["email"] == "brief-active@example.com")
        assert set(active_row.keys()) == {"id", "email", "role", "is_active"}
        assert active_row["is_active"] is True

    @pytest.mark.asyncio
    async def test_brief_role_serialization_returns_role_value(
        self, client, auth_headers_admin, db_session
    ):
        """The brief endpoint must expose the stable enum value, not repr."""
        await _make_user(db_session, "rolepin@example.com", role="analyst")
        r = await client.get("/api/v1/users/brief", headers=auth_headers_admin)
        assert r.status_code == 200, r.text
        row = next(row for row in r.json() if row["email"] == "rolepin@example.com")
        assert row["role"] == "analyst"

    @pytest.mark.asyncio
    async def test_brief_requires_admin(self, client, auth_headers_viewer):
        r = await client.get("/api/v1/users/brief", headers=auth_headers_viewer)
        assert r.status_code == 403, r.text

    @pytest.mark.asyncio
    async def test_brief_writes_users_list_audit(self, client, auth_headers_admin, db_session):
        r = await client.get("/api/v1/users/brief", headers=auth_headers_admin)
        assert r.status_code == 200, r.text
        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "users.list")
                )
            ).scalars()
        )
        assert rows, "users.brief must record a users.list audit event"
        assert rows[-1].details.get("brief") is True
        assert rows[-1].details.get("results") == len(r.json())


class TestListUsersPaginationAndSearch:
    @pytest.mark.asyncio
    async def test_pagination_metadata_and_ordering(
        self, client, auth_headers_admin, db_session
    ):
        for i in range(3):
            await _make_user(db_session, f"page-user-{i}@example.com")

        r = await client.get(
            "/api/v1/users", headers=auth_headers_admin, params={"page": 1, "size": 2}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["page"] == 1
        assert body["size"] == 2
        assert body["pages"] >= 2
        assert len(body["items"]) == 2
        assert body["total"] >= 3

        # Newest first: created_at descending within the listing.
        r2 = await client.get(
            "/api/v1/users", headers=auth_headers_admin, params={"page": 2, "size": 2}
        )
        assert r2.status_code == 200, r2.text
        page1_emails = {item["email"] for item in body["items"]}
        page2_emails = {item["email"] for item in r2.json()["items"]}
        assert page1_emails.isdisjoint(page2_emails), "page 2 must not repeat page 1"

    @pytest.mark.asyncio
    async def test_search_filters_by_email_substring(
        self, client, auth_headers_admin, db_session
    ):
        await _make_user(db_session, "needle-haystack@example.com")
        await _make_user(db_session, "unrelated@example.com")

        r = await client.get(
            "/api/v1/users", headers=auth_headers_admin, params={"search": "needle"}
        )
        assert r.status_code == 200, r.text
        emails = [item["email"] for item in r.json()["items"]]
        assert "needle-haystack@example.com" in emails
        assert all("needle" in e for e in emails)

    @pytest.mark.asyncio
    async def test_search_no_match_returns_empty_page(
        self, client, auth_headers_admin
    ):
        r = await client.get(
            "/api/v1/users", headers=auth_headers_admin, params={"search": "no-such-prefix-xyz"}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["items"] == []
        assert body["total"] == 0

    @pytest.mark.asyncio
    async def test_list_requires_admin(self, client, auth_headers_analyst):
        r = await client.get("/api/v1/users", headers=auth_headers_analyst)
        assert r.status_code == 403, r.text


class TestGetUser:
    @pytest.mark.asyncio
    async def test_get_user_returns_payload_and_audits_view(
        self, client, auth_headers_admin, db_session
    ):
        u = await _make_user(db_session, "viewme@example.com")
        r = await client.get(f"/api/v1/users/{u.id}", headers=auth_headers_admin)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["email"] == "viewme@example.com"
        assert body["role"] == "viewer"
        assert "password" not in body

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "users.view")
                )
            ).scalars()
        )
        assert rows, "user view must be audited"
        assert rows[-1].details.get("target_user_id") == str(u.id)

    @pytest.mark.asyncio
    async def test_get_unknown_user_404(self, client, auth_headers_admin):
        r = await client.get(f"/api/v1/users/{uuid.uuid4()}", headers=auth_headers_admin)
        assert r.status_code == 404, r.text

    @pytest.mark.asyncio
    async def test_get_requires_admin(self, client, auth_headers_viewer, db_session):
        u = await _make_user(db_session, "viewerpeek@example.com")
        r = await client.get(f"/api/v1/users/{u.id}", headers=auth_headers_viewer)
        assert r.status_code == 403, r.text


class TestActivationThroughUpdate:
    """Activation has one path: ``PUT /users/{id}`` (RWI-04 / USR-15).

    ``PATCH .../toggle-active`` was a second writer of ``user.locked`` /
    ``user.unlocked`` with a different ``details`` shape, and the product never
    called it — so a SIEM rule written against the traffic matched only one of two
    routes doing the same thing. The tests below pin the surviving path, and the
    audit shape both directions share.
    """

    @pytest.mark.asyncio
    async def test_deactivating_a_user_is_audited_with_its_method(
        self, client, auth_headers_admin, db_session
    ):
        u = await _make_user(db_session, "lockme@example.com")
        r = await client.put(
            f"/api/v1/users/{u.id}", json={"is_active": False}, headers=auth_headers_admin
        )
        assert r.status_code == 200, r.text
        assert r.json()["is_active"] is False

        await db_session.refresh(u)
        assert u.is_active is False

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "user.locked")
                )
            ).scalars()
        )
        assert rows
        details = rows[-1].details
        assert details.get("method") == "api_update"
        assert details.get("target_user_id") == str(u.id)

    @pytest.mark.asyncio
    async def test_reactivating_a_user_clears_stale_lockout(
        self, client, auth_headers_admin, db_session
    ):
        from datetime import datetime, timedelta, timezone

        u = await _make_user(db_session, "revive-update@example.com", active=False)
        u.failed_login_attempts = 7
        u.locked_until = datetime.now(timezone.utc) + timedelta(minutes=10)
        await db_session.commit()

        r = await client.put(
            f"/api/v1/users/{u.id}", json={"is_active": True}, headers=auth_headers_admin
        )
        assert r.status_code == 200, r.text
        assert r.json()["is_active"] is True

        await db_session.refresh(u)
        assert u.failed_login_attempts == 0
        assert u.locked_until is None

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "user.unlocked")
                )
            ).scalars()
        )
        assert rows
        assert rows[-1].details.get("method") == "api_update"

    @pytest.mark.asyncio
    async def test_both_directions_share_one_audit_field_set(
        self, client, auth_headers_admin, db_session
    ):
        """A rule keyed on one direction must match the other (USR-15)."""
        locking = await _make_user(db_session, "shape-lock@example.com")
        reviving = await _make_user(db_session, "shape-unlock@example.com", active=False)
        await client.put(
            f"/api/v1/users/{locking.id}", json={"is_active": False}, headers=auth_headers_admin
        )
        await client.put(
            f"/api/v1/users/{reviving.id}", json={"is_active": True}, headers=auth_headers_admin
        )

        locked = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "user.locked")
                )
            ).scalars()
        )
        unlocked = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "user.unlocked")
                )
            ).scalars()
        )
        assert locked and unlocked
        assert set(locked[-1].details) == set(unlocked[-1].details)

    @pytest.mark.asyncio
    async def test_deactivating_a_second_admin_succeeds_while_one_remains(
        self, client, auth_headers_admin, db_session
    ):
        u = await _make_user(db_session, "second-admin@example.com", role="admin")
        r = await client.put(
            f"/api/v1/users/{u.id}", json={"is_active": False}, headers=auth_headers_admin
        )
        assert r.status_code == 200, r.text
        assert r.json()["is_active"] is False

    @pytest.mark.asyncio
    async def test_requires_admin(self, client, auth_headers_analyst, db_session):
        u = await _make_user(db_session, "update-rbac@example.com")
        r = await client.put(
            f"/api/v1/users/{u.id}", json={"is_active": False}, headers=auth_headers_analyst
        )
        assert r.status_code == 403, r.text


class TestLastAdminConcurrencyPostgres:
    @pytest.mark.asyncio
    async def test_concurrent_admin_membership_changes_keep_one_active_admin(
        self, client, db_session, auth_headers_admin, test_admin
    ):
        if db_session.get_bind().dialect.name != "postgresql":
            pytest.skip("last-admin serialization requires PostgreSQL row locks")

        import asyncio
        from httpx import ASGITransport, AsyncClient
        from app.api import deps
        from app.core import database
        from app.main import app

        # Keep the existing fixture admin as the one that must survive; one
        # concurrent operation creates an admin while another tries demoting it.
        original = db_session
        sessions = []

        async def isolated_db():
            async with database.AsyncSessionLocal() as session:
                sessions.append(session)
                yield session

        app.dependency_overrides[deps.get_db] = isolated_db
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as race_client:
                first_result, second_result = await asyncio.gather(
                    race_client.post(
                        "/api/v1/users",
                        headers=auth_headers_admin,
                        json={"email": "concurrent-new-admin@example.com", "password": PASSWORD, "role": "admin"},
                    ),
                    race_client.put(
                        f"/api/v1/users/{test_admin.id}",
                        headers=auth_headers_admin,
                        json={"role": "viewer"},
                    ),
                )
        finally:
            app.dependency_overrides.pop(deps.get_db, None)
            for session in sessions:
                await session.close()

        assert first_result.status_code == 201, first_result.text
        assert second_result.status_code in {200, 409}, second_result.text
        await original.refresh(test_admin)
        admins = (
            await original.execute(
                select(User.id).where(User.role == "admin", User.is_active.is_(True))
            )
        ).scalars().all()
        assert admins
        if second_result.status_code == 200:
            assert len(admins) == 1


class TestUpdateDeleteNotFoundBranches:
    @pytest.mark.asyncio
    async def test_update_unknown_user_404(self, client, auth_headers_admin):
        r = await client.put(
            f"/api/v1/users/{uuid.uuid4()}",
            headers=auth_headers_admin,
            json={"full_name": "Nobody"},
        )
        assert r.status_code == 404, r.text

    @pytest.mark.asyncio
    async def test_delete_unknown_user_404(self, client, auth_headers_admin):
        r = await client.delete(f"/api/v1/users/{uuid.uuid4()}", headers=auth_headers_admin)
        assert r.status_code == 404, r.text

    @pytest.mark.asyncio
    async def test_cannot_deactivate_own_account_via_put(
        self, client, auth_headers_admin, test_admin
    ):
        """PUT is_active=false on yourself must be rejected (409)."""
        r = await client.put(
            f"/api/v1/users/{test_admin.id}",
            headers=auth_headers_admin,
            json={"is_active": False},
        )
        assert r.status_code == 409, r.text
        assert "deactivate your own account" in r.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_update_last_admin_guard_branch(
        self, db_session, test_admin
    ):
        """Unit-level pin: the PUT last-admin deactivation guard.

        The branch is unreachable over HTTP: the caller is always an active
        admin, so deactivating a *different* admin always leaves at least one
        (the caller). Exercise the guard directly with an inactive acting admin
        so the target is the only active one.
        """
        from app.api.v1.routers.users import update_user
        from app.core.exceptions import ConflictException
        from app.schemas.user import UserUpdate

        target = await _make_user(db_session, "sole-admin-put@example.com", role="admin")
        test_admin.is_active = False
        await db_session.commit()

        payload = UserUpdate.model_validate({"is_active": False})
        with pytest.raises(ConflictException, match="(?i)last active admin"):
            await update_user(
                request=None,
                user_id=target.id,
                payload=payload,
                db=db_session,
                current_user=test_admin,
            )
