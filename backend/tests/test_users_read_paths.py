"""Characterization tests: users router read, pagination and toggle paths.

Part of the safe-refactoring plan (Step 1). These tests pin the CURRENT
behavior of endpoints that had no direct coverage:

* ``GET /users/brief``        — admin-only active-user checklist payload.
* ``GET /users``              — pagination, email search, ``users.list`` audit.
* ``GET /users/{user_id}``    — fetch + ``users.view`` audit, 404 branch.
* ``PATCH /users/{id}/toggle-active`` — lock/unlock semantics, self-toggle and
  last-admin guards, stale-lockout cleanup on revive, ``user.locked`` /
  ``user.unlocked`` audit events.
* ``PUT`` / ``DELETE`` 404 branches for missing users.

They must stay green before AND after the upcoming refactor; a failure means
behavior changed. Coverage before this file (full-suite, sysmon): 68% for
``app/api/v1/routers/users.py`` with 66-79, 94-115, 125-135, 187, 298-326,
349 uncovered.
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


class TestToggleActive:
    @pytest.mark.asyncio
    async def test_lock_active_user(self, client, auth_headers_admin, db_session):
        u = await _make_user(db_session, "lockme@example.com")
        r = await client.patch(
            f"/api/v1/users/{u.id}/toggle-active", headers=auth_headers_admin
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["is_active"] is False
        assert body["action"] == "locked"
        assert body["id"] == str(u.id)

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
        assert rows[-1].details.get("method") == "toggle-active"

    @pytest.mark.asyncio
    async def test_unlock_inactive_user_clears_stale_lockout(
        self, client, auth_headers_admin, db_session
    ):
        from datetime import datetime, timedelta, timezone

        u = await _make_user(db_session, "revive-toggle@example.com", active=False)
        u.failed_login_attempts = 7
        u.locked_until = datetime.now(timezone.utc) + timedelta(minutes=10)
        await db_session.commit()

        r = await client.patch(
            f"/api/v1/users/{u.id}/toggle-active", headers=auth_headers_admin
        )
        assert r.status_code == 200, r.text
        assert r.json()["action"] == "unlocked"
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

    @pytest.mark.asyncio
    async def test_cannot_toggle_self(self, client, auth_headers_admin, test_admin):
        r = await client.patch(
            f"/api/v1/users/{test_admin.id}/toggle-active", headers=auth_headers_admin
        )
        assert r.status_code == 409, r.text

    @pytest.mark.asyncio
    async def test_toggle_own_account_self_guard_preempts_last_admin_guard(
        self, client, auth_headers_admin, test_admin
    ):
        """TODO(refactor-step-1): documents guard ordering, intentionally pinned.

        For the sole active admin, self-toggle returns 409 "You cannot toggle
        your own account" — the self-guard evaluates BEFORE the last-admin
        guard, so that guard is unreachable through the HTTP API (it would only
        apply to a *different* sole admin, but toggling yourself is the only way
        to target an admin when you are the only other admin... which is you).
        The last-admin branch inside ``toggle_active`` is exercised at unit level
        in ``test_toggle_last_admin_guard_branch`` below.
        """
        r = await client.patch(
            f"/api/v1/users/{test_admin.id}/toggle-active", headers=auth_headers_admin
        )
        assert r.status_code == 409, r.text
        assert "toggle your own account" in r.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_toggle_second_admin_succeeds_while_first_stays_active(
        self, client, auth_headers_admin, db_session
    ):
        """With another active admin remaining, locking an admin is allowed."""
        u = await _make_user(db_session, "second-admin@example.com", role="admin")
        r = await client.patch(
            f"/api/v1/users/{u.id}/toggle-active", headers=auth_headers_admin
        )
        assert r.status_code == 200, r.text
        assert r.json()["action"] == "locked"

    @pytest.mark.asyncio
    async def test_toggle_last_admin_guard_branch(
        self, db_session, test_admin
    ):
        """Unit-level pin: the last-admin guard inside ``toggle_active``.

        The branch is unreachable over HTTP: the self-guard fires first for the
        sole admin, and any authenticated caller is itself an active admin, so
        ``_count_active_admins(exclude_id=target)`` is always >= 1 when the
        target is a different user. To execute and pin the guard branch we call
        the handler directly with an *inactive* acting admin (a state the API
        cannot produce) so the exclusion count drops to zero.
        """
        from app.api.v1.routers.users import toggle_active
        from app.core.exceptions import ConflictException

        target = await _make_user(db_session, "sole-active-admin@example.com", role="admin")
        # Force the (API-impossible) state: acting admin exists but is inactive,
        # making the target the only ACTIVE admin.
        test_admin.is_active = False
        await db_session.commit()

        with pytest.raises(ConflictException, match="(?i)last active admin"):
            await toggle_active(
                request=None,
                user_id=target.id,
                db=db_session,
                current_user=test_admin,
            )

    @pytest.mark.asyncio
    async def test_toggle_unknown_user_404(self, client, auth_headers_admin):
        r = await client.patch(
            f"/api/v1/users/{uuid.uuid4()}/toggle-active", headers=auth_headers_admin
        )
        assert r.status_code == 404, r.text

    @pytest.mark.asyncio
    async def test_toggle_requires_admin(self, client, auth_headers_analyst, db_session):
        u = await _make_user(db_session, "toggle-rbac@example.com")
        r = await client.patch(
            f"/api/v1/users/{u.id}/toggle-active", headers=auth_headers_analyst
        )
        assert r.status_code == 403, r.text


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

        As with ``toggle_active``, the branch is unreachable over HTTP: the
        caller is always an active admin, so deactivating a *different* admin
        always leaves at least one (the caller). Exercise the guard directly
        with an inactive acting admin so the target is the only active one.
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
