"""Integration tests for the user-management lifecycle.

Covers the business process end to end: creation (RBAC, validation,
normalization), editing (email conflicts, last-admin guards, password reset
semantics), and permanent deletion (refresh families removed, dependent
reports preserved via ON DELETE SET NULL, email freed).
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.report import Report
from app.models.token import RefreshTokenFamily
from app.models.user import User

PASSWORD = "InitialPass123!"
NEW_PASSWORD = "RotatedPass456!"


async def _login(client, email: str, password: str):
    return await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )


async def _create_user(client, headers, email: str, *, password: str = PASSWORD, role: str = "viewer"):
    return await client.post(
        "/api/v1/users",
        headers=headers,
        json={"email": email, "password": password, "role": role},
    )


class TestUserCRUD:
    @pytest.mark.asyncio
    async def test_user_endpoints_require_admin(
        self, client, auth_headers_analyst, auth_headers_viewer
    ):
        for headers in (auth_headers_analyst, auth_headers_viewer):
            r = await client.get("/api/v1/users", headers=headers)
            assert r.status_code == 403, r.text
            r = await client.post(
                "/api/v1/users",
                headers=headers,
                json={"email": "x@example.com", "password": PASSWORD, "role": "viewer"},
            )
            assert r.status_code == 403, r.text

    @pytest.mark.asyncio
    async def test_create_user_normalizes_email_and_trims_name(
        self, client, auth_headers_admin, db_session
    ):
        r = await _create_user(
            client,
            auth_headers_admin,
            "  New.User@Example.COM ",
            role="analyst",
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["email"] == "new.user@example.com"
        assert body["role"] == "analyst"
        assert body["is_active"] is True
        assert "password" not in body

        # The creation must be recorded in the audit trail.
        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "user.created")
                )
            ).scalars().all()
        )
        assert rows
        assert rows[-1].details.get("target_email") == "new.user@example.com"

    @pytest.mark.asyncio
    async def test_create_user_weak_password_422(self, client, auth_headers_admin):
        r = await _create_user(client, auth_headers_admin, "weakpw@example.com", password="short")
        assert r.status_code == 422, r.text

    @pytest.mark.asyncio
    async def test_create_duplicate_email_409(self, client, auth_headers_admin, db_session):
        r = await _create_user(client, auth_headers_admin, "dup@example.com")
        assert r.status_code == 201, r.text
        _ = db_session  # noqa: F841 (kept for readability)
        r = await _create_user(client, auth_headers_admin, "DUP@example.com")
        assert r.status_code == 409, r.text

    @pytest.mark.asyncio
    async def test_unknown_password_field_is_ignored(
        self, client, auth_headers_admin, db_session
    ):
        """Regression guard: `password` (not `new_password`) must NOT rotate the hash."""
        r = await _create_user(client, auth_headers_admin, "legacy@example.com")
        target_id = r.json()["id"]

        up = await client.put(
            f"/api/v1/users/{target_id}",
            headers=auth_headers_admin,
            json={"full_name": "Renamed", "password": NEW_PASSWORD},
        )
        assert up.status_code == 200, up.text

        # Old password still valid, attempted rotation ignored.
        assert (await _login(client, "legacy@example.com", PASSWORD)).status_code == 200
        assert (await _login(client, "legacy@example.com", NEW_PASSWORD)).status_code == 401

    @pytest.mark.asyncio
    async def test_update_normalizes_email_name_and_role(self, client, auth_headers_admin, db_session):
        r = await _create_user(client, auth_headers_admin, "mutation-target@example.com")
        target_id = r.json()["id"]

        updated = await client.put(
            f"/api/v1/users/{target_id}",
            headers=auth_headers_admin,
            json={
                "email": "  Renamed.Target@Example.COM ",
                "full_name": "  Target User  ",
                "role": "analyst",
            },
        )
        assert updated.status_code == 200, updated.text
        body = updated.json()
        assert body["email"] == "renamed.target@example.com"
        assert body["full_name"] == "Target User"
        assert body["role"] == "analyst"

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "user.updated")
                )
            ).scalars().all()
        )
        assert rows
        assert set(rows[-1].details["changed_fields"]) == {"email", "full_name", "role"}

    @pytest.mark.asyncio
    async def test_self_demote_allowed_when_another_admin_remains(
        self, client, auth_headers_admin, test_admin
    ):
        await _create_user(client, auth_headers_admin, "remaining-admin@example.com", role="admin")

        updated = await client.put(
            f"/api/v1/users/{test_admin.id}",
            headers=auth_headers_admin,
            json={"role": "analyst"},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["role"] == "analyst"

    @pytest.mark.asyncio
    async def test_delete_inactive_admin_is_allowed(self, client, auth_headers_admin, db_session):
        r = await _create_user(
            client,
            auth_headers_admin,
            "inactive-admin@example.com",
            role="admin",
        )
        target_id = uuid.UUID(r.json()["id"])
        user = (
            await db_session.execute(select(User).where(User.id == target_id))
        ).scalar_one()
        user.is_active = False
        await db_session.commit()

        deleted = await client.delete(
            f"/api/v1/users/{target_id}", headers=auth_headers_admin
        )
        assert deleted.status_code == 204, deleted.text
        assert (
            await db_session.execute(select(User).where(User.id == target_id))
        ).scalar_one_or_none() is None

    @pytest.mark.asyncio
    async def test_self_demote_last_admin_409(self, client, auth_headers_admin, test_admin):
        r = await client.put(
            f"/api/v1/users/{test_admin.id}",
            headers=auth_headers_admin,
            json={"role": "viewer"},
        )
        assert r.status_code == 409, r.text

    @pytest.mark.asyncio
    async def test_demote_and_deactivate_second_admin_ok(
        self, client, auth_headers_admin
    ):
        r = await _create_user(client, auth_headers_admin, "admin2@example.com", role="admin")
        assert r.status_code == 201, r.text
        second_id = r.json()["id"]

        r = await client.put(
            f"/api/v1/users/{second_id}",
            headers=auth_headers_admin,
            json={"role": "analyst"},
        )
        assert r.status_code == 200, r.text

        r = await client.put(
            f"/api/v1/users/{second_id}",
            headers=auth_headers_admin,
            json={"is_active": False},
        )
        assert r.status_code == 200, r.text
        assert r.json()["is_active"] is False

    @pytest.mark.asyncio
    async def test_cannot_delete_own_account(self, client, auth_headers_admin, test_admin):
        r = await client.delete(f"/api/v1/users/{test_admin.id}", headers=auth_headers_admin)
        assert r.status_code == 409, r.text


class TestPasswordResetSemantics:
    @pytest.mark.asyncio
    async def test_reset_clears_lock_and_revokes_refresh_families(
        self, client, auth_headers_admin, db_session
    ):
        # Create the target account and sign in to establish a refresh family.
        r = await _create_user(client, auth_headers_admin, "resetme@example.com")
        target_id = uuid.UUID(r.json()["id"])
        login = await _login(client, "resetme@example.com", PASSWORD)
        assert login.status_code == 200, login.text
        stolen_refresh = login.cookies.get("opendrp_refresh")

        # Simulate brute-force lockout state.
        user = (
            await db_session.execute(select(User).where(User.id == target_id))
        ).scalar_one()
        user.failed_login_attempts = 5
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        await db_session.commit()

        # Admin rotates the password via the API (correct snake_case field).
        up = await client.put(
            f"/api/v1/users/{target_id}",
            headers=auth_headers_admin,
            json={"new_password": NEW_PASSWORD},
        )
        assert up.status_code == 200, up.text
        assert up.json()["is_active"] is True

        # The pre-reset refresh family must be revoked with a recorded reason.
        # (Checked before any new login: a successful login mints a fresh family.)
        families = list(
            (
                await db_session.execute(
                    select(RefreshTokenFamily).where(RefreshTokenFamily.user_id == target_id)
                )
            ).scalars().all()
        )
        assert len(families) == 1
        # Instances are cached in the session (expire_on_commit=False); force a
        # DB re-read so the bulk revocation performed by the router is visible.
        await db_session.refresh(families[0])
        assert families[0].revoked is True
        assert families[0].revoked_reason == "password_reset"

        # The stolen refresh token can no longer mint a session.
        reuse = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": stolen_refresh}
        )
        assert reuse.status_code == 401, reuse.text
        assert "revoked" in reuse.json()["detail"].lower()

        # Lock state cleared: new password works immediately, old one does not.
        assert (await _login(client, "resetme@example.com", NEW_PASSWORD)).status_code == 200
        assert (await _login(client, "resetme@example.com", PASSWORD)).status_code == 401

        # Reset is recorded in the audit trail.
        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "user.password_reset")
                )
            ).scalars().all()
        )
        assert rows
        assert rows[-1].details.get("refresh_families_revoked") == 1

    @pytest.mark.asyncio
    async def test_reactivation_clears_stale_lock(
        self, client, auth_headers_admin, db_session
    ):
        r = await _create_user(client, auth_headers_admin, "revive@example.com")
        target_id = uuid.UUID(r.json()["id"])

        user = (
            await db_session.execute(select(User).where(User.id == target_id))
        ).scalar_one()
        user.is_active = False
        user.failed_login_attempts = 5
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
        await db_session.commit()

        r = await client.put(
            f"/api/v1/users/{target_id}",
            headers=auth_headers_admin,
            json={"is_active": True},
        )
        assert r.status_code == 200, r.text
        assert r.json()["is_active"] is True

        # Force a DB re-read (session keeps expire_on_commit=False).
        await db_session.refresh(user)
        assert user.is_active is True
        assert user.failed_login_attempts == 0
        assert user.locked_until is None


class TestDeleteUser:
    @pytest.mark.asyncio
    async def test_delete_purges_user_and_frees_email(
        self, client, auth_headers_admin, db_session
    ):
        r = await _create_user(client, auth_headers_admin, "gone@example.com")
        target_id = uuid.UUID(r.json()["id"])
        login = await _login(client, "gone@example.com", PASSWORD)
        assert login.status_code == 200

        r = await client.delete(f"/api/v1/users/{target_id}", headers=auth_headers_admin)
        assert r.status_code == 204, r.text

        # Row + refresh families are gone; the email can be re-created.
        user = (
            await db_session.execute(select(User).where(User.id == target_id))
        ).scalar_one_or_none()
        assert user is None
        families = list(
            (
                await db_session.execute(
                    select(RefreshTokenFamily).where(RefreshTokenFamily.user_id == target_id)
                )
            ).scalars().all()
        )
        assert families == []

        r = await _create_user(client, auth_headers_admin, "gone@example.com")
        assert r.status_code == 201, r.text

        rows = list(
            (
                await db_session.execute(
                    select(AuditLog).where(AuditLog.action == "user.deleted")
                )
            ).scalars().all()
        )
        assert rows
        assert rows[-1].details.get("target_email") == "gone@example.com"

    @pytest.mark.asyncio
    async def test_delete_keeps_reports_and_sets_created_by_null(
        self, client, auth_headers_admin, db_session
    ):
        r = await _create_user(client, auth_headers_admin, "reporter@example.com")
        target_id = uuid.UUID(r.json()["id"])

        report = Report(
            report_name="Quarterly DRP",
            created_by=target_id,
            file_path="/tmp/report.pdf",
            status="done",
        )
        db_session.add(report)
        await db_session.commit()

        r = await client.delete(f"/api/v1/users/{target_id}", headers=auth_headers_admin)
        assert r.status_code == 204, r.text

        # The DB-level ON DELETE SET NULL must keep the report row and null its
        # creator. Read through raw SQL: the session keeps expire_on_commit=False
        # and its identity-map snapshot of `report` predates the delete.
        from sqlalchemy import text

        value = (
            await db_session.execute(
                text("SELECT created_by FROM reports WHERE id = :i"),
                {"i": str(report.id)},
            )
        ).scalar_one_or_none()
        assert value is None
        assert report.report_name == "Quarterly DRP"

    @pytest.mark.asyncio
    async def test_delete_second_admin_ok_but_single_admin_guarded(
        self, client, auth_headers_admin, test_admin
    ):
        r = await _create_user(client, auth_headers_admin, "admin2@example.com", role="admin")
        second_id = uuid.UUID(r.json()["id"])

        r = await client.delete(f"/api/v1/users/{second_id}", headers=auth_headers_admin)
        assert r.status_code == 204, r.text

        # Re-check: the acting admin is still the only one, so self-delete stays blocked.
        r = await client.delete(f"/api/v1/users/{test_admin.id}", headers=auth_headers_admin)
        assert r.status_code == 409, r.text
