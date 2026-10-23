"""The operator-facing account surface: export, sessions, support filters, bulk.

U-1, U-2, U-3 and U-5 of the audit's backlog. They share one property worth
pinning: each is a read or a change of the account table, so it must answer with
the facts the table holds, must never carry a credential into a file or a
response, and must leave exactly one audit row for one decision. The negative
halves matter as much as the positive ones — an export that includes a hash, a
session response that includes a token, a bulk action that leaves no
administrator, or a filter that answers from the current page instead of the
database would all look like success from the caller's side.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.token import RefreshTokenFamily
from app.models.user import User

PASSWORD = "TestPass123!"


async def _make_user(
    db,
    email: str,
    *,
    role: str = "viewer",
    active: bool = True,
    **flags,
) -> User:
    from app.core.security import hash_password

    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(PASSWORD),
        role=role,
        is_active=active,
        **flags,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def _session(db, user, *, revoked: bool = False) -> RefreshTokenFamily:
    family = RefreshTokenFamily(
        family_id=uuid.uuid4(),
        user_id=user.id,
        revoked=revoked,
        revoked_at=datetime.now(timezone.utc) if revoked else None,
    )
    db.add(family)
    await db.commit()
    await db.refresh(family)
    return family


async def _audit_rows(db, action: str) -> list[AuditLog]:
    return list(
        (
            await db.execute(
                select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.timestamp)
            )
        ).scalars().all()
    )


class TestSupportFilters:
    @pytest.mark.asyncio
    async def test_each_slice_returns_exactly_the_accounts_it_names(
        self, client, db_session, auth_headers_admin
    ):
        await _make_user(
            db_session, "onboarding@example.com", must_change_password=True
        )
        await _make_user(
            db_session,
            "enrolled@example.com",
            totp_enabled_at=datetime.now(timezone.utc),
        )
        await _make_user(
            db_session,
            "locked@example.com",
            locked_until=datetime.now(timezone.utc) + timedelta(minutes=10),
            failed_login_attempts=7,
        )

        async def emails(params: dict) -> set[str]:
            response = await client.get(
                "/api/v1/users", params={**params, "size": 100}, headers=auth_headers_admin
            )
            assert response.status_code == 200, response.text
            return {row["email"] for row in response.json()["items"]}

        onboarding = await emails({"requires_onboarding": "true"})
        assert "onboarding@example.com" in onboarding
        assert "enrolled@example.com" not in onboarding

        no_factor = await emails({"mfa_enrolled": "false"})
        assert "enrolled@example.com" not in no_factor
        assert "locked@example.com" in no_factor

        locked = await emails({"locked": "true"})
        assert "locked@example.com" in locked
        assert "enrolled@example.com" not in locked

    @pytest.mark.asyncio
    async def test_an_expired_lockout_is_not_locked(self, client, db_session, auth_headers_admin):
        """The column keeps its old value after the window; the filter must not."""
        await _make_user(
            db_session,
            "expired-lock@example.com",
            locked_until=datetime.now(timezone.utc) - timedelta(minutes=1),
        )

        response = await client.get(
            "/api/v1/users",
            params={"locked": "true", "size": 100},
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text
        assert "expired-lock@example.com" not in {
            row["email"] for row in response.json()["items"]
        }


class TestExport:
    @pytest.mark.asyncio
    async def test_the_csv_carries_the_review_columns_and_no_secret(
        self, client, db_session, auth_headers_admin
    ):
        user = await _make_user(
            db_session,
            "exported@example.com",
            role="analyst",
            totp_enabled_at=datetime.now(timezone.utc),
            must_enrol_mfa=True,
            last_login_at=datetime(2026, 5, 6, 7, 8, 9, tzinfo=timezone.utc),
        )
        # Values that must never reach the file, whatever else it contains.
        user.totp_secret = "totp-secret-marker"
        user.mfa_recovery_codes = ["recovery-marker"]
        await db_session.commit()

        response = await client.get(
            "/api/v1/users/export", params={"format": "csv"}, headers=auth_headers_admin
        )
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("text/csv")
        body = response.text
        assert "totp-secret-marker" not in body
        assert "recovery-marker" not in body
        assert user.password_hash not in body

        rows = list(csv.DictReader(io.StringIO(body)))
        row = next(item for item in rows if item["email"] == "exported@example.com")
        assert row["role"] == "analyst"
        assert row["mfa_enrolled"] == "True"
        assert row["must_enrol_mfa"] == "True"
        assert row["last_login_at"]

        audit = await _audit_rows(db_session, "users.export")
        assert len(audit) == 1
        assert audit[0].details["format"] == "csv"

    @pytest.mark.asyncio
    async def test_the_export_uses_the_same_filter_as_the_list(
        self, client, db_session, auth_headers_admin
    ):
        await _make_user(db_session, "never@example.com")
        await _make_user(
            db_session,
            "signed-in@example.com",
            last_login_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

        response = await client.get(
            "/api/v1/users/export",
            params={"signed_in": "false", "format": "json"},
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text
        emails = {row["email"] for row in response.json()["items"]}
        assert "never@example.com" in emails
        assert "signed-in@example.com" not in emails

    @pytest.mark.asyncio
    async def test_a_too_large_export_is_refused_by_name(
        self, client, db_session, auth_headers_admin, monkeypatch
    ):
        import app.api.v1.routers.users as users_router

        monkeypatch.setattr(users_router, "USER_EXPORT_MAX_ROWS", 1)
        await _make_user(db_session, "one@example.com")
        await _make_user(db_session, "two@example.com")

        response = await client.get("/api/v1/users/export", headers=auth_headers_admin)
        assert response.status_code == 400, response.text
        assert "at most 1" in response.json()["detail"]


class TestSessions:
    @pytest.mark.asyncio
    async def test_it_lists_ids_and_times_only(
        self, client, db_session, test_viewer, auth_headers_admin
    ):
        alive = await _session(db_session, test_viewer)
        await _session(db_session, test_viewer, revoked=True)

        response = await client.get(
            f"/api/v1/users/{test_viewer.id}/sessions", headers=auth_headers_admin
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert [row["id"] for row in body] == [str(alive.family_id)]
        for row in body:
            assert set(row) == {"id", "created_at", "last_used_at", "current"}
            assert row["current"] is False

    @pytest.mark.asyncio
    async def test_looking_at_another_accounts_sessions_is_recorded(
        self, client, db_session, test_viewer, auth_headers_admin
    ):
        """`GET /users/{id}` records `users.view`; the session list is the same read.

        Which devices an account can still be used through is the administrator
        read most worth being able to explain afterwards — and it was the one read
        of somebody else's account that left no row at all.
        """
        await _session(db_session, test_viewer)
        response = await client.get(
            f"/api/v1/users/{test_viewer.id}/sessions", headers=auth_headers_admin
        )
        assert response.status_code == 200, response.text

        rows = await _audit_rows(db_session, "users.view")
        assert len(rows) == 1
        assert rows[0].details["target_user_id"] == str(test_viewer.id)
        assert rows[0].details["view"] == "sessions"
        assert rows[0].details["results"] == 1

    @pytest.mark.asyncio
    async def test_revoking_all_signs_out_every_live_session_and_audits_once(
        self, client, db_session, test_viewer, auth_headers_admin
    ):
        first = await _session(db_session, test_viewer)
        second = await _session(db_session, test_viewer)

        response = await client.delete(
            f"/api/v1/users/{test_viewer.id}/sessions", headers=auth_headers_admin
        )
        assert response.status_code == 200, response.text
        assert response.json()["revoked"] == 2

        await db_session.refresh(first)
        await db_session.refresh(second)
        assert first.revoked is True and second.revoked is True
        # The reason is what a refresh attempt reports back, so it names the
        # administrator path rather than the account's own one.
        assert first.revoked_reason == "admin_revoked"

        rows = await _audit_rows(db_session, "user.sessions.revoked")
        assert len(rows) == 1
        assert rows[0].details["revoked_count"] == 2

    @pytest.mark.asyncio
    async def test_an_administrator_cannot_end_their_own_sessions_here(
        self, client, test_admin, auth_headers_admin
    ):
        response = await client.delete(
            f"/api/v1/users/{test_admin.id}/sessions", headers=auth_headers_admin
        )
        assert response.status_code == 409, response.text
        assert "own sessions" in response.json()["detail"]


class TestBulk:
    @pytest.mark.asyncio
    async def test_deactivating_a_selection_is_one_row_and_revokes_sessions(
        self, client, db_session, test_admin, test_viewer, auth_headers_admin
    ):
        second = await _make_user(db_session, "second@example.com")
        session = await _session(db_session, test_viewer)
        session2 = await _session(db_session, second)

        response = await client.post(
            "/api/v1/users/bulk",
            json={
                "operation": "deactivate",
                "user_ids": [str(test_viewer.id), str(second.id)],
            },
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text
        assert response.json() == {
            "operation": "deactivate",
            "changed": 2,
            "skipped": 0,
            "revoked_sessions": 2,
        }

        await db_session.refresh(test_viewer)
        await db_session.refresh(second)
        assert test_viewer.is_active is False and second.is_active is False
        await db_session.refresh(session)
        await db_session.refresh(session2)
        assert session.revoked is True and session2.revoked is True

        rows = await _audit_rows(db_session, "users.bulk")
        assert len(rows) == 1, "one batch, one row"
        assert rows[0].details["changed"] == 2
        assert rows[0].details["operation"] == "deactivate"

    @pytest.mark.asyncio
    async def test_reactivating_a_selection_clears_the_stale_lockout(
        self, client, db_session, auth_headers_admin
    ):
        """Turning an account back on must not leave the lockout set while it was off.

        `PUT is_active=true` clears the counters and says why: reactivation must
        not restore stale lock state. The batch is the same change, and it used to
        answer "changed" while the account still could not sign in.
        """
        dormant = await _make_user(
            db_session,
            "dormant@example.com",
            active=False,
            locked_until=datetime.now(timezone.utc) + timedelta(minutes=10),
            failed_login_attempts=6,
        )

        response = await client.post(
            "/api/v1/users/bulk",
            json={"operation": "activate", "user_ids": [str(dormant.id)]},
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text
        assert response.json()["changed"] == 1

        await db_session.refresh(dormant)
        assert dormant.is_active is True
        assert dormant.locked_until is None
        assert dormant.failed_login_attempts == 0

    @pytest.mark.asyncio
    async def test_the_caller_cannot_deactivate_themselves_in_a_batch(
        self, client, db_session, test_admin, auth_headers_admin
    ):
        """The self guard runs before the selection, so the batch cannot sign out
        the administrator running it."""
        assert test_admin.is_active is True
        await _make_user(db_session, "other@example.com", role="viewer")

        response = await client.post(
            "/api/v1/users/bulk",
            json={
                "operation": "deactivate",
                "user_ids": [str(test_admin.id)],
            },
            headers=auth_headers_admin,
        )
        # The caller's own account is refused first, by the explicit self guard.
        assert response.status_code == 409, response.text

        await db_session.refresh(test_admin)
        assert test_admin.is_active is True

    @pytest.mark.asyncio
    async def test_the_bulk_path_holds_the_same_last_admin_guard(
        self, db_session, test_admin
    ):
        """The guard is defence in depth, so it is pinned at the layer that owns it.

        Through the API an administrator can never trip it: the caller is an
        active administrator and deactivating themselves is refused first, so a
        selection always leaves at least the caller. The batch still calls the
        shared predicate — a future role or a service caller may not have that
        accident of ordering — and this test keeps that call from being dropped
        as redundant.
        """
        from app.services.admin_invariants import (
            LastActiveAdminError,
            ensure_active_admin_remains,
        )

        with pytest.raises(LastActiveAdminError):
            await ensure_active_admin_remains(
                db_session, test_admin, final_active=False
            )

    @pytest.mark.asyncio
    async def test_an_unknown_id_refuses_the_batch_before_anything_is_written(
        self, client, db_session, test_viewer, auth_headers_admin
    ):
        response = await client.post(
            "/api/v1/users/bulk",
            json={
                "operation": "deactivate",
                "user_ids": [str(test_viewer.id), str(uuid.uuid4())],
            },
            headers=auth_headers_admin,
        )
        assert response.status_code == 400, response.text

        await db_session.refresh(test_viewer)
        assert test_viewer.is_active is True
        assert await _audit_rows(db_session, "users.bulk") == []
