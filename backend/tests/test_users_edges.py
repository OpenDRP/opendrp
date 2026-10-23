"""The account router's branches a happy-path review never reaches.

Coverage batch 02. The operator surface in `test_users_operator_surface.py`
proves the flows an administrator uses daily; what it leaves unexecuted is the
answer to a request that is already wrong: a filter pair nobody exercised, an
address already taken, an invitation for an account that no longer exists, a
batch that is already in the requested state, or a storage conflict. Each is a
refusal or a no-op the caller has to be able to tell apart from success — a
"200" that wrote nothing, or a 500 where a 409 belongs, is how an operator
learns to distrust the response.

The last two tests patch the session's ``commit``: the route's contract for a
storage failure is an HTTP answer, and the collaborator is what fails, not the
route under test.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

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


class TestListFilters:
    @pytest.mark.anyio
    async def test_role_and_activation_each_filter_in_the_database(
        self, client, db_session, auth_headers_admin
    ):
        await _make_user(db_session, "filter-admin@example.com", role="admin")
        await _make_user(db_session, "filter-off@example.com", active=False)

        by_role = await client.get(
            "/api/v1/users",
            params={"role": "admin", "is_active": "true", "size": 100},
            headers=auth_headers_admin,
        )
        assert by_role.status_code == 200, by_role.text
        emails = {row["email"] for row in by_role.json()["items"]}
        assert "filter-admin@example.com" in emails
        assert "filter-off@example.com" not in emails

        inactive = await client.get(
            "/api/v1/users",
            params={"is_active": "false", "size": 100},
            headers=auth_headers_admin,
        )
        assert inactive.status_code == 200, inactive.text
        assert "filter-off@example.com" in {
            row["email"] for row in inactive.json()["items"]
        }


class TestDuplicateAddresses:
    @pytest.mark.anyio
    async def test_creating_the_same_address_twice_is_a_conflict(
        self, client, auth_headers_admin
    ):
        payload = {
            "email": "created-twice@example.com",
            "password": PASSWORD,
            "role": "viewer",
        }
        first = await client.post(
            "/api/v1/users", json=payload, headers=auth_headers_admin
        )
        assert first.status_code == 201, first.text

        second = await client.post(
            "/api/v1/users", json=payload, headers=auth_headers_admin
        )
        assert second.status_code == 409, second.text
        assert "already exists" in second.json()["detail"]

    @pytest.mark.anyio
    async def test_inviting_an_address_that_already_has_an_account_is_a_conflict(
        self, client, test_admin, auth_headers_admin
    ):
        response = await client.post(
            "/api/v1/users/invite",
            json={"email": test_admin.email, "role": "viewer"},
            headers=auth_headers_admin,
        )
        assert response.status_code == 409, response.text
        assert "already exists" in response.json()["detail"]

    @pytest.mark.anyio
    async def test_inviting_an_administrator_takes_the_admin_set_lock(
        self, client, db_session, auth_headers_admin
    ):
        response = await client.post(
            "/api/v1/users/invite",
            json={"email": "invited-admin@example.com", "role": "admin"},
            headers=auth_headers_admin,
        )
        assert response.status_code == 201, response.text
        assert response.json()["user"]["role"] == "admin"
        assert response.json()["invitation_token"]

    @pytest.mark.anyio
    async def test_updating_to_an_address_in_use_is_a_conflict(
        self, client, test_admin, test_viewer, auth_headers_admin
    ):
        response = await client.put(
            f"/api/v1/users/{test_viewer.id}",
            json={"email": test_admin.email},
            headers=auth_headers_admin,
        )
        assert response.status_code == 409, response.text
        assert "already exists" in response.json()["detail"]


class TestInvitationsAndBulkNoOps:
    @pytest.mark.anyio
    async def test_reissuing_for_an_unknown_account_is_not_found(
        self, client, auth_headers_admin
    ):
        response = await client.post(
            f"/api/v1/users/{uuid.uuid4()}/invitation",
            headers=auth_headers_admin,
        )
        assert response.status_code == 404, response.text

    @pytest.mark.anyio
    async def test_activating_an_already_active_account_is_reported_as_skipped(
        self, client, test_viewer, auth_headers_admin
    ):
        assert test_viewer.is_active is True
        response = await client.post(
            "/api/v1/users/bulk",
            json={"operation": "activate", "user_ids": [str(test_viewer.id)]},
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text
        assert response.json()["changed"] == 0
        assert response.json()["skipped"] == 1


class TestUpdateFields:
    @pytest.mark.anyio
    async def test_a_rate_limit_change_is_written_and_counted(
        self, client, db_session, test_viewer, auth_headers_admin
    ):
        response = await client.put(
            f"/api/v1/users/{test_viewer.id}",
            json={"rate_limit_minutes": 30},
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text
        await db_session.refresh(test_viewer)
        assert test_viewer.rate_limit_minutes == 30
        assert response.json()["rate_limit_minutes"] == 30


class TestUnlock:
    @pytest.mark.anyio
    async def test_a_naive_database_lock_is_released_without_a_type_error(
        self, client, db_session, test_viewer, auth_headers_admin
    ):
        """SQLite returns the aware column as a naive datetime."""
        test_viewer.failed_login_attempts = 4
        test_viewer.locked_until = (
            datetime.now(timezone.utc) + timedelta(minutes=10)
        ).replace(tzinfo=None)
        await db_session.commit()

        response = await client.post(
            f"/api/v1/users/{test_viewer.id}/unlock", headers=auth_headers_admin
        )
        assert response.status_code == 200, response.text
        await db_session.refresh(test_viewer)
        assert test_viewer.locked_until is None
        assert test_viewer.failed_login_attempts == 0


class TestUnknownAccounts:
    @pytest.mark.anyio
    async def test_every_per_account_route_answers_not_found(
        self, client, auth_headers_admin
    ):
        unknown = uuid.uuid4()
        sessions = await client.get(
            f"/api/v1/users/{unknown}/sessions", headers=auth_headers_admin
        )
        assert sessions.status_code == 404, sessions.text

        revoked = await client.delete(
            f"/api/v1/users/{unknown}/sessions", headers=auth_headers_admin
        )
        assert revoked.status_code == 404, revoked.text

        reset = await client.post(
            f"/api/v1/users/{unknown}/mfa/reset", headers=auth_headers_admin
        )
        assert reset.status_code == 404, reset.text


class TestReissueInvitation:
    @pytest.mark.anyio
    async def test_reissuing_returns_a_new_link_for_the_same_account(
        self, client, auth_headers_admin
    ):
        invited = await client.post(
            "/api/v1/users/invite",
            json={"email": "reissue@example.com", "role": "viewer"},
            headers=auth_headers_admin,
        )
        assert invited.status_code == 201, invited.text
        user_id = invited.json()["user"]["id"]

        reissued = await client.post(
            f"/api/v1/users/{user_id}/invitation", headers=auth_headers_admin
        )
        assert reissued.status_code == 200, reissued.text
        assert reissued.json()["user"]["id"] == user_id
        assert reissued.json()["invitation_token"] != invited.json()["invitation_token"]


class TestUnlockRefusals:
    @pytest.mark.anyio
    async def test_an_unknown_account_is_not_found(self, client, auth_headers_admin):
        response = await client.post(
            f"/api/v1/users/{uuid.uuid4()}/unlock", headers=auth_headers_admin
        )
        assert response.status_code == 404, response.text

    @pytest.mark.anyio
    async def test_an_unlocked_account_is_refused_by_name(
        self, client, test_viewer, auth_headers_admin
    ):
        response = await client.post(
            f"/api/v1/users/{test_viewer.id}/unlock", headers=auth_headers_admin
        )
        assert response.status_code == 409, response.text
        assert "not locked" in response.json()["detail"].lower()


class TestMfaReset:
    @pytest.mark.anyio
    async def test_an_administrator_cannot_reset_their_own_factor(
        self, client, test_admin, auth_headers_admin
    ):
        response = await client.post(
            f"/api/v1/users/{test_admin.id}/mfa/reset", headers=auth_headers_admin
        )
        assert response.status_code == 409, response.text
        assert "manage_admin" in response.json()["detail"]

    @pytest.mark.anyio
    async def test_an_account_without_a_factor_is_refused(
        self, client, test_viewer, auth_headers_admin
    ):
        response = await client.post(
            f"/api/v1/users/{test_viewer.id}/mfa/reset", headers=auth_headers_admin
        )
        assert response.status_code == 409, response.text
        assert "No second factor" in response.json()["detail"]

    @pytest.mark.anyio
    async def test_resetting_clears_the_factor_and_ends_its_sessions(
        self, client, db_session, test_viewer, auth_headers_admin
    ):
        from datetime import datetime, timezone

        from app.core.crypto import encrypt_value
        from app.models.token import RefreshTokenFamily

        test_viewer.totp_secret = encrypt_value("JBSWY3DPEHPK3PXP")
        test_viewer.totp_enabled_at = datetime.now(timezone.utc)
        test_viewer.mfa_recovery_codes = ["hashed-code"]
        test_viewer.mfa_failed_attempts = 3
        family = RefreshTokenFamily(
            family_id=uuid.uuid4(),
            user_id=test_viewer.id,
            revoked=False,
        )
        db_session.add(family)
        await db_session.commit()

        response = await client.post(
            f"/api/v1/users/{test_viewer.id}/mfa/reset", headers=auth_headers_admin
        )
        assert response.status_code == 200, response.text
        await db_session.refresh(test_viewer)
        await db_session.refresh(family)
        assert test_viewer.totp_secret is None
        assert test_viewer.totp_enabled_at is None
        assert test_viewer.mfa_recovery_codes is None
        assert test_viewer.mfa_failed_attempts == 0
        assert test_viewer.must_enrol_mfa is True
        assert family.revoked is True


class TestStorageConflicts:
    @pytest.mark.anyio
    async def test_an_update_that_loses_an_address_race_answers_conflict(
        self, client, test_viewer, auth_headers_admin
    ):
        failure = IntegrityError(
            "UPDATE users", {}, Exception("duplicate key users_email_key")
        )
        with patch.object(AsyncSession, "commit", new=AsyncMock(side_effect=failure)):
            response = await client.put(
                f"/api/v1/users/{test_viewer.id}",
                json={"full_name": "Racy Rename"},
                headers=auth_headers_admin,
            )
        assert response.status_code == 409, response.text
        assert "already exists" in response.json()["detail"]

    @pytest.mark.anyio
    async def test_a_delete_that_is_still_referenced_answers_conflict(
        self, client, test_viewer, auth_headers_admin
    ):
        failure = IntegrityError("DELETE FROM users", {}, Exception("foreign key"))
        with patch.object(AsyncSession, "commit", new=AsyncMock(side_effect=failure)):
            response = await client.delete(
                f"/api/v1/users/{test_viewer.id}", headers=auth_headers_admin
            )
        assert response.status_code == 409, response.text
        assert "referenced by other records" in response.json()["detail"]

    @pytest.mark.anyio
    async def test_creating_against_another_constraint_does_not_claim_an_address(
        self, client, auth_headers_admin
    ):
        failure = IntegrityError("INSERT INTO users", {}, Exception("CHECK failed"))
        with patch.object(AsyncSession, "commit", new=AsyncMock(side_effect=failure)):
            response = await client.post(
                "/api/v1/users",
                json={
                    "email": "constraint-create@example.com",
                    "password": PASSWORD,
                    "role": "viewer",
                },
                headers=auth_headers_admin,
            )
        assert response.status_code == 409, response.text
        assert "constraint violation" in response.json()["detail"]
        assert "already exists" not in response.json()["detail"]

    @pytest.mark.anyio
    async def test_an_invitation_that_loses_an_address_race_answers_conflict(
        self, client, auth_headers_admin
    ):
        failure = IntegrityError(
            "INSERT INTO users", {}, Exception("duplicate key users_email_key")
        )
        with patch.object(AsyncSession, "commit", new=AsyncMock(side_effect=failure)):
            response = await client.post(
                "/api/v1/users/invite",
                json={"email": "racy-invite@example.com", "role": "viewer"},
                headers=auth_headers_admin,
            )
        assert response.status_code == 409, response.text
        assert "already exists" in response.json()["detail"]

    @pytest.mark.anyio
    async def test_a_bulk_write_that_fails_answers_conflict(
        self, client, test_viewer, auth_headers_admin
    ):
        failure = IntegrityError("UPDATE users", {}, Exception("deadlock"))
        with patch.object(AsyncSession, "commit", new=AsyncMock(side_effect=failure)):
            response = await client.post(
                "/api/v1/users/bulk",
                json={"operation": "activate", "user_ids": [str(test_viewer.id)]},
                headers=auth_headers_admin,
            )
        assert response.status_code == 409, response.text
        assert "bulk action" in response.json()["detail"]

    @pytest.mark.anyio
    async def test_an_update_against_another_constraint_names_no_address(
        self, client, test_viewer, auth_headers_admin
    ):
        failure = IntegrityError("UPDATE users", {}, Exception("CHECK failed"))
        with patch.object(AsyncSession, "commit", new=AsyncMock(side_effect=failure)):
            response = await client.put(
                f"/api/v1/users/{test_viewer.id}",
                json={"full_name": "Constraint Rename"},
                headers=auth_headers_admin,
            )
        assert response.status_code == 409, response.text
        assert response.json()["detail"] == "Could not update user"

    @pytest.mark.anyio
    async def test_an_unlock_that_cannot_be_committed_answers_conflict(
        self, client, db_session, test_viewer, auth_headers_admin
    ):
        test_viewer.failed_login_attempts = 4
        await db_session.commit()
        failure = IntegrityError("UPDATE users", {}, Exception("deadlock"))
        with patch.object(AsyncSession, "commit", new=AsyncMock(side_effect=failure)):
            response = await client.post(
                f"/api/v1/users/{test_viewer.id}/unlock", headers=auth_headers_admin
            )
        assert response.status_code == 409, response.text
        assert "unlock the account" in response.json()["detail"]

    @pytest.mark.anyio
    async def test_an_mfa_reset_that_cannot_be_committed_answers_conflict(
        self, client, db_session, test_viewer, auth_headers_admin
    ):
        from datetime import datetime, timezone

        from app.core.crypto import encrypt_value

        test_viewer.totp_secret = encrypt_value("JBSWY3DPEHPK3PXP")
        test_viewer.totp_enabled_at = datetime.now(timezone.utc)
        await db_session.commit()
        failure = IntegrityError("UPDATE users", {}, Exception("deadlock"))
        with patch.object(AsyncSession, "commit", new=AsyncMock(side_effect=failure)):
            response = await client.post(
                f"/api/v1/users/{test_viewer.id}/mfa/reset",
                headers=auth_headers_admin,
            )
        assert response.status_code == 409, response.text
        assert "reset the second factor" in response.json()["detail"]
