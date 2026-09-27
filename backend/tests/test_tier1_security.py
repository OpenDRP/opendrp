from datetime import datetime, timezone
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.main import app
from app.models.audit import AuditLog
from app.models.token import RefreshTokenFamily
from app.models.user import User


BASE = "http://test"


@pytest.fixture()
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    from app.api.deps import get_db

    async def _override():
        yield db_session

    app.dependency_overrides[get_db] = _override
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_db, None)


async def _count(db, table: str) -> int:
    from tests.conftest import safe_sql_identifier
    safe = safe_sql_identifier(table)
    r = await db.execute(text(f"SELECT COUNT(*) FROM {safe}"))
    return int(r.scalar_one() or 0)


class TestAuditLog5Fields:
    @pytest.mark.asyncio
    async def test_login_success_writes_audit_row_5_fields(
        self, client, db_session, test_analyst
    ):
        before = await _count(db_session, "drp_audit_logs")
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": test_analyst.email, "password": "TestPass123!"},
            headers={"X-Forwarded-For": "203.0.113.42"},
        )
        assert r.status_code == 200, r.text
        after = await _count(db_session, "drp_audit_logs")
        assert after >= before + 1

        rows = list(
            (await db_session.execute(
                select(AuditLog).order_by(AuditLog.timestamp.desc())
            )).scalars().all()
        )
        success = None
        for x in rows:
            if x.action == "auth.login.success":
                success = x
                break
        assert success is not None
        assert success.user_id == test_analyst.id
        assert success.ip_address == "203.0.113.42"
        assert isinstance(success.timestamp, datetime)
        assert success.details and success.details.get("email") == test_analyst.email.lower()

    @pytest.mark.asyncio
    async def test_login_audit_ip_ignores_forged_forwarded_entry(
        self, client, db_session, test_analyst
    ):
        """The recorded address must not be forgeable by the client.

        nginx appends the real peer, so a client-supplied leading entry arrives
        first; recording it would let anyone attribute their login to an
        arbitrary address.
        """
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": test_analyst.email, "password": "TestPass123!"},
            headers={"X-Forwarded-For": "203.0.113.42, 198.51.100.7"},
        )
        assert r.status_code == 200, r.text

        rows = list(
            (await db_session.execute(
                select(AuditLog).order_by(AuditLog.timestamp.desc())
            )).scalars().all()
        )
        success = None
        for x in rows:
            if x.action == "auth.login.success":
                success = x
                break
        assert success is not None
        assert success.ip_address == "198.51.100.7"
        assert success.ip_address != "203.0.113.42"

    @pytest.mark.asyncio
    async def test_login_failure_audits_unknown_email(
        self, client, db_session
    ):
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": "ghost@example.com", "password": "WrongPass9!"},
        )
        assert r.status_code == 401
        rows = list(
            (await db_session.execute(
                select(AuditLog).where(AuditLog.action == "auth.login.failure")
            )).scalars().all()
        )
        assert rows
        last = rows[-1]
        assert last.user_id is None
        assert last.details.get("reason") == "invalid_credentials"


class TestDBFallBackAccountLockout:
    @pytest.mark.asyncio
    async def test_locked_account_is_refused_without_disclosing_lock(
        self, client, db_session, test_viewer
    ):
        for _ in range(8):
            await client.post(
                "/api/v1/auth/login",
                json={"email": test_viewer.email, "password": "WrongPass9!"},
            )
        user = (await db_session.execute(
            select(User).where(User.id == test_viewer.id)
        )).scalar_one()
        assert user.locked_until is not None
        assert user.locked_until > datetime.now(timezone.utc)

        # Even the correct password is refused while locked...
        r = await client.post(
            "/api/v1/auth/login",
            json={"email": test_viewer.email, "password": "TestPass123!"},
        )
        assert r.status_code == 401
        # ...and the answer is byte-identical to any other credential failure,
        # because a distinct "account is locked" reply would confirm that the
        # address exists whenever the Redis limiter is unavailable.
        assert r.json()["detail"] == "Invalid email or password"
        assert "Retry-After" not in r.headers


class TestRefreshTokenRotation:
    @pytest.mark.asyncio
    async def test_sequential_refresh_rotates_new_tokens(
        self, client, test_admin
    ):
        r0 = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": "TestPass123!"},
        )
        refresh_a = r0.cookies.get("opendrp_refresh")

        r1 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_a})
        assert r1.status_code == 200, r1.text
        refresh_b = r1.cookies.get("opendrp_refresh")
        assert refresh_b != refresh_a

        r2 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_b})
        assert r2.status_code == 200, r2.text
        refresh_c = r2.cookies.get("opendrp_refresh")
        assert refresh_c != refresh_b

    @pytest.mark.asyncio
    async def test_reuse_old_refresh_revokes_family_401(
        self, client, db_session, test_admin
    ):
        r0 = await client.post(
            "/api/v1/auth/login",
            json={"email": test_admin.email, "password": "TestPass123!"},
        )
        refresh_a = r0.cookies.get("opendrp_refresh")

        r1 = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_a})
        assert r1.status_code == 200, r1.text

        reuse = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": refresh_a}
        )
        assert reuse.status_code == 401
        detail = reuse.json()["detail"].lower()
        assert ("revoked" in detail) or ("reuse" in detail)

        fam = (await db_session.execute(
            select(RefreshTokenFamily).where(RefreshTokenFamily.user_id == test_admin.id)
        )).scalar_one()
        assert fam.revoked is True
        assert fam.revoked_reason == "reuse_detected"


class TestRedisRateLimit429:
    @pytest.mark.asyncio
    async def test_redis_lock_triggers_429_retry_after_header(
        self, client, test_analyst
    ):
        mock_is_locked = AsyncMock(return_value=True)
        with patch(
            "app.api.v1.routers.auth._rate_limiter.is_locked", mock_is_locked
        ):
            r = await client.post(
                "/api/v1/auth/login",
                json={"email": test_analyst.email, "password": "TestPass123!"},
            )
        assert r.status_code == 429, r.text
        assert "Retry-After" in r.headers
        assert int(r.headers["Retry-After"]) >= 60
