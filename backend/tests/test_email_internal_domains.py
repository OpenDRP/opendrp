"""Operator accounts and monitored mailboxes on internal domains.

Pydantic's ``EmailStr`` rejects RFC 6761/2606 special-use names such as
``.local``, so an internal deployment could not create ``admin@corp.local``.
These tests pin the relaxed contract *and* the checks that must survive it:
syntactically broken addresses stay rejected.
"""

from __future__ import annotations

import pytest

from app.schemas.asset import AssetCreate
from app.schemas.email import normalize_email
from app.schemas.breaches import BreachScanEmailRequest
from app.schemas.user import LoginRequest, UserCreate, UserUpdate

INTERNAL_OK = [
    "admin@localdomain.local",
    "svc-backup@corp.local",
    "user@corp.internal",
    "soc@home.arpa",
]

INVALID = [
    "not-an-email",
    "a@b",
    "a b@example.com",
    "user@",
    "@example.com",
    "user@-bad-.local",
]


class TestNormalizeEmail:
    @pytest.mark.parametrize("value", INTERNAL_OK)
    def test_internal_domains_are_accepted(self, value: str):
        assert normalize_email(value) == value

    @pytest.mark.parametrize("value", INVALID)
    def test_broken_addresses_still_fail(self, value: str):
        with pytest.raises(ValueError):
            normalize_email(value)

    def test_public_addresses_keep_their_normalization(self):
        assert normalize_email("  User@Example.COM ") == "User@example.com"

    def test_local_part_case_is_preserved(self):
        # RFC 5321: the local part is case-sensitive; only the domain is lowered.
        assert normalize_email("Admin@LocalDomain.Local") == "Admin@localdomain.local"


class TestSchemas:
    def test_user_create_accepts_internal_domain(self):
        payload = UserCreate(email="admin@localdomain.local", password="StrongPass123!")
        assert payload.email == "admin@localdomain.local"
        assert payload.rate_limit_minutes == 0

    def test_user_update_email_and_rate_limit_bounds(self):
        assert UserUpdate(email="ops@corp.local").email == "ops@corp.local"
        assert UserUpdate(rate_limit_minutes=1440).rate_limit_minutes == 1440
        with pytest.raises(ValueError):
            UserUpdate(rate_limit_minutes=1441)
        with pytest.raises(ValueError):
            UserUpdate(rate_limit_minutes=-1)

    def test_login_request_accepts_internal_domain(self):
        # Login must accept anything that could have been stored at create time,
        # otherwise the account is unusable after the fact.
        assert LoginRequest(email="admin@localdomain.local", password="x").email == (
            "admin@localdomain.local"
        )

    def test_breach_scan_email_accepts_internal_domain(self):
        assert (
            BreachScanEmailRequest(email="victim@corp.local").email == "victim@corp.local"
        )

    def test_email_asset_accepts_internal_domain(self):
        asset = AssetCreate(
            asset_type="email_account", asset_value="victim@corp.local"
        )
        assert asset.asset_value == "victim@corp.local"

    def test_email_asset_rejects_garbage(self):
        with pytest.raises(ValueError):
            AssetCreate(asset_type="email_account", asset_value="not-an-email")


class TestUsersApi:
    @pytest.mark.asyncio
    async def test_admin_can_create_and_login_internal_domain_user(
        self, client, auth_headers_admin
    ):
        created = await client.post(
            "/api/v1/users",
            json={
                "email": "admin@localdomain.local",
                "password": "StrongPass123!",
                "role": "analyst",
                "rate_limit_minutes": 60,
            },
            headers=auth_headers_admin,
        )
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["email"] == "admin@localdomain.local"
        assert body["rate_limit_minutes"] == 60

        login = await client.post(
            "/api/v1/auth/login",
            json={"email": "admin@localdomain.local", "password": "StrongPass123!"},
        )
        assert login.status_code == 200, login.text
        assert login.json()["user"]["email"] == "admin@localdomain.local"

    @pytest.mark.asyncio
    async def test_invalid_email_is_still_rejected(self, client, auth_headers_admin):
        bad = await client.post(
            "/api/v1/users",
            json={"email": "not-an-email", "password": "StrongPass123!"},
            headers=auth_headers_admin,
        )
        assert bad.status_code == 422

    @pytest.mark.asyncio
    async def test_rate_limit_must_be_within_range(self, client, auth_headers_admin):
        too_big = await client.post(
            "/api/v1/users",
            json={
                "email": "ops@corp.local",
                "password": "StrongPass123!",
                "rate_limit_minutes": 2000,
            },
            headers=auth_headers_admin,
        )
        assert too_big.status_code == 422
