import uuid
from datetime import date
from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.breach import Breach


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


async def _seed_breaches(db):
    from sqlalchemy import text

    await db.execute(text("DELETE FROM drp_breaches"))
    await db.commit()
    suffix = uuid.uuid4().hex[:8]
    breaches = [
        Breach(
            id=uuid.uuid4(),
            breach_name="Adobe2013",
            title="Adobe 2013 Breach",
            domain="adobe.com",
            breach_date=date(2013, 10, 1),
            pwn_count=152_445_165,
            matched_email=f"ops-{suffix}@adobe.com",
            description="Huge Adobe leak",
        ),
        Breach(
            id=uuid.uuid4(),
            breach_name="LinkedIn2021",
            title="LinkedIn 2021",
            domain="linkedin.com",
            breach_date=date(2021, 6, 1),
            pwn_count=700_000_000,
            matched_email=f"ceo-{suffix}@linkedin.com",
        ),
        Breach(
            id=uuid.uuid4(),
            breach_name="LastPass2022",
            title="LastPass 2022",
            domain="lastpass.com",
            breach_date=date(2022, 8, 1),
            pwn_count=27_000_000,
            matched_email=f"dev-{suffix}@example.com",
        ),
    ]
    for b in breaches:
        db.add(b)
    await db.commit()
    return suffix, breaches


class TestOrphanBreachCleanup:
    @pytest.mark.asyncio
    async def test_admin_cleanup_preserves_linked_domain_email_and_inactive_assets(self, client, db_session, auth_headers_admin, auth_headers_viewer):
        from app.models.asset import Asset

        domain_asset = Asset(asset_type="domain", asset_value="hibp-integration-tests.com", is_active=False)
        email_asset = Asset(asset_type="email_account", asset_value="direct@example.com", is_active=True)
        db_session.add_all([domain_asset, email_asset])
        linked_domain = Breach(
            breach_name="LinkedDomainBreach",
            title="LinkedDomainBreach",
            domain="example.com",
            breach_date=date(2024, 1, 1),
            matched_email="alias@hibp-integration-tests.com",
            matched_domain=None,
        )
        linked_email = Breach(
            breach_name="LinkedEmailBreach",
            title="LinkedEmailBreach",
            domain="example.com",
            breach_date=date(2024, 1, 1),
            matched_email="direct@example.com",
        )
        orphan = Breach(
            breach_name="OrphanBreach",
            title="OrphanBreach",
            domain="example.com",
            breach_date=date(2024, 1, 1),
            matched_email="orphan@missing.example",
            matched_domain=None,
        )
        db_session.add_all([linked_domain, linked_email, orphan])
        await db_session.commit()
        linked_domain_id, linked_email_id, orphan_id = linked_domain.id, linked_email.id, orphan.id

        viewer_response = await client.post(
            "/api/v1/breaches/cleanup-orphans",
            headers=auth_headers_viewer,
        )
        assert viewer_response.status_code == 403

        response = await client.post(
            "/api/v1/breaches/cleanup-orphans",
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text
        assert response.json() == {"status": "completed", "deleted": 1}

        db_session.expire_all()
        assert await db_session.get(Breach, linked_domain_id) is not None
        assert await db_session.get(Breach, linked_email_id) is not None
        assert await db_session.get(Breach, orphan_id) is None


class TestListBreaches:
    @pytest.mark.asyncio
    async def test_list_breaches_total_3_paginated(
        self, client, db_session, auth_headers_analyst
    ):
        await _seed_breaches(db_session)
        r = await client.get(
            "/api/v1/breaches?page=1&size=2", headers=auth_headers_analyst
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 3
        assert body["size"] == 2
        assert body["pages"] == 2
        assert len(body["items"]) == 2

    @pytest.mark.asyncio
    async def test_search_by_domain_filters(
        self, client, db_session, auth_headers_viewer
    ):
        suffix, _ = await _seed_breaches(db_session)
        r = await client.get(
            "/api/v1/breaches?search=linkedIn.com",
            headers=auth_headers_viewer,
        )
        body = r.json()
        assert body["total"] == 1
        assert body["items"][0]["domain"] == "linkedin.com"

        # Search metacharacters are literal and cannot expand the result set.
        r = await client.get(
            "/api/v1/breaches?search=%25",
            headers=auth_headers_viewer,
        )
        assert r.json()["total"] == 0

    @pytest.mark.asyncio
    async def test_breach_detail_200_and_not_found_404(
        self, client, db_session, auth_headers_admin
    ):
        _, breaches = await _seed_breaches(db_session)
        r = await client.get(
            f"/api/v1/breaches/{breaches[0].id}",
            headers=auth_headers_admin,
        )
        assert r.status_code == 200
        assert r.json()["breach_name"] == "Adobe2013"
        missing = uuid.uuid4()
        r = await client.get(
            f"/api/v1/breaches/{missing}", headers=auth_headers_admin
        )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_scan_endpoint_schedules_task_200(
        self, client, db_session, auth_headers_analyst
    ):
        from app.models import Connector

        conn = Connector(
            name="hibp", connector_type="breaches", default_job_type="breaches.hibp"
        )
        db_session.add(conn)
        await db_session.commit()
        try:
            r = await client.post(
                "/api/v1/breaches/scan", headers=auth_headers_analyst
            )
            assert r.status_code == 200
            body = r.json()
            assert body["status"] == "scheduled"
            assert len(body["job_ids"]) == 1
        finally:
            await db_session.delete(conn)
            await db_session.commit()

    @pytest.mark.asyncio
    async def test_scan_viewer_forbidden_403(
        self, client, auth_headers_viewer
    ):
        r = await client.post("/api/v1/breaches/scan", headers=auth_headers_viewer)
        assert r.status_code == 403
