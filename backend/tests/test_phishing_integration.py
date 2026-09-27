import uuid
from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.main import app
from app.models.phishing import PhishingDomain


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


async def _seed_threats(db):
    await db.execute(text("DELETE FROM drp_phishing_domains"))
    await db.commit()
    suffix = uuid.uuid4().hex[:8]
    threats = [
        PhishingDomain(
            id=uuid.uuid4(),
            phishing_domain=f"paypa1-{suffix}.com",
            matched_asset="paypal.com",
            ip_address="198.51.100.10",
            web_ports="80,443",
            detection_source="dnstwist",
            original_domain="paypal.com",
            whois_registrar="NameCheap",
            whois_abuse_email="abuse@namecheap.com",
            status="active",
        ),
        PhishingDomain(
            id=uuid.uuid4(),
            phishing_domain=f"my-paypal-{suffix}.tk",
            matched_asset="paypal.com",
            ip_address="198.51.100.11",
            detection_source="dnstwist",
            whois_abuse_email="abuse@freenom.com",
            status="investigating",
        ),
        PhishingDomain(
            id=uuid.uuid4(),
            phishing_domain=f"secure-chase-{suffix}.online",
            matched_asset="chase.com",
            ip_address="203.0.113.5",
            detection_source="dnstwist",
            whois_abuse_email="abuse@exampleisp.net",
            status="resolved",
        ),
        PhishingDomain(
            id=uuid.uuid4(),
            phishing_domain=f"login-office365-{suffix}.cf",
            matched_asset="office365.com",
            ip_address="192.0.2.88",
            detection_source="shodan_ssl",
            whois_abuse_email="abuse@cloudflare.com",
            status="active",
        ),
        PhishingDomain(
            id=uuid.uuid4(),
            phishing_domain=f"fake-dropbox-{suffix}.ml",
            matched_asset="dropbox.com",
            ip_address="192.0.2.89",
            detection_source="shodan_title",
            whois_abuse_email="abuse@registrar.ru",
            status="active",
        ),
    ]
    for t in threats:
        db.add(t)
    await db.commit()
    for t in threats:
        await db.refresh(t)
    return suffix, threats


class TestOrphanPhishingCleanup:
    @pytest.mark.asyncio
    async def test_admin_cleanup_removes_only_orphan_findings(self, client, db_session, auth_headers_admin, auth_headers_viewer):
        from app.models.asset import Asset

        linked_asset = Asset(asset_type="keyword_title", asset_value="KEDEN", is_active=False)
        db_session.add(linked_asset)
        linked = PhishingDomain(
            phishing_domain="185.129.51.198",
            matched_asset="KEDEN",
            detection_source="shodan_title",
        )
        orphan = PhishingDomain(
            phishing_domain="orphan-cleanup.example",
            matched_asset="deleted-asset.example",
            detection_source="dnstwist",
        )
        db_session.add_all([linked, orphan])
        await db_session.commit()
        linked_id, orphan_id = linked.id, orphan.id

        viewer_response = await client.post(
            "/api/v1/phishing/threats/cleanup-orphans",
            headers=auth_headers_viewer,
        )
        assert viewer_response.status_code == 403

        response = await client.post(
            "/api/v1/phishing/threats/cleanup-orphans",
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text
        assert response.json() == {"status": "completed", "deleted": 1}

        db_session.expire_all()
        assert await db_session.get(PhishingDomain, linked_id) is not None
        assert await db_session.get(PhishingDomain, orphan_id) is None


class TestListThreats:
    @pytest.mark.asyncio
    async def test_filters_and_search_work(
        self, client, db_session, auth_headers_viewer
    ):
        await _seed_threats(db_session)

        r = await client.get(
            "/api/v1/phishing/threats?page=1&size=20",
            headers=auth_headers_viewer,
        )
        assert r.status_code == 200
        assert r.json()["total"] == 5

        r = await client.get(
            "/api/v1/phishing/threats?detection_source=dnstwist",
            headers=auth_headers_viewer,
        )
        assert r.json()["total"] == 3

        r = await client.get(
            "/api/v1/phishing/threats?status=resolved",
            headers=auth_headers_viewer,
        )
        assert r.json()["total"] == 1

        r = await client.get(
            "/api/v1/phishing/threats?search=dropbox",
            headers=auth_headers_viewer,
        )
        body = r.json()
        assert body["total"] == 1
        assert "dropbox" in body["items"][0]["phishing_domain"]

        r = await client.get(
            "/api/v1/phishing/threats?search=192.0.2.88",
            headers=auth_headers_viewer,
        )
        assert r.json()["total"] == 1

        # Wildcards are literal search characters, not SQL LIKE expansion.
        r = await client.get(
            "/api/v1/phishing/threats?search=%25",
            headers=auth_headers_viewer,
        )
        assert r.json()["total"] == 0


class TestThreatDetailAndUpdate:
    @pytest.mark.asyncio
    async def test_detail_200_and_not_found_404(
        self, client, db_session, auth_headers_analyst
    ):
        _, threats = await _seed_threats(db_session)
        r = await client.get(
            f"/api/v1/phishing/threats/{threats[0].id}",
            headers=auth_headers_analyst,
        )
        assert r.status_code == 200
        assert r.json()["detection_source"] == "dnstwist"

        missing = uuid.uuid4()
        r = await client.get(
            f"/api/v1/phishing/threats/{missing}",
            headers=auth_headers_analyst,
        )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_patch_status_analyst_200_viewer_403(
        self, client, db_session, auth_headers_analyst, auth_headers_viewer
    ):
        _, threats = await _seed_threats(db_session)
        tid = threats[0].id

        r = await client.patch(
            f"/api/v1/phishing/threats/{tid}",
            json={"status": "processing"},
            headers=auth_headers_viewer,
        )
        assert r.status_code == 403

        r = await client.patch(
            f"/api/v1/phishing/threats/{tid}",
            json={"status": "investigating"},
            headers=auth_headers_analyst,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "investigating"

        from sqlalchemy import select

        saved = (
            await db_session.execute(
                select(PhishingDomain).where(PhishingDomain.id == tid)
            )
        ).scalar_one()
        assert saved.status == "investigating"


class TestTakedownRemoved:
    @pytest.mark.asyncio
    async def test_takedown_endpoint_is_gone(
        self, client, db_session, auth_headers_analyst
    ):
        _, threats = await _seed_threats(db_session)
        r = await client.get(
            f"/api/v1/phishing/threats/{threats[0].id}/takedown",
            headers=auth_headers_analyst,
        )
        assert r.status_code == 404


class TestScanEndpoints:
    @pytest.fixture
    async def phishing_connector(self, db_session):
        from app.models import Connector

        conn = Connector(
            name="dnstwist", connector_type="phishing", default_job_type="phishing.dnstwist"
        )
        db_session.add(conn)
        await db_session.commit()
        yield conn
        await db_session.delete(conn)
        await db_session.commit()

    @pytest.mark.asyncio
    async def test_dnstwist_scan_enqueues_connector_work(
        self, client, auth_headers_analyst, db_session, phishing_connector
    ):
        from sqlalchemy import select

        from app.models.job import Job

        r = await client.post(
            "/api/v1/phishing/scan/dnstwist", headers=auth_headers_analyst
        )
        assert r.status_code == 202
        body = r.json()
        assert body["status"] == "scheduled"
        assert len(body["job_ids"]) == 1
        job = (
            await db_session.execute(
                select(Job).where(Job.id == uuid.UUID(body["job_ids"][0]))
            )
        ).scalar_one_or_none()
        assert job is not None
        assert job.status == "pending"
        assert job.job_type == "phishing.dnstwist"
        assert (job.params or {}).get("connector") == "dnstwist"

    @pytest.mark.asyncio
    async def test_scan_without_connector_reports_clear_error(
        self, client, auth_headers_analyst, db_session
    ):
        # No connector registered -> explicit error, no pending jobs left.
        from sqlalchemy import select

        from app.models.job import Job

        r = await client.post(
            "/api/v1/phishing/scan/dnstwist", headers=auth_headers_analyst
        )
        assert r.status_code == 202
        body = r.json()
        assert body["status"] == "no_connector"
        assert "No enabled" in body["error"]
        jobs = (
            await db_session.execute(select(Job).where(Job.job_type == "phishing.dnstwist"))
        ).scalars().all()
        assert jobs == []

    @pytest.mark.asyncio
    async def test_shodan_scan_scheduled_202_and_viewer_403(
        self, client, auth_headers_analyst, auth_headers_viewer, db_session, phishing_connector
    ):
        from app.models import Connector
        from app.models.job import Job
        from sqlalchemy import select

        # Endpoint is scoped to the shodan connector, so register it too.
        shodan = Connector(
            name="shodan", connector_type="phishing", default_job_type="phishing.shodan"
        )
        db_session.add(shodan)
        await db_session.commit()

        r = await client.post(
            "/api/v1/phishing/scan/shodan", headers=auth_headers_analyst
        )
        assert r.status_code == 202
        assert r.json()["status"] == "scheduled"
        assert len(r.json()["job_ids"]) == 1
        job = (
            await db_session.execute(select(Job).where(Job.id == uuid.UUID(r.json()["job_ids"][0])))
        ).scalar_one()
        assert job.job_type == "phishing.shodan"

        r = await client.post(
            "/api/v1/phishing/scan/shodan", headers=auth_headers_viewer
        )
        assert r.status_code == 403

        await db_session.delete(shodan)
        await db_session.commit()
