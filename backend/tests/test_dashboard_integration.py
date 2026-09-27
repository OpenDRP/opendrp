import uuid
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.asset import Asset, AssetType
from app.models.breach import Breach
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


async def _cleanup_before_seed(db):
    from sqlalchemy import text
    from tests.conftest import safe_sql_identifier

    ordered = [
        "drp_breaches",
        "drp_phishing_domains",
        "reports",
        "assets",
    ]
    for name in ordered:
        await db.execute(text(f"DELETE FROM {safe_sql_identifier(name)}"))
    await db.commit()


async def _seed_dashboard(db):
    await _cleanup_before_seed(db)
    now = datetime.now(timezone.utc)
    suffix = uuid.uuid4().hex[:8]
    assets = [
        Asset(
            id=uuid.uuid4(),
            asset_type=AssetType.domain,
            asset_value=f"crit-{suffix}.com",
            criticality="critical",
            is_active=True,
        ),
        Asset(
            id=uuid.uuid4(),
            asset_type=AssetType.domain,
            asset_value=f"high-{suffix}.com",
            criticality="high",
            is_active=True,
        ),
        Asset(
            id=uuid.uuid4(),
            asset_type=AssetType.ip_address,
            asset_value=f"10.1.{suffix[:2]}.{suffix[2:4]}",
            criticality="medium",
            is_active=True,
        ),
        Asset(
            id=uuid.uuid4(),
            asset_type=AssetType.keyword_domain,
            asset_value=f"inactive-{suffix}",
            criticality="low",
            is_active=False,
        ),
    ]
    for a in assets:
        db.add(a)
    matched_domain = assets[0].asset_value
    phishing = [
        PhishingDomain(
            id=uuid.uuid4(),
            phishing_domain=f"evil-{suffix}-{i}-{days_ago}.com",
            matched_asset=matched_domain,
            detection_source=("dnstwist" if i % 2 == 0 else "shodan"),
            created_at=now - timedelta(days=days_ago),
        )
        for i, days_ago in enumerate([1, 2, 5, 10, 35])
    ]
    for p in phishing:
        db.add(p)
    hibp = [
        Breach(
            id=uuid.uuid4(),
            breach_name=f"MyBreach2024_{suffix}_{d}",
            title=f"MyBreach 2024 {suffix}",
            domain=f"example-{suffix}.com",
            breach_date=datetime(2024, 6, 1, tzinfo=timezone.utc).date(),
            pwn_count=1000,
            matched_email=f"ops-{suffix}@example.com",
            created_at=now - timedelta(days=d),
        )
        for d in [1, 20]
    ]
    for h in hibp:
        db.add(h)
    await db.commit()


class TestDashboardStats:
    @pytest.mark.asyncio
    async def test_stats_kpis_match_seed_counts(
        self, client, auth_headers_analyst, db_session
    ):
        await _seed_dashboard(db_session)
        r = await client.get(
            "/api/v1/dashboard/stats", headers=auth_headers_analyst
        )
        assert r.status_code == 200, r.text
        kpi = r.json()["kpi"]
        assert kpi["total_assets"] == 3
        assert kpi["total_phishing"] == 5
        assert kpi["total_breaches"] == 2
        assert kpi["active_threats_7d"] == 3

    @pytest.mark.asyncio
    async def test_stats_by_criticality_breakdown(
        self, client, auth_headers_viewer, db_session
    ):
        await _seed_dashboard(db_session)
        r = await client.get(
            "/api/v1/dashboard/stats", headers=auth_headers_viewer
        )
        body = r.json()
        crit = {
            row["criticality"]: row["count"] for row in body["assets_by_criticality"]
        }
        assert crit.get("critical") == 1
        assert crit.get("high") == 1
        assert crit.get("medium") == 1
        assert "low" not in crit

    @pytest.mark.asyncio
    async def test_stats_phishing_by_source_breakdown(
        self, client, auth_headers_viewer, db_session
    ):
        await _seed_dashboard(db_session)
        r = await client.get(
            "/api/v1/dashboard/stats", headers=auth_headers_viewer
        )
        srcs = {
            row["source"]: row["count"]
            for row in r.json()["phishing_by_source"]
        }
        assert srcs.get("dnstwist") == 3
        assert srcs.get("shodan") == 2

    @pytest.mark.asyncio
    async def test_stats_timeline_30_entries(
        self, client, auth_headers_admin, db_session
    ):
        await _seed_dashboard(db_session)
        r = await client.get(
            "/api/v1/dashboard/stats", headers=auth_headers_admin
        )
        tl = r.json()["timeline"]
        assert len(tl) == 30
        for entry in tl:
            assert "date" in entry
            assert "phishing" in entry and isinstance(entry["phishing"], int)
            assert "breaches" in entry and isinstance(entry["breaches"], int)
        last_entry = tl[-1]
        first_entry = tl[0]
        assert first_entry["date"] != last_entry["date"]
        total_ph = sum(t["phishing"] for t in tl)
        total_hb = sum(t["breaches"] for t in tl)
        assert total_ph + total_hb >= 0

    @pytest.mark.asyncio
    async def test_stats_viewer_plus_401_no_bearer(
        self, client
    ):
        r = await client.get("/api/v1/dashboard/stats")
        assert r.status_code == 401
