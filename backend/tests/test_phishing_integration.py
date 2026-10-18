import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.main import app
from app.models.phishing import PhishingCandidateSignal, PhishingDomain


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


class TestListThreatsByScore:
    """The scored list: the number, the explanation, and the two filters (WI-08/WI-11).

    The audit's list requirement is that a candidate is always visible with its
    signals — a score an analyst cannot see the reasons for is a number they have to
    take on faith, and one they cannot filter by is eighty rows they have to read to
    find the two that matter (F-08, F-09). These tests pin the row (score, fired
    signals, the band the deployment's own thresholds put it in), the ordering by
    score, and both filters — including that `?signal=` means "this signal fired",
    not "the platform once looked".
    """

    @pytest.fixture()
    async def scored(self, db_session):
        await db_session.execute(text("DELETE FROM drp_phishing_domains"))
        await db_session.commit()
        suffix = uuid.uuid4().hex[:8]
        rows = {
            # A parked lookalike: one signal, and it subtracts.
            "parked": PhishingDomain(
                phishing_domain=f"parked-{suffix}.com",
                matched_asset="paypal.com",
                detection_source="dnstwist",
                confidence=0,
                signals={"parked_hint": "sedo"},
            ),
            # The middle band: young registration plus a brand in the body.
            "digest": PhishingDomain(
                phishing_domain=f"digest-{suffix}.com",
                matched_asset="paypal.com",
                detection_source="dnstwist",
                confidence=40,
                signals={"young_domain": 20, "brand_in_body": True},
            ),
            # The band that interrupts someone, with a fact that did not fire.
            "direct": PhishingDomain(
                phishing_domain=f"direct-{suffix}.com",
                matched_asset="paypal.com",
                detection_source="dnstwist",
                confidence=80,
                signals={
                    "young_domain": 5,
                    "title_match": True,
                    "brand_in_body": True,
                    "tls_issuer_reuse": True,
                    "html_similarity": 0.5,
                },
            ),
        }
        for row in rows.values():
            db_session.add(row)
        await db_session.flush()
        # The evidence rows are what `?signal=` reads. The direct candidate's
        # similarity fact was observed and did not reach its threshold, which is
        # exactly the case the filter has to leave out.
        for name, value, points in (
            ("title_match", True, 20),
            ("brand_in_body", True, 15),
            ("young_domain", 5, 25),
            ("tls_issuer_reuse", True, 20),
            ("html_similarity", 0.5, 0),
        ):
            db_session.add(
                PhishingCandidateSignal(
                    candidate_id=rows["direct"].id,
                    name=name,
                    value=value,
                    confidence=points,
                    source="dnstwist",
                )
            )
        # The summary map and the trail are written together by the scoring service,
        # so the fixture writes both: `?signal=` reads the trail, and a fixture whose
        # two halves disagreed would be testing a state the platform cannot produce.
        for name, value, points in (("young_domain", 20, 25), ("brand_in_body", True, 15)):
            db_session.add(
                PhishingCandidateSignal(
                    candidate_id=rows["digest"].id,
                    name=name,
                    value=value,
                    confidence=points,
                    source="dnstwist",
                )
            )
        db_session.add(
            PhishingCandidateSignal(
                candidate_id=rows["parked"].id,
                name="parked_hint",
                value="sedo",
                confidence=-30,
                source="platform",
            )
        )
        await db_session.commit()
        return rows

    async def _list(self, client, headers, query: str = "") -> list[dict]:
        response = await client.get(f"/api/v1/phishing/threats?size=50{query}", headers=headers)
        assert response.status_code == 200, response.text
        return response.json()["items"]

    @pytest.mark.asyncio
    async def test_each_row_carries_its_score_and_what_scored_it(
        self, client, scored, auth_headers_viewer
    ):
        items = {item["phishing_domain"]: item for item in await self._list(client, auth_headers_viewer)}
        direct = items[scored["direct"].phishing_domain]

        assert direct["confidence"] == 80
        # Only the signals that fired, with their weights, in table order.
        assert direct["signals"] == {
            "young_domain": 25,
            "title_match": 20,
            "brand_in_body": 15,
            "tls_issuer_reuse": 20,
        }
        assert direct["alert_band"] == "direct"
        assert items[scored["digest"].phishing_domain]["alert_band"] == "digest"
        assert items[scored["parked"].phishing_domain]["alert_band"] == "list"

        detail = await client.get(
            f"/api/v1/phishing/threats/{scored['digest'].id}", headers=auth_headers_viewer
        )
        assert detail.json()["signals"] == {"young_domain": 25, "brand_in_body": 15}

    @pytest.mark.asyncio
    async def test_the_band_follows_the_settings_not_a_constant(
        self, client, scored, auth_headers_viewer, monkeypatch
    ):
        """An operator who raises the threshold must see the list agree."""
        from app.core.config import settings

        monkeypatch.setattr(settings, "ALERT_CONFIDENCE_DIRECT", 90)
        items = {item["phishing_domain"]: item for item in await self._list(client, auth_headers_viewer)}
        assert items[scored["direct"].phishing_domain]["alert_band"] == "digest"

    @pytest.mark.asyncio
    async def test_the_score_orders_the_list(self, client, scored, auth_headers_viewer):
        items = await self._list(client, auth_headers_viewer, "&sort=confidence&order=desc")
        assert [item["confidence"] for item in items] == [80, 40, 0]

        items = await self._list(client, auth_headers_viewer, "&sort=confidence&order=asc")
        assert [item["confidence"] for item in items] == [0, 40, 80]

    @pytest.mark.asyncio
    async def test_a_minimum_confidence_keeps_what_is_at_or_above_it(
        self, client, scored, auth_headers_viewer
    ):
        items = await self._list(client, auth_headers_viewer, "&min_confidence=40")
        assert {item["confidence"] for item in items} == {40, 80}

        items = await self._list(client, auth_headers_viewer, "&min_confidence=0")
        assert len(items) == 3

        refused = await client.get(
            "/api/v1/phishing/threats?min_confidence=101", headers=auth_headers_viewer
        )
        assert refused.status_code == 422

    @pytest.mark.asyncio
    async def test_the_signal_filter_follows_the_evidence(
        self, client, scored, auth_headers_viewer
    ):
        items = await self._list(client, auth_headers_viewer, "&signal=parked_hint")
        assert [item["phishing_domain"] for item in items] == [
            scored["parked"].phishing_domain
        ]

        # A fact the platform observed and did not match is not a fired signal.
        items = await self._list(client, auth_headers_viewer, "&signal=html_similarity")
        assert items == []

        items = await self._list(client, auth_headers_viewer, "&signal=young_domain")
        assert len(items) == 2

        refused = await client.get(
            "/api/v1/phishing/threats?signal=not_a_signal", headers=auth_headers_viewer
        )
        assert refused.status_code == 422


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


class TestListThreatsByAge:
    """The age of a registration is a fact the list has to be able to read (WI-05).

    A young registration is the strongest single signal a look-alike carries, and the
    platform stored the registration date without ever showing it: the only ordering
    the list offered was "newest finding first", which is the opposite question.
    These tests pin the computed field, the ordering it enables (a candidate whose
    registration nobody resolved is not the youngest one) and the refusal of a sort
    field the API does not declare.
    """

    @pytest.fixture()
    async def aged(self, db_session):
        from datetime import datetime, timedelta, timezone

        await db_session.execute(text("DELETE FROM drp_phishing_domains"))
        await db_session.commit()
        suffix = uuid.uuid4().hex[:8]
        rows = {
            "young": PhishingDomain(
                phishing_domain=f"young-{suffix}.com",
                matched_asset="paypal.com",
                detection_source="dnstwist",
                domain_created_at=datetime.now(timezone.utc) - timedelta(days=10),
            ),
            "old": PhishingDomain(
                phishing_domain=f"old-{suffix}.com",
                matched_asset="paypal.com",
                detection_source="dnstwist",
                domain_created_at=datetime.now(timezone.utc) - timedelta(days=3000),
            ),
            "unknown": PhishingDomain(
                phishing_domain=f"unknown-{suffix}.com",
                matched_asset="paypal.com",
                detection_source="dnstwist",
            ),
        }
        for row in rows.values():
            db_session.add(row)
        await db_session.commit()
        return rows

    async def _list(self, client, headers, query: str = "") -> list[dict]:
        response = await client.get(f"/api/v1/phishing/threats?size=50{query}", headers=headers)
        assert response.status_code == 200, response.text
        return response.json()["items"]

    @pytest.mark.asyncio
    async def test_each_row_carries_the_computed_age(
        self, client, aged, auth_headers_viewer
    ):
        items = await self._list(client, auth_headers_viewer)
        ages = {item["phishing_domain"]: item["domain_age_days"] for item in items}
        assert ages[aged["young"].phishing_domain] == 10
        assert ages[aged["old"].phishing_domain] == 3000
        # Not zero: nobody has resolved this candidate's registration yet.
        assert ages[aged["unknown"].phishing_domain] is None

        detail = await client.get(
            f"/api/v1/phishing/threats/{aged['young'].id}", headers=auth_headers_viewer
        )
        assert detail.json()["domain_age_days"] == 10

    @pytest.mark.asyncio
    async def test_the_age_sort_is_youngest_first_with_an_unknown_date_last(
        self, client, aged, auth_headers_viewer
    ):
        order = [aged[key].phishing_domain for key in ("young", "old", "unknown")]
        items = await self._list(client, auth_headers_viewer, "&sort=age&order=asc")
        assert [item["phishing_domain"] for item in items] == order
        oldest_first = [aged[key].phishing_domain for key in ("old", "young", "unknown")]
        items = await self._list(client, auth_headers_viewer, "&sort=age&order=desc")
        assert [item["phishing_domain"] for item in items] == oldest_first

    @pytest.mark.asyncio
    async def test_an_undeclared_sort_field_is_refused(
        self, client, aged, auth_headers_viewer
    ):
        response = await client.get(
            "/api/v1/phishing/threats?sort=domain_created_at", headers=auth_headers_viewer
        )
        assert response.status_code == 422

    def test_every_declared_sort_field_has_a_column(self):
        """The allowlist and the map behind it are one contract, checked as one."""
        from typing import get_args

        from app.api.v1.routers.phishing import _PHISHING_SORT_COLUMNS
        from app.schemas.phishing import PhishingSortField, SortDirection

        assert set(get_args(PhishingSortField)) == set(_PHISHING_SORT_COLUMNS)
        assert set(get_args(SortDirection)) == {"asc", "desc"}


class TestSourceCorroboration:
    """Which sources reported a candidate travels with the row (WI-30).

    A candidate is found by one connector and confirmed by another, and the difference
    between "one provider saw this" and "two independent providers saw this" is the
    corroboration the score pays for. The column is read from the evidence rows rather
    than stored on the candidate, so it cannot drift from what the score counted — and
    a candidate with no evidence says so instead of reprinting the connector that
    found it.
    """

    @pytest.fixture
    async def reported(self, db_session):
        from app.models import SourceObservation

        _, threats = await _seed_threats(db_session)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        reported_threat = threats[0]
        db_session.add_all(
            [
                SourceObservation(
                    module="phishing",
                    source=source,
                    observation_key=f"key-{source}-{index}",
                    subject=reported_threat.phishing_domain,
                    matched_asset=reported_threat.matched_asset,
                    candidate_id=reported_threat.id,
                    first_seen_at=now,
                    last_seen_at=now,
                    payload={},
                )
                # One source twice and a second source once: the column counts
                # providers, not observations.
                for index, source in enumerate(("netlas", "dnstwist", "dnstwist"))
            ]
        )
        await db_session.commit()
        return threats

    @pytest.mark.asyncio
    async def test_each_row_carries_the_sources_that_reported_it(
        self, client, reported, auth_headers_viewer
    ):
        response = await client.get(
            "/api/v1/phishing/threats?size=50", headers=auth_headers_viewer
        )
        assert response.status_code == 200, response.text
        items = {item["phishing_domain"]: item for item in response.json()["items"]}

        row = items[reported[0].phishing_domain]
        assert row["sources"] == ["dnstwist", "netlas"]
        assert row["source_count"] == 2

        # Nothing reported this one, and the connector that found it is a different
        # fact: the column must not fill in from `detection_source`.
        quiet = items[reported[1].phishing_domain]
        assert quiet["sources"] == []
        assert quiet["source_count"] == 0
        assert quiet["detection_source"] == reported[1].detection_source

    @pytest.mark.asyncio
    async def test_the_detail_and_update_reads_carry_them_too(
        self, client, reported, auth_headers_analyst
    ):
        detail = await client.get(
            f"/api/v1/phishing/threats/{reported[0].id}", headers=auth_headers_analyst
        )
        assert detail.json()["sources"] == ["dnstwist", "netlas"]

        updated = await client.patch(
            f"/api/v1/phishing/threats/{reported[0].id}",
            json={"status": "investigating"},
            headers=auth_headers_analyst,
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["source_count"] == 2
