"""Characterization tests: hibp router gaps (Step 8).

Pins the CURRENT behavior of previously untested endpoints and branches:

* ``_asset_matches_for_breaches`` — candidate collection (matched_domain,
  matched_email, domain-from-email), the no-candidates fast path, and the
  type-matched asset resolution (domain vs email_account mismatches are
  skipped);
* ``PATCH /breaches/{id}`` — status update + ``breach.update``
  audit + matched-asset enrichment, 404 branch;
* ``POST /breaches/scan`` — the ``no_connector`` fallback: no enabled breaches
  connector → 200 with ``status="no_connector"`` and a truncated error;
* ``POST /breaches/scan-email`` / ``POST /breaches/scan-domain`` — 202 + audit with
  job ids, and 422 validation (bad email / too-short domain);
* ``DELETE /breaches/{id}`` — 204 with ``breach.delete`` audit
  carrying the pre-delete snapshot, 404 branch, analyst forbidden → 403.
"""

from __future__ import annotations

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


async def _mk_breach(
    db,
    *,
    breach_name: str | None = None,
    matched_email: str | None = None,
    matched_domain: str | None = None,
    domain: str = "example.com",
) -> Breach:
    b = Breach(
        breach_name=breach_name or f"Br-{uuid.uuid4().hex[:8]}",
        title="T",
        domain=domain,
        breach_date=date(2024, 1, 1),
        pwn_count=1000,
        matched_email=matched_email,
        matched_domain=matched_domain,
    )
    db.add(b)
    await db.commit()
    await db.refresh(b)
    return b


async def _audit_actions(db, action: str) -> list[dict]:
    from sqlalchemy import text

    rows = (
        await db.execute(
            text(
                "SELECT action, details FROM drp_audit_logs "
                "WHERE action = :a ORDER BY timestamp"
            ),
            {"a": action},
        )
    ).mappings().all()
    return [dict(r) for r in rows]


class TestAssetMatching:
    @pytest.mark.asyncio
    async    def test_breach_linked_to_both_assets_prefers_the_email_account(
        self, client, db_session, auth_headers_viewer
    ):
        from app.models.asset import Asset

        email_asset = Asset(
            asset_type="email_account", asset_value="victim@example.com", is_active=True
        )
        domain_asset = Asset(
            asset_type="domain", asset_value="matched.example.com", is_active=True
        )
        db_session.add_all([email_asset, domain_asset])
        await db_session.commit()

        breach = await _mk_breach(
            db_session,
            matched_email="victim@example.com",
            matched_domain="matched.example.com",
        )

        r = await client.get(
            f"/api/v1/breaches/{breach.id}", headers=auth_headers_viewer
        )
        assert r.status_code == 200, r.text
        body = r.json()
        # Resolution precedence: the exact email-account asset wins over the
        # domain, even when the breach row carries an explicit matched_domain.
        # A finding against ``victim@example.com`` is about that mailbox; naming
        # the parent domain hid which account was actually exposed.
        assert body["matched_asset"] == "victim@example.com"
        assert body["matched_asset_type"] == "email_account"

    @pytest.mark.asyncio
    async def test_wrong_asset_type_is_not_matched(self, client, db_session, auth_headers_viewer):
        from app.models.asset import Asset

        # A *domain* asset for the email value must NOT match the email
        # candidate (type check in the resolver).
        wrong_type = Asset(
            asset_type="domain", asset_value="victim@example.com", is_active=True
        )
        db_session.add(wrong_type)
        await db_session.commit()

        breach = await _mk_breach(db_session, matched_email="victim@example.com")
        r = await client.get(
            f"/api/v1/breaches/{breach.id}", headers=auth_headers_viewer
        )
        body = r.json()
        assert body["matched_asset"] is None
        assert body["matched_asset_type"] is None

    @pytest.mark.asyncio
    async def test_domain_candidate_matches_domain_asset(self, client, db_session, auth_headers_viewer):
        from app.models.asset import Asset

        db_session.add(
            Asset(
                asset_type="domain",
                asset_value="Matched.Example.com",  # case-insensitive store
                is_active=True,
            )
        )
        await db_session.commit()

        breach = await _mk_breach(
            db_session, matched_email=None, matched_domain="matched.example.com"
        )
        r = await client.get(
            f"/api/v1/breaches/{breach.id}", headers=auth_headers_viewer
        )
        body = r.json()
        assert body["matched_asset"] == "Matched.Example.com"
        assert body["matched_asset_type"] == "domain"

    @pytest.mark.asyncio
    async def test_inferred_domain_from_email_used_when_no_matched_domain(
        self, client, db_session, auth_headers_viewer
    ):
        from app.models.asset import Asset

        db_session.add(
            Asset(asset_type="domain", asset_value="corp.example.com", is_active=True)
        )
        await db_session.commit()

        breach = await _mk_breach(db_session, matched_email="ops@corp.example.com")
        r = await client.get(
            f"/api/v1/breaches/{breach.id}", headers=auth_headers_viewer
        )
        body = r.json()
        assert body["matched_asset"] == "corp.example.com"
        assert body["matched_asset_type"] == "domain"

    @pytest.mark.asyncio
    async def test_no_candidates_returns_empty_resolution(
        self, db_session, auth_headers_viewer
    ):
        from app.api.v1.routers.breaches import _asset_matches_for_breaches

        breach = await _mk_breach(
            db_session, matched_email=None, matched_domain=None
        )
        resolved = await _asset_matches_for_breaches(db_session, [breach])
        assert resolved == {}

    @pytest.mark.asyncio
    async def test_list_enriches_only_linked_items(
        self, client, db_session, auth_headers_viewer
    ):
        from app.models.asset import Asset

        db_session.add(
            Asset(asset_type="email_account", asset_value="hit@example.com", is_active=True)
        )
        await db_session.commit()
        hit = await _mk_breach(db_session, matched_email="hit@example.com")
        miss = await _mk_breach(db_session, matched_email="miss@nowhere.example")

        r = await client.get("/api/v1/breaches", headers=auth_headers_viewer)
        assert r.status_code == 200
        items = {i["breach_name"]: i for i in r.json()["items"]}
        assert items[hit.breach_name]["matched_asset"] == "hit@example.com"
        assert items[miss.breach_name]["matched_asset"] is None


class TestPatchBreach:
    @pytest.mark.asyncio
    async def test_update_status_audits_and_returns_enriched_payload(
        self, client, db_session, auth_headers_analyst
    ):
        from app.models.asset import Asset

        db_session.add(
            Asset(asset_type="email_account", asset_value="p@example.com", is_active=True)
        )
        await db_session.commit()
        breach = await _mk_breach(db_session, matched_email="p@example.com")

        r = await client.patch(
            f"/api/v1/breaches/{breach.id}",
            json={"status": "investigating"},
            headers=auth_headers_analyst,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "investigating"
        assert body["matched_asset"] == "p@example.com"

        await db_session.commit()
        rows = await _audit_actions(db_session, "breach.update")
        assert len(rows) == 1
        assert str(breach.id) in rows[0]["details"]
        assert "status" in rows[0]["details"]

    @pytest.mark.asyncio
    async def test_patch_missing_breach_404(self, client, auth_headers_analyst):
        r = await client.patch(
            f"/api/v1/breaches/{uuid.uuid4()}",
            json={"status": "resolved"},
            headers=auth_headers_analyst,
        )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_patch_invalid_status_422(self, client, db_session, auth_headers_analyst):
        breach = await _mk_breach(db_session)
        r = await client.patch(
            f"/api/v1/breaches/{breach.id}",
            json={"status": "nonsense"},
            headers=auth_headers_analyst,
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_patch_viewer_forbidden_403(self, client, db_session, auth_headers_viewer):
        breach = await _mk_breach(db_session)
        r = await client.patch(
            f"/api/v1/breaches/{breach.id}",
            json={"status": "resolved"},
            headers=auth_headers_viewer,
        )
        assert r.status_code == 403


class TestScanEndpoints:
    @pytest.mark.asyncio
    async def test_scan_no_connector_returns_no_connector_status(
        self, client, db_session, auth_headers_analyst
    ):
        r = await client.post("/api/v1/breaches/scan", headers=auth_headers_analyst)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "no_connector"
        assert body["job_ids"] == []
        assert "error" in body
        assert "No enabled connector" in body["error"]

        await db_session.commit()
        rows = await _audit_actions(db_session, "breach.scan.start")
        assert len(rows) == 1
        assert '"no_connector"' in rows[0]["details"]

    @pytest.mark.asyncio
    async def test_scan_email_202_audits_and_enqueues(
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
                "/api/v1/breaches/scan-email",
                json={"email": "target@example.com"},
                headers=auth_headers_analyst,
            )
            assert r.status_code == 202, r.text
            body = r.json()
            assert body["status"] == "scheduled"
            assert body["email"] == "target@example.com"
            assert len(body["job_ids"]) == 1
        finally:
            await db_session.delete(conn)
            await db_session.commit()

        await db_session.commit()
        rows = await _audit_actions(db_session, "breach.scan.email")
        assert len(rows) == 1
        assert "target@example.com" in rows[0]["details"]

    @pytest.mark.asyncio
    async def test_scan_email_invalid_422(self, client, auth_headers_analyst):
        r = await client.post(
            "/api/v1/breaches/scan-email",
            json={"email": "not-an-email"},
            headers=auth_headers_analyst,
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_scan_domain_202_audits_and_enqueues(
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
                "/api/v1/breaches/scan-domain",
                json={"domain": "watched.example.com"},
                headers=auth_headers_analyst,
            )
            assert r.status_code == 202, r.text
            body = r.json()
            assert body["status"] == "scheduled"
            assert body["domain"] == "watched.example.com"
            assert len(body["job_ids"]) == 1
        finally:
            await db_session.delete(conn)
            await db_session.commit()

        await db_session.commit()
        rows = await _audit_actions(db_session, "breach.scan.domain")
        assert len(rows) == 1
        assert "watched.example.com" in rows[0]["details"]

    @pytest.mark.asyncio
    async def test_scan_domain_too_short_422(self, client, auth_headers_analyst):
        r = await client.post(
            "/api/v1/breaches/scan-domain",
            json={"domain": "ab"},
            headers=auth_headers_analyst,
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_scan_email_viewer_forbidden_403(self, client, auth_headers_viewer):
        r = await client.post(
            "/api/v1/breaches/scan-email",
            json={"email": "x@example.com"},
            headers=auth_headers_viewer,
        )
        assert r.status_code == 403


class TestDeleteBreach:
    @pytest.mark.asyncio
    async def test_delete_204_audits_snapshot_and_row_gone(
        self, client, db_session, auth_headers_admin
    ):
        breach = await _mk_breach(
            db_session,
            matched_email="gone@example.com",
            matched_domain="gone.example.com",
            domain="breach.example.com",
        )
        breach_id = str(breach.id)

        r = await client.delete(
            f"/api/v1/breaches/{breach_id}", headers=auth_headers_admin
        )
        assert r.status_code == 204, r.text

        await db_session.commit()
        rows = await _audit_actions(db_session, "breach.delete")
        assert len(rows) == 1
        for needle in (breach_id, "gone@example.com", "gone.example.com", "breach.example.com"):
            assert needle in rows[0]["details"]

        from sqlalchemy import select as _select

        gone = (
            await db_session.execute(
                _select(Breach).where(Breach.id == breach.id)
            )
        ).scalar_one_or_none()
        assert gone is None

    @pytest.mark.asyncio
    async def test_delete_missing_404(self, client, auth_headers_admin):
        r = await client.delete(
            f"/api/v1/breaches/{uuid.uuid4()}", headers=auth_headers_admin
        )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_viewer_forbidden_403(self, client, db_session, auth_headers_viewer):
        breach = await _mk_breach(db_session)
        r = await client.delete(
            f"/api/v1/breaches/{breach.id}", headers=auth_headers_viewer
        )
        assert r.status_code == 403


class TestProviderReadiness:
    """What the last scan was allowed to ask, beside the findings it produced (WI-14).

    A list with nothing in it has two meanings, and this endpoint is where the platform
    says which: the provider was asked and had nothing, or it refused to be asked. The
    scan's own summary is the source — same wording for the page and Jobs — and the
    source's own vocabulary of data classes travels with it (F-04).
    """

    async def _finished_scan(self, db, *, domains, summary, status="partial"):
        from datetime import datetime, timezone

        from app.models.job import Job

        job = Job(
            job_type="breaches.hibp",
            status=status,
            title="Breach scan",
            params={"domains": domains, "emails": ["user@example.com"]},
            result_summary=summary,
            finished_at=datetime.now(timezone.utc),
        )
        db.add(job)
        await db.commit()
        return job

    async def _connector(self, db, *, readiness, status="enabled", name=None):
        from app.models.connector import Connector

        conn = Connector(
            name=name or f"breaches-{uuid.uuid4().hex[:8]}",
            connector_type="breaches",
            status=status,
            default_job_type=f"breaches.{uuid.uuid4().hex[:8]}",
            readiness=readiness,
        )
        db.add(conn)
        await db.commit()
        return conn

    @pytest.mark.asyncio
    async def test_no_finished_scan_is_not_a_clean_scan(self, client, auth_headers_viewer):
        r = await client.get(
            "/api/v1/breaches/provider-readiness", headers=auth_headers_viewer
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["scan_job_id"] is None
        assert body["partial"] is False
        assert body["domains"] == []
        assert body["entitlements"] is None

    @pytest.mark.asyncio
    async def test_a_refused_domain_names_the_reason_the_scan_reported(
        self, client, db_session, auth_headers_viewer
    ):
        await self._finished_scan(
            db_session,
            domains=["example.com", "other.example"],
            summary={
                "provider_readiness": {
                    "subscription": "Pro",
                    "reported_requests_per_minute": 600,
                    "includes_stealer_logs": False,
                    "includes_kanon": True,
                    "subscribed_domains": 2,
                },
                "domains_unscanned": [
                    {"domain": "example.com", "reason": "domain_not_verified"}
                ],
                "skipped_reasons": {"domain_not_verified": 1},
                "pacing": {"configured_requests_per_minute": 10, "applied_requests_per_minute": 4},
            },
        )
        r = await client.get(
            "/api/v1/breaches/provider-readiness", headers=auth_headers_viewer
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "partial"
        assert body["partial"] is True
        assert body["reasons"] == {"domain_not_verified": 1}
        assert body["entitlements"] == {
            "subscription": "Pro",
            "requests_per_minute": 600,
            "includes_stealer_logs": False,
            "includes_kanon": True,
            "domains_verified": 2,
        }
        assert body["pacing"]["applied_requests_per_minute"] == 4
        assert body["domains"] == [
            {"domain": "example.com", "status": "unscanned", "reason": "domain_not_verified"},
            {"domain": "other.example", "status": "asked", "reason": None},
        ]
        assert body["unscanned_total"] == 1

    @pytest.mark.asyncio
    async def test_a_domain_the_scan_never_reached_is_not_reported_as_asked(
        self, client, db_session, auth_headers_viewer
    ):
        """A scan stopped by its own budget cannot claim it asked about what is left."""
        await self._finished_scan(
            db_session,
            domains=["example.com"],
            summary={"budget_exhausted": True, "skipped_reasons": {"request_budget_exhausted": 1}},
        )
        body = (
            await client.get(
                "/api/v1/breaches/provider-readiness", headers=auth_headers_viewer
            )
        ).json()
        assert body["domains"] == [
            {"domain": "example.com", "status": "unknown", "reason": "scan_stopped_short"}
        ]

    @pytest.mark.asyncio
    async def test_the_last_finished_scan_is_the_one_reported(
        self, client, db_session, auth_headers_viewer
    ):
        from datetime import datetime, timedelta, timezone

        older = await self._finished_scan(
            db_session, domains=["old.example"], summary={}, status="success"
        )
        older.finished_at = datetime.now(timezone.utc) - timedelta(days=1)
        newer = await self._finished_scan(
            db_session,
            domains=["new.example"],
            summary={"skipped_reasons": {"domain_not_verified": 1}},
        )
        await db_session.commit()
        assert newer.finished_at >= older.finished_at
        body = (
            await client.get(
                "/api/v1/breaches/provider-readiness", headers=auth_headers_viewer
            )
        ).json()
        assert body["scan_job_id"] == str(newer.id)
        assert [row["domain"] for row in body["domains"]] == ["new.example"]

    @pytest.mark.asyncio
    async def test_the_data_class_labels_come_from_the_sources_that_published_them(
        self, client, db_session, auth_headers_viewer
    ):
        await self._connector(
            db_session,
            readiness={"data_class_labels": {"Passwords": "Account passwords"}},
        )
        await self._connector(
            db_session,
            status="disabled",
            readiness={"data_class_labels": {"Passwords": "from a disabled source"}},
        )
        body = (
            await client.get(
                "/api/v1/breaches/provider-readiness", headers=auth_headers_viewer
            )
        ).json()
        assert body["data_class_labels"] == {"Passwords": "Account passwords"}

    @pytest.mark.asyncio
    async def test_a_source_that_publishes_no_labels_leaves_the_stored_names(
        self, client, db_session, auth_headers_viewer
    ):
        await self._connector(db_session, readiness={"credentials_configured": True})
        body = (
            await client.get(
                "/api/v1/breaches/provider-readiness", headers=auth_headers_viewer
            )
        ).json()
        assert body["data_class_labels"] == {}

    @pytest.mark.asyncio
    async def test_the_readiness_read_requires_a_session(self, client):
        r = await client.get("/api/v1/breaches/provider-readiness")
        assert r.status_code == 401
