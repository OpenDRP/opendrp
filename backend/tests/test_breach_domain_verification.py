"""Domain verification as a product flow, not a scan (WI-20).

A domain the source has not verified cannot be asked about at all — its 403 is
indistinguishable from "nothing was found" unless the operator is told why (F-04) — and
the only way to change that used to be the provider's own dashboard. The platform now
asks for it: `POST /api/v1/breaches/domain-verification` queues one step of the flow on
one source's account, the worker performs it and reports the TXT record or the reason,
and `GET /api/v1/breaches/provider-readiness` reads the attempt back per domain.

Three properties are asserted here, because each of them is a way this could be wrong:

* the request is a *job on one named connector*, audited whether or not it could be
  queued, and it carries no inventory: a verification that scanned as well would spend a
  scan's budget every time somebody copied a TXT record;
* a verification job is **not** the last scan: the readiness card keeps reporting the
  scan's own domains, pace and entitlements while the attempt is reported beside them;
* a summary this core does not understand is left out rather than presented as a verdict.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.main import app
from app.models.job import Job

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


async def _enabled_connector(db, name: str | None = None):
    """A registered, enabled breaches connector as the product would have it."""
    from app.services.connector_service import ConnectorService

    suffix = uuid.uuid4().hex[:8]
    connector_name = name or f"breaches-hibp-{suffix}"
    service = ConnectorService(db)
    conn = await service.get_by_name(connector_name)
    if conn is None:
        # A job type is owned by one connector, so two enabled sources of the same module
        # declare two — which is also what makes "which one is asked" a real question.
        conn = await service.register(
            name=connector_name,
            connector_type="breaches",
            api_version="1.0",
            default_job_type=f"breaches.hibp{suffix}",
        )
    conn.status = "enabled"
    await db.commit()
    await db.refresh(conn)
    return conn


async def _audit_details(db, action: str) -> list[dict]:
    rows = (
        await db.execute(
            text("SELECT details FROM drp_audit_logs WHERE action = :a ORDER BY timestamp"),
            {"a": action},
        )
    ).all()
    import json

    return [json.loads(row[0]) if isinstance(row[0], str) else row[0] for row in rows]


async def _terminal_job(
    db, *, params: dict, summary: dict, job_type: str = "breaches.hibp", finished_at=None
) -> Job:
    job = Job(
        job_type=job_type,
        title="verification",
        status="success",
        params=params,
        result_summary=summary,
        finished_at=finished_at or datetime.now(timezone.utc),
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    return job


class TestTheRequest:
    @pytest.mark.asyncio
    async def test_it_queues_one_step_on_one_source_and_records_the_attempt(
        self, client, db_session, auth_headers_analyst
    ):
        conn = await _enabled_connector(db_session)

        response = await client.post(
            "/api/v1/breaches/domain-verification",
            json={"domain": "Example.COM", "action": "generate"},
            headers=auth_headers_analyst,
        )

        assert response.status_code == 202, response.text
        body = response.json()
        assert body["status"] == "scheduled"
        assert body["domain"] == "example.com", "the domain is normalised before it is stored"
        assert body["action"] == "generate"
        assert len(body["job_ids"]) == 1

        job = (
            await db_session.execute(
                select(Job).where(Job.id == uuid.UUID(body["job_ids"][0]))
            )
        ).scalar_one()
        assert job.connector_id == conn.id, "the job belongs to the connector it was asked of"
        assert job.params["domain_verification"] == {
            "action": "generate",
            "domain": "example.com",
        }
        # A verification is not a scan: it carries no inventory, so a worker that ignored
        # the action could not quietly scan anything.
        assert job.params["emails"] == []
        assert job.params["domains"] == []

        rows = await _audit_details(db_session, "breach.domain_verification.requested")
        assert rows[-1]["domain"] == "example.com"
        assert rows[-1]["verification_action"] == "generate"
        assert rows[-1]["status"] == "scheduled"
        assert rows[-1]["jobs"] == [str(job.id)]
        assert rows[-1]["connector"] == conn.name

    @pytest.mark.asyncio
    async def test_it_refuses_to_guess_which_source_should_verify(
        self, client, db_session, auth_headers_analyst
    ):
        """A verification belongs to one account: enrolling it everywhere is not a default."""
        first = await _enabled_connector(db_session)
        second = await _enabled_connector(db_session)

        response = await client.post(
            "/api/v1/breaches/domain-verification",
            json={"domain": "example.com", "action": "verify"},
            headers=auth_headers_analyst,
        )

        assert response.status_code == 400
        assert first.name in response.text and second.name in response.text

    @pytest.mark.asyncio
    async def test_the_named_source_is_the_one_that_gets_the_job(
        self, client, db_session, auth_headers_analyst
    ):
        await _enabled_connector(db_session)
        second = await _enabled_connector(db_session)

        response = await client.post(
            "/api/v1/breaches/domain-verification",
            json={"domain": "example.com", "action": "verify", "connector": second.name},
            headers=auth_headers_analyst,
        )

        assert response.status_code == 202, response.text
        job = (
            await db_session.execute(
                select(Job).where(Job.id == uuid.UUID(response.json()["job_ids"][0]))
            )
        ).scalar_one()
        assert job.connector_id == second.id

    @pytest.mark.asyncio
    async def test_an_attempt_that_could_not_be_queued_is_recorded(
        self, client, db_session, auth_headers_analyst
    ):
        """\"Nobody asked\" and \"nobody could ask\" are different answers on the page."""
        response = await client.post(
            "/api/v1/breaches/domain-verification",
            json={"domain": "example.com", "action": "generate"},
            headers=auth_headers_analyst,
        )

        assert response.status_code == 202
        assert response.json()["status"] == "no_connector"
        assert response.json()["job_ids"] == []
        rows = await _audit_details(db_session, "breach.domain_verification.requested")
        assert rows[-1]["status"] == "no_connector"
        assert rows[-1]["error"]

    @pytest.mark.asyncio
    async def test_a_viewer_may_not_request_one(self, client, auth_headers_viewer):
        response = await client.post(
            "/api/v1/breaches/domain-verification",
            json={"domain": "example.com", "action": "generate"},
            headers=auth_headers_viewer,
        )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_a_payload_outside_the_flow_is_refused(self, client, auth_headers_analyst):
        for payload in (
            {"domain": "example.com", "action": "delete"},
            {"domain": "not a domain", "action": "generate"},
            {"domain": "example.com"},
        ):
            response = await client.post(
                "/api/v1/breaches/domain-verification",
                json=payload,
                headers=auth_headers_analyst,
            )
            assert response.status_code == 422, payload


class TestTheReadiness:
    @pytest.mark.asyncio
    async def test_the_attempt_is_reported_beside_the_domains(
        self, client, db_session, auth_headers_viewer
    ):
        await _terminal_job(
            db_session,
            params={"domains": ["example.com"], "domain_verification": {"action": "generate", "domain": "example.com"}},
            summary={
                "domain_verification": {
                    "action": "generate",
                    "domain": "example.com",
                    "status": "generated",
                    "reason": None,
                    "txt_record_value": "hibp-verify=dweb_abc123",
                }
            },
        )

        response = await client.get(
            "/api/v1/breaches/provider-readiness", headers=auth_headers_viewer
        )

        assert response.status_code == 200, response.text
        (attempt,) = response.json()["verifications"]
        assert attempt["domain"] == "example.com"
        assert attempt["action"] == "generate"
        assert attempt["status"] == "generated"
        assert attempt["reason"] is None
        # The record is passed through for an operator to publish, not summarised.
        assert attempt["txt_record_value"] == "hibp-verify=dweb_abc123"
        assert attempt["job_id"]
        assert attempt["requested_at"]

    @pytest.mark.asyncio
    async def test_a_verification_job_is_not_read_as_the_last_scan(
        self, client, db_session, auth_headers_viewer
    ):
        """The card keeps the scan's own domains, pace and entitlements (WI-14, WI-20)."""
        conn = await _enabled_connector(db_session)
        older = datetime(2026, 10, 16, tzinfo=timezone.utc)
        scan = Job(
            job_type="breaches.hibp",
            title="scan",
            status="partial",
            connector_id=conn.id,
            params={"domains": ["example.com"]},
            result_summary={
                "provider_readiness": {"subscription": "Pro", "reported_requests_per_minute": 10},
                "domains_unscanned": [{"domain": "example.com", "reason": "domain_not_verified"}],
                "pacing": {"applied_requests_per_minute": 10},
                "skipped_reasons": {"domain_not_verified": 1},
            },
            finished_at=older,
        )
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)
        await _terminal_job(
            db_session,
            params={"domain_verification": {"action": "verify", "domain": "example.com"}},
            summary={
                "domain_verification": {
                    "action": "verify",
                    "domain": "example.com",
                    "status": "verified",
                }
            },
        )

        body = (
            await client.get("/api/v1/breaches/provider-readiness", headers=auth_headers_viewer)
        ).json()

        assert body["scan_job_id"] == str(scan.id), "the newest scan, not the newest job"
        # The source the scan ran on is named, so the page can ask that account to
        # verify a domain instead of making an operator guess between several.
        assert body["connector"] == conn.name
        assert body["domains"] == [
            {"domain": "example.com", "status": "unscanned", "reason": "domain_not_verified"}
        ]
        assert body["entitlements"]["subscription"] == "Pro"
        assert body["pacing"]["applied_requests_per_minute"] == 10
        assert [item["status"] for item in body["verifications"]] == ["verified"]

    @pytest.mark.asyncio
    async def test_a_verification_does_not_move_the_new_since_boundary(
        self, client, db_session, auth_headers_viewer
    ):
        """Copying a TXT record is not a scan: it cannot make the last scan's findings old."""
        scan = Job(
            job_type="breaches.hibp",
            title="scan",
            status="success",
            params={"domains": []},
            result_summary={},
            finished_at=datetime(2026, 10, 16, 12, tzinfo=timezone.utc),
        )
        db_session.add(scan)
        await db_session.commit()
        await _terminal_job(
            db_session,
            params={"domain_verification": {"action": "verify", "domain": "example.com"}},
            summary={
                "domain_verification": {
                    "action": "verify",
                    "domain": "example.com",
                    "status": "verified",
                }
            },
            finished_at=datetime(2026, 10, 17, 12, tzinfo=timezone.utc),
        )

        body = (
            await client.get(
                "/api/v1/breaches",
                params={"new_since_last_scan": True},
                headers=auth_headers_viewer,
            )
        ).json()

        assert body["new_since"] is not None
        assert body["new_since"].startswith("2026-10-16"), (
            "measured from the scan that finished, not from the verification after it"
        )

    @pytest.mark.asyncio
    async def test_the_newest_attempt_per_domain_wins(
        self, client, db_session, auth_headers_viewer
    ):
        await _terminal_job(
            db_session,
            params={"domain_verification": {"action": "generate", "domain": "example.com"}},
            summary={
                "domain_verification": {
                    "action": "generate",
                    "domain": "example.com",
                    "status": "generated",
                    "txt_record_value": "hibp-verify=dweb_abc123",
                }
            },
            finished_at=datetime(2026, 10, 17, 9, 0, tzinfo=timezone.utc),
        )
        await _terminal_job(
            db_session,
            params={"domain_verification": {"action": "verify", "domain": "example.com"}},
            summary={
                "domain_verification": {
                    "action": "verify",
                    "domain": "example.com",
                    "status": "verified",
                }
            },
            finished_at=datetime(2026, 10, 17, 11, 30, tzinfo=timezone.utc),
        )

        body = (
            await client.get("/api/v1/breaches/provider-readiness", headers=auth_headers_viewer)
        ).json()

        assert len(body["verifications"]) == 1
        assert body["verifications"][0]["action"] == "verify"
        assert body["verifications"][0]["status"] == "verified"

    @pytest.mark.asyncio
    async def test_a_summary_the_core_does_not_understand_is_left_out(
        self, client, db_session, auth_headers_viewer
    ):
        """A verdict nobody can render is not rendered as one that said nothing."""
        await _terminal_job(
            db_session,
            params={"domain_verification": {"action": "generate", "domain": "example.com"}},
            summary={
                "domain_verification": {
                    "action": "generate",
                    "domain": "example.com",
                    "status": "who_knows",
                }
            },
        )

        body = (
            await client.get("/api/v1/breaches/provider-readiness", headers=auth_headers_viewer)
        ).json()

        assert body["verifications"] == []

    @pytest.mark.asyncio
    async def test_a_request_still_in_flight_does_not_hide_the_last_answer(
        self, client, db_session, auth_headers_viewer
    ):
        await _terminal_job(
            db_session,
            params={"domain_verification": {"action": "generate", "domain": "example.com"}},
            summary={
                "domain_verification": {
                    "action": "generate",
                    "domain": "example.com",
                    "status": "generated",
                    "txt_record_value": "hibp-verify=dweb_abc123",
                }
            },
        )
        db_session.add(
            Job(
                job_type="breaches.hibp",
                title="verification in flight",
                status="running",
                params={"domain_verification": {"action": "verify", "domain": "example.com"}},
            )
        )
        await db_session.commit()

        body = (
            await client.get("/api/v1/breaches/provider-readiness", headers=auth_headers_viewer)
        ).json()

        assert [item["status"] for item in body["verifications"]] == ["generated"]
