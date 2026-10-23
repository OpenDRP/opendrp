"""The candidate surface's refusals and side effects, over HTTP.

The verdict path has its own file (``test_phishing_verdict``). This one pins what
the rest of the router does when a row is missing, a domain cannot be monitored,
a scan is already in flight, or an analyst asks for one candidate by id — the
answers an operator meets on a bad day rather than on a good one.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.core.exceptions import ConflictException
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.phishing import PhishingDomain
from app.services.asset_service import AssetService
from app.services.scan_admission import ScanAlreadyRunning


def _candidate(
    domain: str, *, matched: str = "egov.kz", confidence: int = 40, **kwargs
) -> PhishingDomain:
    return PhishingDomain(
        phishing_domain=domain,
        matched_asset=matched,
        detection_source="dnstwist",
        status="active",
        confidence=confidence,
        signals={},
        **kwargs,
    )


async def _actions(db, prefix: str) -> list[AuditLog]:
    rows = (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.action.like(f"{prefix}%"))
            .order_by(AuditLog.timestamp, AuditLog.id)
        )
    ).scalars().all()
    return list(rows)


class TestListing:
    @pytest.mark.asyncio
    async def test_one_candidate_can_be_read_back_by_id(
        self, client, db_session, auth_headers_viewer
    ):
        """The detail page deep-links: the filter is the by-id read of the list."""
        wanted = _candidate("look-alike.example")
        other = _candidate("another.example")
        db_session.add_all([wanted, other])
        await db_session.commit()

        response = await client.get(
            "/api/v1/phishing/threats",
            headers=auth_headers_viewer,
            params={"finding_id": str(wanted.id)},
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["total"] == 1
        assert [row["id"] for row in body["items"]] == [str(wanted.id)]


class TestMissingRows:
    @pytest.mark.asyncio
    async def test_every_row_scoped_route_answers_404_for_an_unknown_id(
        self, client, db_session, auth_headers_analyst
    ):
        """One answer for read, decide, promote and delete: the row is not there."""
        missing = uuid.uuid4()

        read = await client.get(
            f"/api/v1/phishing/threats/{missing}", headers=auth_headers_analyst
        )
        decide = await client.patch(
            f"/api/v1/phishing/threats/{missing}",
            headers=auth_headers_analyst,
            json={"verdict": "confirmed"},
        )
        promote = await client.post(
            f"/api/v1/phishing/threats/{missing}/asset", headers=auth_headers_analyst
        )
        delete = await client.delete(
            f"/api/v1/phishing/threats/{missing}", headers=auth_headers_analyst
        )

        assert [read.status_code, decide.status_code, promote.status_code, delete.status_code] == [
            404,
            404,
            404,
            404,
        ]
        assert decide.json()["detail"] == "Phishing threat not found"
        assert promote.json()["detail"] == "Threat not found"


class TestPromotion:
    @pytest.mark.asyncio
    async def test_a_candidate_whose_domain_cannot_be_monitored_is_refused(
        self, client, db_session, auth_headers_analyst
    ):
        """A stored value the validator rejects is a 409, not a half-created asset."""
        candidate = _candidate("not a domain at all")
        db_session.add(candidate)
        await db_session.commit()

        response = await client.post(
            f"/api/v1/phishing/threats/{candidate.id}/asset",
            headers=auth_headers_analyst,
        )

        assert response.status_code == 409
        assert "cannot be promoted" in response.json()["detail"]
        assert (await db_session.execute(select(Asset))).scalars().all() == []

    @pytest.mark.asyncio
    async def test_promoting_twice_reports_the_asset_it_already_has(
        self, client, db_session, auth_headers_analyst
    ):
        """The throttle and the audit row still apply to an already-monitored value."""
        candidate = _candidate("look-alike-promote.example")
        db_session.add(candidate)
        await db_session.commit()

        first = await client.post(
            f"/api/v1/phishing/threats/{candidate.id}/asset",
            headers=auth_headers_analyst,
        )
        second = await client.post(
            f"/api/v1/phishing/threats/{candidate.id}/asset",
            headers=auth_headers_analyst,
        )

        assert first.status_code == 201, first.text
        assert first.json()["already_exists"] is False
        assert second.status_code == 201, second.text
        assert second.json()["already_exists"] is True
        assert second.json()["asset"]["id"] == first.json()["asset"]["id"]

        actions = [row.action for row in await _actions(db_session, "phishing.asset.")]
        assert actions == ["phishing.asset.promoted", "phishing.asset.already_exists"]
        already = (await _actions(db_session, "phishing.asset.already_exists"))[0]
        assert already.details["promoted_from"] == "phishing"
        assert already.details["asset_value"] == "look-alike-promote.example"

    @pytest.mark.asyncio
    async def test_a_concurrent_writer_does_not_turn_a_promotion_into_an_error(
        self, client, db_session, auth_headers_analyst, monkeypatch
    ):
        """The unique constraint is the authority; the route answers with that row.

        The pre-check runs in the same transaction as the insert, so the value can
        still be taken between the two by another replica. What must not happen is
        a 500 on an asset that now exists.
        """
        candidate = _candidate("raced-promotion.example")
        db_session.add(candidate)
        await db_session.commit()

        original = AssetService.create_asset

        async def _raced(self, data, *, commit: bool = True):
            # The other replica wins first: the row is inserted, then this call
            # discovers the conflict the unique constraint would have raised.
            await original(self, data, commit=commit)
            raise ConflictException("asset already exists")

        monkeypatch.setattr(AssetService, "create_asset", _raced)

        response = await client.post(
            f"/api/v1/phishing/threats/{candidate.id}/asset",
            headers=auth_headers_analyst,
        )

        assert response.status_code == 201, response.text
        assert response.json()["already_exists"] is True
        assert response.json()["asset"]["asset_value"] == "raced-promotion.example"
        rows = (await db_session.execute(select(Asset))).scalars().all()
        assert len(rows) == 1


    @pytest.mark.asyncio
    async def test_a_conflict_with_no_row_behind_it_is_still_a_refusal(
        self, client, db_session, auth_headers_analyst, monkeypatch
    ):
        """If the value is not there, the conflict was real and must not be swallowed."""
        candidate = _candidate("unexplained-conflict.example")
        db_session.add(candidate)
        await db_session.commit()

        async def _refused(self, data, *, commit: bool = True):
            raise ConflictException("refused by the store")

        monkeypatch.setattr(AssetService, "create_asset", _refused)

        response = await client.post(
            f"/api/v1/phishing/threats/{candidate.id}/asset",
            headers=auth_headers_analyst,
        )

        assert response.status_code == 409
        assert response.json()["detail"] == "refused by the store"


class TestDeletion:
    @pytest.mark.asyncio
    async def test_deleting_a_candidate_records_what_was_removed(
        self, client, db_session, auth_headers_analyst
    ):
        candidate = _candidate("gone.example", ip_address="203.0.113.4")
        db_session.add(candidate)
        await db_session.commit()
        candidate_id = candidate.id

        response = await client.delete(
            f"/api/v1/phishing/threats/{candidate_id}", headers=auth_headers_analyst
        )

        assert response.status_code == 204
        remaining = (
            await db_session.execute(
                select(PhishingDomain).where(PhishingDomain.id == candidate_id)
            )
        ).scalar_one_or_none()
        assert remaining is None
        rows = await _actions(db_session, "phishing.threat.delete")
        assert len(rows) == 1
        # The row is gone; its identifying facts survive in the trail.
        assert rows[0].details["phishing_domain"] == "gone.example"
        assert rows[0].details["ip_address"] == "203.0.113.4"
        assert rows[0].details["detection_source"] == "dnstwist"


class TestScanAdmission:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("source", ["dnstwist", "shodan"])
    async def test_a_refused_scan_slot_is_not_reported_as_scheduled(
        self, client, db_session, auth_headers_analyst, monkeypatch, source
    ):
        """409 is the answer; turning it into a 202 would hide that nothing queued."""
        from app.services import connector_service as service_module
        from app.services.connector_service import ConnectorService

        svc = ConnectorService(db_session)
        if await svc.get_by_name(source) is None:
            await svc.register(
                name=source,
                connector_type="phishing",
                api_version="1.0",
                default_job_type=f"phishing.{source}",
            )
        await db_session.commit()

        async def _acquire(name, *, ttl_seconds):
            raise ScanAlreadyRunning(name)

        monkeypatch.setattr(service_module, "acquire_scan_slot", _acquire)

        response = await client.post(
            f"/api/v1/phishing/scan/{source}", headers=auth_headers_analyst
        )

        assert response.status_code == 409
        assert source in response.json()["detail"]
        assert await _actions(db_session, "phishing.scan.") == []


class TestClock:
    @pytest.mark.asyncio
    async def test_the_list_reports_the_policy_in_force(
        self, client, db_session, auth_headers_viewer
    ):
        """The band beside a candidate is today's policy, not a stored one."""
        db_session.add(_candidate("banded.example", confidence=90))
        await db_session.commit()

        response = await client.get("/api/v1/phishing/threats", headers=auth_headers_viewer)

        assert response.status_code == 200
        row = response.json()["items"][0]
        assert row["confidence"] == 90
        assert row["alert_band"] in {"direct", "digest", "list"}
