"""Triage of a breach list: how loud a row is and which rows are worth seeing (F-13).

The list used to answer "what is in the database", ordered by arrival. An operator
opening it with a morning's worth of findings needs the other two questions: *what can
be done with this data* (severity, from the classes of data exposed) and *which rows
match the decision I am about to make* (filters by severity, source flag, source and
domain), plus the fact that the address on a row is not new to the platform.

The severity is written when the row is written, from one rule
(`app/services/breach_severity.py`), because three implementations of one rule would
disagree about the same row.
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.main import app
from app.models import Breach, Connector
from app.services.breach_severity import severity_for_data_classes, severity_rank

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


@pytest_asyncio.fixture()
async def breaches_connector(db_session):
    connector = Connector(
        name=f"conn-triage-{uuid.uuid4().hex[:8]}",
        connector_type="breaches",
        status="enabled",
        default_job_type="breaches.test",
    )
    db_session.add(connector)
    await db_session.commit()
    await db_session.refresh(connector)
    return connector


async def _ingest(db, connector, finding: dict) -> bool:
    from app.services.ingestion_service import ingest_breach_finding

    return await ingest_breach_finding(db, connector, finding)


def _finding(overrides: dict | None = None) -> dict:
    suffix = uuid.uuid4().hex[:8]
    body = {
        "breach_name": f"Incident-{suffix}",
        "title": "Incident",
        "domain": "vendor.example",
        "breach_date": "2024-01-01",
        "pwn_count": 1000,
        "data_classes": ["Email addresses"],
        "matched_email": f"user-{suffix}@acme.test",
        "attributes": {},
    }
    body.update(overrides or {})
    return body


async def _rows(db, name: str) -> list[Breach]:
    return list(
        (await db.execute(select(Breach).where(Breach.breach_name == name))).scalars().all()
    )


class TestTheRule:
    def test_plaintext_credentials_are_the_loudest_thing_a_breach_exposes(self):
        assert severity_for_data_classes(["Passwords"]) == "critical"
        assert severity_for_data_classes(["Plain text passwords"]) == "critical"

    def test_hashed_credentials_are_not_the_same_exposure_as_plaintext_ones(self):
        # "Hashed passwords" contains "password"; classifying it as critical would tell
        # an operator to force a reset on evidence that cannot be replayed as-is.
        assert severity_for_data_classes(["Hashed passwords"]) == "high"
        assert severity_for_data_classes(["Password hints"]) == "medium"

    def test_payment_and_recovery_data_are_critical(self):
        assert severity_for_data_classes(["Credit cards"]) == "critical"
        assert severity_for_data_classes(["Bank account numbers"]) == "critical"
        assert severity_for_data_classes(["Security questions and answers"]) == "critical"

    def test_identity_details_rank_below_credentials(self):
        assert severity_for_data_classes(["Physical addresses"]) == "medium"
        assert severity_for_data_classes(["Phone numbers"]) == "medium"
        assert severity_for_data_classes(["Email addresses"]) == "low"
        assert severity_for_data_classes(["Usernames"]) == "low"

    def test_the_loudest_class_on_a_row_wins(self):
        assert (
            severity_for_data_classes(["Email addresses", "Names", "Passwords"]) == "critical"
        )

    def test_a_class_the_rule_has_never_seen_is_unknown_rather_than_low(self):
        # "Unknown" is a statement about the platform, not about the incident: ranking
        # it at the bottom would quietly call an unrecognized leak a harmless one.
        assert severity_for_data_classes(["Astrological signs and mystical data"]) == "unknown"
        assert severity_for_data_classes([]) == "unknown"
        assert severity_for_data_classes(None) == "unknown"

    def test_unknown_sorts_below_low(self):
        assert severity_rank("critical") > severity_rank("high") > severity_rank("medium")
        assert severity_rank("medium") > severity_rank("low") > severity_rank("unknown")
        assert severity_rank(None) == severity_rank("nonsense")


class TestTheStoredRow:
    @pytest.mark.asyncio
    async def test_ingestion_writes_the_severity_of_the_classes_it_stored(
        self, db_session, breaches_connector
    ):
        finding = _finding({"data_classes": ["Passwords", "Email addresses"]})
        assert await _ingest(db_session, breaches_connector, finding) is True
        await db_session.commit()

        row = (await _rows(db_session, finding["breach_name"]))[0]
        assert row.severity == "critical"
        # The classes themselves stay as the source stated them: severity is derived,
        # not a rewrite of the evidence.
        assert row.data_classes == ["Passwords", "Email addresses"]

    @pytest.mark.asyncio
    async def test_a_correction_to_the_classes_moves_the_severity(
        self, db_session, breaches_connector
    ):
        finding = _finding({"data_classes": ["Email addresses"]})
        await _ingest(db_session, breaches_connector, finding)
        await db_session.commit()

        corrected = {**finding, "data_classes": ["Passwords"]}
        assert await _ingest(db_session, breaches_connector, corrected) is True
        await db_session.commit()

        rows = await _rows(db_session, finding["breach_name"])
        assert len(rows) == 1, "a correction updates the incident it is about"
        assert rows[0].severity == "critical"


class TestTheFilters:
    @pytest.mark.asyncio
    async def test_severity_filter_and_sort_read_the_stored_value(
        self, client, db_session, breaches_connector, auth_headers_viewer
    ):
        low = _finding({"data_classes": ["Email addresses"]})
        critical = _finding({"data_classes": ["Passwords"]})
        await _ingest(db_session, breaches_connector, low)
        await _ingest(db_session, breaches_connector, critical)
        await db_session.commit()

        body = (
            await client.get(
                "/api/v1/breaches",
                params={"severity": "critical", "size": 100},
                headers=auth_headers_viewer,
            )
        ).json()
        names = {item["breach_name"] for item in body["items"]}
        assert critical["breach_name"] in names
        assert low["breach_name"] not in names
        assert all(item["severity"] == "critical" for item in body["items"])

        ordered = (
            await client.get(
                "/api/v1/breaches",
                params={"sort": "severity", "order": "desc", "size": 100},
                headers=auth_headers_viewer,
            )
        ).json()["items"]
        ranks = [severity_rank(item["severity"]) for item in ordered]
        assert ranks == sorted(ranks, reverse=True), "the loudest finding heads the list"

    @pytest.mark.asyncio
    async def test_a_severity_outside_the_vocabulary_is_refused(
        self, client, auth_headers_viewer
    ):
        response = await client.get(
            "/api/v1/breaches", params={"severity": "catastrophic"}, headers=auth_headers_viewer
        )
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_a_flag_filter_asks_the_source_s_own_payload(
        self, client, db_session, breaches_connector, auth_headers_viewer
    ):
        verified = _finding({"attributes": {"is_verified": True}})
        unverified = _finding({"attributes": {"is_verified": False}})
        await _ingest(db_session, breaches_connector, verified)
        await _ingest(db_session, breaches_connector, unverified)
        await db_session.commit()

        body = (
            await client.get(
                "/api/v1/breaches",
                params={"flag": "verified", "size": 100},
                headers=auth_headers_viewer,
            )
        ).json()
        names = {item["breach_name"] for item in body["items"]}
        assert verified["breach_name"] in names
        assert unverified["breach_name"] not in names

    @pytest.mark.asyncio
    async def test_status_filter_reads_the_triage_state_an_operator_set(
        self, client, db_session, breaches_connector, auth_headers_analyst
    ):
        untouched = _finding()
        working = _finding()
        await _ingest(db_session, breaches_connector, untouched)
        await _ingest(db_session, breaches_connector, working)
        await db_session.commit()

        row = (await _rows(db_session, working["breach_name"]))[0]
        patch = await client.patch(
            f"/api/v1/breaches/{row.id}",
            json={"status": "investigating"},
            headers=auth_headers_analyst,
        )
        assert patch.status_code == 200, patch.text

        body = (
            await client.get(
                "/api/v1/breaches",
                params={"status": "investigating", "size": 100},
                headers=auth_headers_analyst,
            )
        ).json()
        # The status is the operator's decision, so the filter answers "what is still
        # open" rather than repeating the source's own flags.
        assert {item["breach_name"] for item in body["items"]} == {working["breach_name"]}

    @pytest.mark.asyncio
    async def test_source_and_domain_filters(
        self, client, db_session, breaches_connector, auth_headers_viewer
    ):
        mine = _finding({"matched_email": "someone@acme.test"})
        other = _finding({"matched_email": "someone@other.test"})
        await _ingest(db_session, breaches_connector, mine)
        await _ingest(db_session, breaches_connector, other)
        await db_session.commit()

        by_domain = (
            await client.get(
                "/api/v1/breaches",
                params={"domain": "ACME.test", "size": 100},
                headers=auth_headers_viewer,
            )
        ).json()
        # The address at the domain is what is monitored; the filter is about the
        # domain, not about the spelling somebody typed.
        assert {item["breach_name"] for item in by_domain["items"]} == {mine["breach_name"]}

        by_source = (
            await client.get(
                "/api/v1/breaches",
                params={"source": "no-such-source", "size": 100},
                headers=auth_headers_viewer,
            )
        ).json()
        assert by_source["items"] == []


class TestTheAggregate:
    @pytest.mark.asyncio
    async def test_an_address_in_three_incidents_says_so_on_each_row(
        self, client, db_session, breaches_connector, auth_headers_viewer
    ):
        email = "repeat@acme.test"
        for _ in range(3):
            await _ingest(
                db_session, breaches_connector, _finding({"matched_email": email})
            )
        await _ingest(
            db_session,
            breaches_connector,
            _finding({"matched_email": "once@acme.test", "breach_date": str(date(2024, 2, 2))}),
        )
        await db_session.commit()

        body = (
            await client.get(
                "/api/v1/breaches", params={"size": 100}, headers=auth_headers_viewer
            )
        ).json()

        counts = {
            item["matched_email"]: item["email_incident_count"] for item in body["items"]
        }
        assert counts[email] == 3
        assert counts["once@acme.test"] == 1

    @pytest.mark.asyncio
    async def test_the_count_is_about_the_address_not_about_the_filter(
        self, client, db_session, breaches_connector, auth_headers_viewer
    ):
        email = "filtered@acme.test"
        critical = _finding({"matched_email": email, "data_classes": ["Passwords"]})
        low = _finding({"matched_email": email, "data_classes": ["Email addresses"]})
        await _ingest(db_session, breaches_connector, critical)
        await _ingest(db_session, breaches_connector, low)
        await db_session.commit()

        body = (
            await client.get(
                "/api/v1/breaches",
                params={"severity": "critical", "domain": "acme.test", "size": 100},
                headers=auth_headers_viewer,
            )
        ).json()

        row = next(item for item in body["items"] if item["breach_name"] == critical["breach_name"])
        assert row["email_incident_count"] == 2, (
            "triaging the loud row must show the quiet one it shares an address with"
        )
