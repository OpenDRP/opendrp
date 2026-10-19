"""What a re-reported breach incident is allowed to say (WI-08, WI-11).

The breaches module used to be write-once in practice: an incident arrived, a row
appeared, and every later scan of the same pair was either a silent refresh or a
false alarm. Neither is a report. This suite pins the five facts a re-report can
carry — the incident came back after an operator resolved it, it now exposes a
class of data it did not, it grew by enough to matter, the source confirmed it,
its date moved — and the property that makes each one usable: **one event per
change**, because the outbox key names the change rather than the row.

``unchanged`` is the sixth outcome and the quiet one: a scan that rediscovers
exactly what the platform already stored writes no event at all, so the channel
reports arrivals rather than repetitions. The row is still refreshed — a sighting
is not a change, and ``last_seen_at`` is where it goes, which is what keeps "is
this incident still arriving?" a question the platform can answer.

The last test is the other half of F-02: the flag a reporter sets when it could
not describe the incident has to reach the API, not just the row.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.config import settings
from app.models.breach import Breach
from app.models.connector import Connector
from app.models.ingestion_event import IngestionEvent
from app.services.ingestion_service import ingest_breach_finding

#: One incident, in the shape the HIBP worker submits it.
_INCIDENT = {
    "breach_name": "Adobe",
    "matched_email": "user@corp.example",
    "breach_date": "2013-10-04",
    "pwn_count": 150_000_000,
    "data_classes": ["Email addresses", "Password hints"],
    "attributes": {"is_verified": True, "added_date": "2013-10-04T00:00:00+00:00"},
}


@pytest.fixture
async def breaches_connector(db_session):
    connector = Connector(
        name=f"conn-hibp-{uuid.uuid4().hex[:8]}",
        connector_type="breaches",
        status="enabled",
        default_job_type="breaches.hibp",
    )
    db_session.add(connector)
    await db_session.commit()
    await db_session.refresh(connector)
    return connector


async def _ingest(db, connector, **overrides) -> bool:
    """Submit one finding, defaulting to the incident above."""
    finding = {**_INCIDENT, **overrides}
    return await ingest_breach_finding(db, connector, finding)


async def _events(db) -> list[IngestionEvent]:
    rows = await db.execute(
        select(IngestionEvent)
        .where(
            IngestionEvent.kind == "notification",
            IngestionEvent.module == "breach",
        )
        .order_by(IngestionEvent.created_at, IngestionEvent.id)
    )
    return list(rows.scalars())


async def _one_row(db) -> Breach:
    return (await db.execute(select(Breach))).scalar_one()


async def _classes(db) -> list[str]:
    return [event.payload["change_class"] for event in await _events(db)]


@pytest.mark.asyncio
async def test_a_first_sighting_is_one_new_incident(db_session, breaches_connector):
    assert await _ingest(db_session, breaches_connector) is True
    assert await _classes(db_session) == ["new_incident"]


@pytest.mark.asyncio
async def test_a_scan_that_rediscovers_the_same_facts_says_nothing(
    db_session, breaches_connector
):
    """The repetition that made the channel noisy: no event, no second message."""
    assert await _ingest(db_session, breaches_connector) is True
    assert await _ingest(db_session, breaches_connector) is False
    assert await _ingest(db_session, breaches_connector) is False
    assert await _classes(db_session) == ["new_incident"]


@pytest.mark.asyncio
async def test_a_sighting_is_still_recorded_when_nothing_changed(
    db_session, breaches_connector
):
    """"Is it still arriving?" and "did it change?" are two different answers."""
    await _ingest(db_session, breaches_connector)
    first_seen = (await _one_row(db_session)).last_seen_at
    assert first_seen is not None
    await _ingest(db_session, breaches_connector)
    row = await _one_row(db_session)
    assert row.last_seen_at is not None and row.last_seen_at >= first_seen
    # The row was touched by a sighting, and still produced no delivery.
    assert await _classes(db_session) == ["new_incident"]


@pytest.mark.asyncio
async def test_growth_past_the_floor_is_one_incident_grew(db_session, breaches_connector):
    await _ingest(db_session, breaches_connector)
    grown = {**_INCIDENT, "pwn_count": _INCIDENT["pwn_count"] + 5}
    assert await ingest_breach_finding(db_session, breaches_connector, grown) is True
    assert await _classes(db_session) == ["new_incident", "incident_grew"]
    # ...and the grown count itself is not reported again.
    assert await ingest_breach_finding(db_session, breaches_connector, grown) is False
    assert await _classes(db_session) == ["new_incident", "incident_grew"]


@pytest.mark.asyncio
async def test_a_source_editing_its_own_count_below_the_floor_is_silent(
    db_session, breaches_connector, monkeypatch
):
    """A correction of a few accounts out of millions is bookkeeping, not news."""
    monkeypatch.setattr(settings, "ALERT_BREACH_GROWTH_FLOOR", 1000)
    await _ingest(db_session, breaches_connector)
    small_edit = {**_INCIDENT, "pwn_count": _INCIDENT["pwn_count"] + 50}
    assert await ingest_breach_finding(db_session, breaches_connector, small_edit) is True
    assert await _classes(db_session) == ["new_incident"]
    # The row moved while the channel stayed quiet: silence is about what is worth
    # reporting, not about what is stored.
    assert (await _one_row(db_session)).pwn_count == _INCIDENT["pwn_count"] + 50


@pytest.mark.asyncio
async def test_a_new_class_of_data_is_reported_once(db_session, breaches_connector):
    await _ingest(db_session, breaches_connector)
    wider = {
        **_INCIDENT,
        "pwn_count": _INCIDENT["pwn_count"] + 1_000,
        "data_classes": [*_INCIDENT["data_classes"], "Passwords"],
    }
    assert await ingest_breach_finding(db_session, breaches_connector, wider) is True
    # A wider class of data is what the operator has to act on, so it leads even
    # when the incident also grew.
    assert await _classes(db_session) == ["new_incident", "new_data_class"]
    assert await ingest_breach_finding(db_session, breaches_connector, wider) is False
    assert await _classes(db_session) == ["new_incident", "new_data_class"]


@pytest.mark.asyncio
async def test_a_later_verification_is_one_event_and_records_its_instant(
    db_session, breaches_connector
):
    unverified = {**_INCIDENT, "attributes": {"is_verified": False}}
    assert await ingest_breach_finding(db_session, breaches_connector, unverified) is True
    assert (await _one_row(db_session)).verified_at is None
    confirmed = {**_INCIDENT, "attributes": {"is_verified": True}}
    assert await ingest_breach_finding(db_session, breaches_connector, confirmed) is True
    row = await _one_row(db_session)
    assert await _classes(db_session) == ["new_incident", "now_verified"]
    assert row.verified_at is not None
    confirmed_at = row.verified_at
    assert await ingest_breach_finding(db_session, breaches_connector, confirmed) is False
    assert (await _one_row(db_session)).verified_at == confirmed_at


@pytest.mark.asyncio
async def test_a_corrected_date_is_reported_once(db_session, breaches_connector):
    await _ingest(db_session, breaches_connector)
    corrected = {**_INCIDENT, "breach_date": "2013-10-05"}
    assert await ingest_breach_finding(db_session, breaches_connector, corrected) is True
    assert await _classes(db_session) == ["new_incident", "date_corrected"]
    assert await ingest_breach_finding(db_session, breaches_connector, corrected) is False
    assert await _classes(db_session) == ["new_incident", "date_corrected"]


@pytest.mark.asyncio
async def test_a_resolved_incident_that_reappears_is_one_event_and_stays_resolved(
    db_session, breaches_connector
):
    """A re-report is news; undoing the analyst's resolution is not the ingest's."""
    await _ingest(db_session, breaches_connector)
    row = await _one_row(db_session)
    row.status = "resolved"
    await db_session.commit()

    assert await _ingest(db_session, breaches_connector) is True
    assert await _classes(db_session) == ["new_incident", "reappeared"]
    assert (await _one_row(db_session)).status == "resolved"


@pytest.mark.asyncio
async def test_each_real_change_is_a_delivery_while_the_repeat_is_not(
    db_session, breaches_connector
):
    """Two growths are two events with different keys; a repeat is neither."""
    await _ingest(db_session, breaches_connector)
    for count in (_INCIDENT["pwn_count"] + 10, _INCIDENT["pwn_count"] + 20):
        assert await _ingest(db_session, breaches_connector, pwn_count=count) is True
    assert await _ingest(
        db_session, breaches_connector, pwn_count=_INCIDENT["pwn_count"] + 20
    ) is False
    events = await _events(db_session)
    assert [event.payload["change_class"] for event in events] == [
        "new_incident",
        "incident_grew",
        "incident_grew",
    ]
    # The outbox key is what makes a repeat of the same change impossible, and it
    # has to differ between two real changes.
    assert len({event.event_key for event in events}) == 3


@pytest.mark.asyncio
async def test_a_report_without_a_date_is_refused_unless_the_reporter_says_so(
    db_session, breaches_connector
):
    """No 1970-01-01 is reachable from this path (F-02)."""
    assert await _ingest(db_session, breaches_connector, breach_date=None) is False
    assert await _events(db_session) == []

    admitted = {
        **_INCIDENT,
        "breach_date": None,
        "attributes": {"metadata_incomplete": True, "source": "paste:42"},
    }
    assert await ingest_breach_finding(db_session, breaches_connector, admitted) is True
    row = await _one_row(db_session)
    assert row.metadata_incomplete is True
    # The observation instant, in the platform's own timezone: not the incident's
    # date, and not the local day either.
    assert row.breach_date == datetime.now(timezone.utc).date()


@pytest.mark.asyncio
async def test_the_api_says_the_metadata_is_incomplete(
    db_session, breaches_connector, auth_headers_viewer
):
    """The flag has to survive to the page, or the date reads as a fact."""
    from app.main import app

    admitted = {
        **_INCIDENT,
        "breach_date": None,
        "attributes": {"metadata_incomplete": True, "source": "paste:42"},
    }
    await ingest_breach_finding(db_session, breaches_connector, admitted)
    row = await _one_row(db_session)
    await db_session.commit()

    async def _override():
        yield db_session

    from app.api.deps import get_db

    app.dependency_overrides[get_db] = _override
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get(
                f"/api/v1/breaches/{row.id}", headers=auth_headers_viewer
            )
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["metadata_incomplete"] is True
    assert body["last_seen_at"] is not None
