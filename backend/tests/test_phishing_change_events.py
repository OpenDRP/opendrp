"""An arrival *and* a change for the phishing module (WI-03, W0.1).

The module alerted on one thing only — the first sighting of a candidate — and was
silent about everything that happened to it afterwards, so a lookalike that moved to
a new address, published new ports, or was re-attributed to another brand looked
exactly like one nobody had touched since (F-04 in the phishing audit). These tests
pin the arrival rules WI-03 introduces: the first sighting is
``phishing.candidate.created``, a revision of one of the four fields the platform
tracks is ``phishing.candidate.changed`` carrying both values, re-observing the same
fact is silence, and a replay that changes nothing is ``unchanged``.
"""

import pytest
from sqlalchemy import select

from app.models import Connector, IngestionEvent
from app.services.ingestion_service import ingest_findings


def finding(**overrides) -> dict:
    base = {"phishing_domain": "evil.example.com", "matched_asset": "example.com"}
    base.update(overrides)
    return base


async def phishing_connector(db) -> Connector:
    connector = Connector(
        name="dnstwist-phishing-default",
        connector_type="phishing",
        default_job_type="phishing.dnstwist",
        status="enabled",
    )
    db.add(connector)
    await db.flush()
    return connector


async def feed(db, connector, item) -> str:
    """Ingest one finding and answer the outcome the service reported."""
    result = await ingest_findings(db, connector=connector, job_id=None, findings=[item])
    await db.commit()
    if result.created:
        return "created"
    if result.rejected:
        return "rejected"
    return "updated" if result.updated else "unchanged"


async def notifications(db) -> list[IngestionEvent]:
    events = list((await db.execute(select(IngestionEvent))).scalars())
    return [event for event in events if event.kind == "notification"]


def changes(events: list[IngestionEvent]) -> list[IngestionEvent]:
    return [e for e in events if e.payload.get("rule") == "phishing.candidate.changed"]


@pytest.mark.asyncio
async def test_the_first_sighting_is_one_arrival(db_session):
    connector = await phishing_connector(db_session)
    assert await feed(db_session, connector, finding()) == "created"
    events = await notifications(db_session)
    assert len(events) == 1
    assert events[0].payload["rule"] == "phishing.candidate.created"
    assert events[0].payload["severity"] == "info"
    assert events[0].payload["phishing_domain"] == "evil.example.com"


@pytest.mark.asyncio
async def test_a_changed_address_is_one_event_and_a_repeat_is_silence(db_session):
    connector = await phishing_connector(db_session)
    await feed(db_session, connector, finding(ip_address="203.0.113.10"))
    assert len(await notifications(db_session)) == 1

    assert (
        await feed(db_session, connector, finding(ip_address="203.0.113.11"))
        == "updated"
    )
    events = await notifications(db_session)
    assert len(events) == 2
    changed = changes(events)
    assert len(changed) == 1
    assert changed[0].payload["Field"] == "IP address"
    assert changed[0].payload["Previous value"] == "203.0.113.10"
    assert changed[0].payload["Current value"] == "203.0.113.11"
    assert changed[0].payload["finding_id"] == events[0].payload["finding_id"]

    # The same pair again is the same fact, not a second revision.
    assert (
        await feed(db_session, connector, finding(ip_address="203.0.113.11"))
        == "unchanged"
    )
    assert len(await notifications(db_session)) == 2


@pytest.mark.asyncio
async def test_a_retargeted_candidate_reports_the_asset_it_moved_to(db_session):
    connector = await phishing_connector(db_session)
    await feed(db_session, connector, finding())
    assert await feed(db_session, connector, finding(matched_asset="brand.example")) == (
        "updated"
    )
    changed = changes(await notifications(db_session))
    assert len(changed) == 1
    assert changed[0].payload["Field"] == "Matched asset"
    assert changed[0].payload["Previous value"] == "example.com"
    assert changed[0].payload["Current value"] == "brand.example"
    assert changed[0].payload["matched_asset"] == "brand.example"


@pytest.mark.asyncio
async def test_two_revised_fields_are_one_event_naming_both(db_session):
    connector = await phishing_connector(db_session)
    await feed(db_session, connector, finding(ip_address="203.0.113.10", web_ports="80"))
    assert await feed(
        db_session, connector, finding(ip_address="203.0.113.11", web_ports="80,443")
    ) == "updated"
    changed = changes(await notifications(db_session))
    assert len(changed) == 1
    assert changed[0].payload["Field"] == "IP address; Web ports"
    assert changed[0].payload["Previous value"] == "203.0.113.10; 80"
    assert changed[0].payload["Current value"] == "203.0.113.11; 80,443"


@pytest.mark.asyncio
async def test_a_replay_that_changes_nothing_writes_no_change_event(db_session):
    connector = await phishing_connector(db_session)
    await feed(db_session, connector, finding(web_ports="80,443", original_domain="example.com"))
    before = len(await notifications(db_session))
    assert (
        await feed(
            db_session, connector, finding(web_ports="80,443", original_domain="example.com")
        )
        == "unchanged"
    )
    assert len(await notifications(db_session)) == before


@pytest.mark.asyncio
async def test_a_change_before_enrichment_does_not_repeat_the_creation(db_session):
    """The change event carries the entity's own key, so re-deriving it is silence.

    A candidate is identified by its domain, and the row keeps that identity across
    revisions: the outbox row for a revision must therefore be keyed by *what*
    changed, or the first change would collide with the creation event and be
    swallowed (the same reason DNS arrivals pass a dedup digest).
    """
    connector = await phishing_connector(db_session)
    await feed(db_session, connector, finding(original_domain="example.com"))
    assert await feed(
        db_session, connector, finding(original_domain="example.net")
    ) == "updated"
    events = await notifications(db_session)
    kinds = [event.payload.get("rule") for event in events]
    assert kinds == ["phishing.candidate.created", "phishing.candidate.changed"]
    await feed(db_session, connector, finding(original_domain="example.net"))
    assert len(await notifications(db_session)) == 2
