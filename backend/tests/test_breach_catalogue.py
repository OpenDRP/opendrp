"""The source's incident catalogue, and what its diff is worth (F-09, WI-13).

A finding can only exist for an address somebody put in the inventory, so the platform
used to learn about a breach of a domain it watches only after an operator had added an
address of that domain. The catalogue is the other half — what the source knows about
incidents at large — and this suite pins the four things that make it trustworthy:

* the diff is the platform's own (the provider has no "added since" question), so a
  first sweep creates rows and a repeated sweep creates none;
* an incident naming a domain that is watched is announced **once**, and only when it is
  new: a second sweep of the same catalogue is silent, which is what keeps this from
  being a news feed;
* an incident at a domain nobody watches is stored, not announced — the catalogue is
  wider than the inventory on purpose;
* an empty catalogue is not a clean one. A source that answered nothing, and a source
  that was never asked, both say so; neither may read as "there is nothing to find".
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.asset import Asset, AssetType
from app.models.breach import BreachCatalogue
from app.models.ingestion_event import IngestionEvent
from app.services.breach_catalogue import (
    CATALOGUE_STALE_AFTER_HOURS,
    catalogue_state,
    catalogue_window,
    sync_catalogue,
)

#: One incident as a connector submits it: the source's own facts, no match.
def _entry(name: str = "Adobe", **overrides) -> dict:
    entry = {
        "breach_name": name,
        "title": f"{name} incident",
        "domain": "vendor.example",
        "breach_date": date(2020, 1, 1),
        "added_date": datetime(2020, 1, 1, tzinfo=timezone.utc),
        "modified_date": datetime(2020, 1, 2, tzinfo=timezone.utc),
        "pwn_count": 100,
        "data_classes": ["Email addresses"],
        "attributes": {"is_verified": True, "is_spam_list": False},
    }
    entry.update(overrides)
    return entry


def _wire(entry: dict) -> dict:
    """The same entry as it travels: JSON has no date type, so the timestamps are text.

    The connector sends what its provider parser produced (ISO text) and the entry schema
    coerces it, so a test that posted Python objects would be checking a shape no worker
    can send.
    """
    payload = dict(entry)
    for key in ("breach_date", "added_date", "modified_date"):
        value = payload.get(key)
        if value is not None and not isinstance(value, str):
            payload[key] = value.isoformat()
    return payload


async def _watch(db, value: str, *, active: bool = True) -> Asset:
    """A monitored domain in the inventory, in the shape the platform stores it."""
    asset = Asset(
        asset_type=AssetType.domain.value,
        asset_value=value,
        normalized_value=value,
        is_active=active,
    )
    db.add(asset)
    await db.commit()
    return asset


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


async def _catalogue(db) -> list[BreachCatalogue]:
    rows = await db.execute(select(BreachCatalogue).order_by(BreachCatalogue.breach_name))
    return list(rows.scalars())


# ---------------------------------------------------------------------------
# The diff
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_source_that_was_never_synced_says_so(db_session):
    """The checkpoint a first scan is given: nothing stored, nothing claimed."""
    window = await catalogue_window(db_session, "hibp")
    assert window == {
        "source": "hibp",
        "incidents": 0,
        "last_synced_at": None,
        "stale": False,
    }


@pytest.mark.asyncio
async def test_the_first_sweep_creates_every_incident(db_session):
    summary = await sync_catalogue(
        db_session,
        source="hibp",
        entries=[_entry("Adobe"), _entry("LinkedIn"), _entry("Dropbox")],
    )
    assert summary["created"] == 3
    assert summary["updated"] == summary["unchanged"] == 0
    assert summary["received"] == 3
    #: No asset watches ``vendor.example``, so nothing here is an incident of ours.
    assert summary["new_incidents"] == 0
    assert [row.breach_name for row in await _catalogue(db_session)] == [
        "Adobe",
        "Dropbox",
        "LinkedIn",
    ]
    assert await _events(db_session) == []


@pytest.mark.asyncio
async def test_a_repeated_sweep_of_the_same_facts_is_silent(db_session):
    """The platform's own diff: the provider has no "added since" to ask."""
    entries = [_entry("Adobe"), _entry("LinkedIn")]
    await sync_catalogue(db_session, source="hibp", entries=entries)
    again = await sync_catalogue(db_session, source="hibp", entries=entries)
    assert again["created"] == 0
    assert again["unchanged"] == 2
    assert again["updated"] == 0


@pytest.mark.asyncio
async def test_a_corrected_incident_updates_its_row(db_session):
    """A grown incident is one row rewritten, not a second incident."""
    await sync_catalogue(db_session, source="hibp", entries=[_entry("Adobe")])
    changed = await sync_catalogue(
        db_session,
        source="hibp",
        entries=[_entry("Adobe", pwn_count=250, data_classes=["Email addresses", "Passwords"])],
    )
    assert changed["updated"] == 1
    assert changed["created"] == 0
    row = (await _catalogue(db_session))[0]
    assert row.pwn_count == 250
    assert sorted(row.data_classes) == ["Email addresses", "Passwords"]


@pytest.mark.asyncio
async def test_a_reordered_data_class_list_is_not_a_change(db_session):
    """A source reordering a list says the same thing, and must not churn the row."""
    await sync_catalogue(
        db_session,
        source="hibp",
        entries=[_entry("Adobe", data_classes=["Passwords", "Email addresses"])],
    )
    again = await sync_catalogue(
        db_session,
        source="hibp",
        entries=[_entry("Adobe", data_classes=["Email addresses", "Passwords"])],
    )
    assert again["unchanged"] == 1 and again["updated"] == 0


@pytest.mark.asyncio
async def test_one_incident_repeated_inside_a_batch_is_stored_once(db_session):
    """A caller that names the same incident twice describes one incident."""
    summary = await sync_catalogue(
        db_session,
        source="hibp",
        entries=[_entry("Adobe"), _entry("Adobe", title="Adobe (again)")],
    )
    assert summary["created"] == 1
    rows = await _catalogue(db_session)
    assert len(rows) == 1 and rows[0].title == "Adobe incident"


@pytest.mark.asyncio
async def test_the_checkpoint_moves_to_the_sync_that_wrote_it(db_session):
    """What the next scan is told: this source was read, and how much is stored."""
    await sync_catalogue(db_session, source="hibp", entries=[_entry("Adobe")])
    window = await catalogue_window(db_session, "hibp")
    assert window["incidents"] == 1
    assert window["last_synced_at"] is not None
    assert window["stale"] is False


@pytest.mark.asyncio
async def test_a_catalogue_nothing_confirms_becomes_stale(db_session):
    """A row nothing has re-read must not keep claiming to be current."""
    await sync_catalogue(db_session, source="hibp", entries=[_entry("Adobe")])
    row = (await _catalogue(db_session))[0]
    row.last_synced_at = datetime.now(timezone.utc) - timedelta(
        hours=CATALOGUE_STALE_AFTER_HOURS + 1
    )
    await db_session.commit()
    assert (await catalogue_window(db_session, "hibp"))["stale"] is True


# ---------------------------------------------------------------------------
# The event
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_new_incident_of_a_watched_domain_is_announced_once(db_session):
    """The whole point: the incident is reported before an address is scanned."""
    await _watch(db_session, "example.com")
    entries = [
        _entry("Acme", domain="example.com", title="Acme breach"),
        _entry("Elsewhere", domain="not-watched.example"),
    ]
    summary = await sync_catalogue(db_session, source="hibp", entries=entries)
    assert summary["created"] == 2
    assert summary["new_incidents"] == 1
    assert summary["announced"] == [{"breach_name": "Acme", "matched_asset": "example.com"}]

    events = await _events(db_session)
    assert len(events) == 1
    payload = events[0].payload
    assert payload["change_class"] == "new_incident"
    assert payload["catalogue"] is True
    assert payload["breach_name"] == "Acme"
    assert payload["title"] == "Acme breach"
    #: The vendor domain is the account this incident is about: no address of ours is
    #: in it, and the message says what the operator should look at.
    assert payload["matched_domain"] == "example.com"
    assert payload["matched_email"] is None
    assert payload["data_classes"] == ["Email addresses"]
    #: The noise policy reads the same attributes on a catalogue entry as on a finding.
    assert payload["attributes"]["is_spam_list"] is False


@pytest.mark.asyncio
async def test_the_second_sweep_of_a_known_incident_announces_nothing(db_session):
    """One event per incident, so a re-sweep is not a second message."""
    await _watch(db_session, "example.com")
    entries = [_entry("Acme", domain="example.com")]
    await sync_catalogue(db_session, source="hibp", entries=entries)
    again = await sync_catalogue(db_session, source="hibp", entries=entries)
    assert again["new_incidents"] == 0
    assert len(await _events(db_session)) == 1


@pytest.mark.asyncio
async def test_a_domain_that_is_not_watched_is_stored_and_not_announced(db_session):
    """The catalogue is wider than the inventory: knowing is not an incident."""
    await _watch(db_session, "example.com")
    summary = await sync_catalogue(
        db_session, source="hibp", entries=[_entry("Elsewhere", domain="other.example")]
    )
    assert summary["created"] == 1 and summary["new_incidents"] == 0
    assert await _events(db_session) == []
    assert [row.breach_name for row in await _catalogue(db_session)] == ["Elsewhere"]


@pytest.mark.asyncio
async def test_an_incident_of_an_inactive_domain_is_not_an_incident_of_ours(db_session):
    """An asset nobody monitors any more is not a domain this installation watches."""
    await _watch(db_session, "retired.example", active=False)
    summary = await sync_catalogue(
        db_session, source="hibp", entries=[_entry("Acme", domain="retired.example")]
    )
    assert summary["new_incidents"] == 0
    assert await _events(db_session) == []


@pytest.mark.asyncio
async def test_the_domain_match_uses_the_platforms_own_rule(db_session):
    """Case, a trailing dot and IDNA are the same identifier, not four domains."""
    await _watch(db_session, "example.com")
    summary = await sync_catalogue(
        db_session, source="hibp", entries=[_entry("Acme", domain="Example.COM.")]
    )
    assert summary["new_incidents"] == 1
    assert (await _events(db_session))[0].payload["matched_domain"] == "example.com"


@pytest.mark.asyncio
async def test_a_sources_catalogue_is_its_own(db_session):
    """Two sources describing one incident are two rows, and two announcements."""
    await _watch(db_session, "example.com")
    first = await sync_catalogue(
        db_session, source="hibp", entries=[_entry("Acme", domain="example.com")]
    )
    second = await sync_catalogue(
        db_session, source="leakcheck", entries=[_entry("Acme", domain="example.com")]
    )
    assert first["new_incidents"] == 1 and second["new_incidents"] == 1
    assert len(await _catalogue(db_session)) == 2
    assert len(await _events(db_session)) == 2


# ---------------------------------------------------------------------------
# The state
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_empty_catalogue_is_not_a_clean_one(db_session):
    """A source that answered nothing says nothing; it does not say "no incidents"."""
    summary = await sync_catalogue(db_session, source="hibp", entries=[])
    assert summary["empty"] is True
    assert summary["received"] == summary["created"] == 0
    state = await catalogue_state(db_session, source="hibp")
    assert state["incidents"] == 0
    #: Never synced, which is a statement about this installation rather than about the
    #: source — and the difference is exactly what a page has to be able to show.
    assert state["last_synced_at"] is None
    assert state["sources"] == []


@pytest.mark.asyncio
async def test_the_state_reports_each_source_separately(db_session):
    """One timestamp for two catalogues would claim a freshness half the rows lack."""
    await sync_catalogue(db_session, source="hibp", entries=[_entry("Adobe")])
    await sync_catalogue(
        db_session,
        source="leakcheck",
        entries=[_entry("Acme", added_date=datetime(2021, 6, 1, tzinfo=timezone.utc))],
    )
    state = await catalogue_state(db_session)
    assert state["incidents"] == 2
    assert [row["source"] for row in state["sources"]] == ["hibp", "leakcheck"]
    assert all(row["incidents"] == 1 for row in state["sources"])
    assert all(row["last_synced_at"] for row in state["sources"])
    #: The newest incident the source knows about, which is what a report counts.
    assert state["newest_added_date"] == "2021-06-01"


@pytest.mark.asyncio
async def test_the_state_can_ask_about_one_source(db_session):
    await sync_catalogue(db_session, source="hibp", entries=[_entry("Adobe")])
    await sync_catalogue(db_session, source="leakcheck", entries=[_entry("Acme")])
    state = await catalogue_state(db_session, source="leakcheck")
    assert state["incidents"] == 1
    assert [row["source"] for row in state["sources"]] == ["leakcheck"]


# ---------------------------------------------------------------------------
# The connector-facing endpoint
# ---------------------------------------------------------------------------

async def _provision(db, *, name: str = "hibp", connector_type: str = "breaches"):
    """A registered connector, its credential, and one claimed job to report against."""
    from app.services.connector_credentials import ConnectorCredentials
    from app.services.connector_service import ConnectorService

    svc = ConnectorService(db)
    conn = await svc.get_by_name(name)
    if conn is None:
        conn = await svc.register(
            name=name,
            connector_type=connector_type,
            api_version="1.0",
            default_job_type=f"{connector_type}.{name}",
        )
    token, _ = await ConnectorCredentials(db).issue(conn)
    await db.commit()
    job = (
        await svc.enqueue_module_scan(
            connector_type=connector_type, created_by=None, title="Scan"
        )
    )[0]
    return conn, job, {"X-Connector-Token": token, "X-Connector-Name": name}


@pytest.mark.asyncio
async def test_the_batches_checkpoint_travels_with_the_scan(db_session):
    """The worker is told what the core holds, so it can ask the cheap question."""
    _, job, _headers = await _provision(db_session, name="hibp-cat-checkpoint")
    assert job.params["catalogue"] == {
        "source": "hibp-cat-checkpoint",
        "incidents": 0,
        "last_synced_at": None,
        "stale": False,
    }
    assert job.params["module"] == "breaches"


@pytest.mark.asyncio
async def test_a_module_without_a_checkpoint_gets_none(db_session):
    """The param belongs to the module that stores incidents, and to nobody else."""
    _, job, _headers = await _provision(
        db_session, name="dnstwist-cat-param", connector_type="phishing"
    )
    assert "catalogue" not in job.params


@pytest.mark.asyncio
async def test_the_stealer_log_window_travels_with_the_scan(db_session):
    """WI-18: the worker is told whether it may spend the paid pass at all.

    Read from the core rather than remembered by the worker: the pass is weekly, the
    worker is restarted and rescheduled between scans, and the fact that decides it is
    when this installation last *stored* stealer-log exposure.
    """
    _, job, _headers = await _provision(db_session, name="hibp-stealer-param")
    assert job.params["stealer_logs"] == {
        "source": "hibp-stealer-param",
        "last_seen_at": None,
    }


@pytest.mark.asyncio
async def test_a_module_without_a_checkpoint_gets_no_stealer_window(db_session):
    """A pass only the breach module spends is not offered to a source that has none."""
    _, job, _headers = await _provision(
        db_session, name="dnstwist-stealer-param", connector_type="phishing"
    )
    assert "stealer_logs" not in job.params


@pytest.mark.asyncio
async def test_the_endpoint_stores_a_batch_and_announces_a_watched_domain(client, db_session):
    await _watch(db_session, "example.com")
    _, job, headers = await _provision(db_session, name="hibp-cat-endpoint")
    work = await client.get("/api/v1/connectors/me/work", headers=headers)
    lease = work.json()["lease_token"]

    response = await client.post(
        f"/api/v1/connectors/me/catalogue/{job.id}",
        headers={**headers, "X-Connector-Lease": lease},
        json=[
            _wire(_entry("Acme", domain="example.com")),
            _wire(_entry("Elsewhere", domain="other.example")),
        ],
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["received"] == 2
    assert body["created"] == 2
    assert body["new_incidents"] == 1
    assert len(await _events(db_session)) == 1

    # The whole read path the page uses, over HTTP: what the catalogue holds.
    state = await catalogue_state(db_session, source="hibp-cat-endpoint")
    assert state["incidents"] == 2


@pytest.mark.asyncio
async def test_a_caller_without_a_connector_credential_is_refused(client, db_session):
    """The catalogue is written by a connector, never by an anonymous caller."""
    _, job, _headers = await _provision(db_session, name="hibp-cat-auth")
    response = await client.post(
        f"/api/v1/connectors/me/catalogue/{job.id}",
        headers={
            "X-Connector-Token": "never-issued-token",
            "X-Connector-Lease": "l" * 32,
        },
        json=[_wire(_entry("Acme"))],
    )
    assert response.status_code == 401
    assert await _catalogue(db_session) == []


@pytest.mark.asyncio
async def test_a_batch_from_a_job_this_connector_does_not_own_is_refused(client, db_session):
    """A stale or foreign claim cannot write catalogue rows under its name."""
    _, job, headers = await _provision(db_session, name="hibp-cat-lease")
    response = await client.post(
        f"/api/v1/connectors/me/catalogue/{job.id}",
        headers={**headers, "X-Connector-Lease": "l" * 32},
        json=[_wire(_entry("Acme"))],
    )
    assert response.status_code in {403, 404}
    assert await _catalogue(db_session) == []


@pytest.mark.asyncio
async def test_a_module_without_a_catalogue_is_refused(client, db_session):
    """The route belongs to the module that stores incidents, and says so."""
    _, job, headers = await _provision(
        db_session, name="dnstwist-cat", connector_type="phishing"
    )
    work = await client.get("/api/v1/connectors/me/work", headers=headers)
    lease = work.json()["lease_token"]
    response = await client.post(
        f"/api/v1/connectors/me/catalogue/{job.id}",
        headers={**headers, "X-Connector-Lease": lease},
        json=[_wire(_entry("Acme"))],
    )
    assert response.status_code == 400
    assert "catalogue" in response.json()["detail"]
