"""Findings nobody announced, and what the last scan turned up (WI-09, F-06).

A breach finding is durable the moment it is ingested: it is in the list, it can be
triaged, it is what the module exists for. That is also why the *silence* around it
used to be invisible — an installation that ran its first scan before anyone
configured SMTP had a page full of exposures and an alert history with nothing in
it, and nothing in the product said so.

Two answers are pinned here, and they are the two an operator asks in order:

* **"Has anybody been told?"** The list reports ``unannounced``: notifications that
  arrived and no channel has delivered. It is read from the outbox rather than the
  findings, because a finding being visible and a finding being announced are
  different facts, and only the second one is about the channel. A save that
  configures a channel claims the held rows as one backlog digest, so the counter
  falls to zero *and* the finding is announced exactly once.
* **"What did the last scan find?"** ``?new_since_last_scan=true`` measures from the
  completion of the most recent finished breach scan and reports that instant back,
  so a filtered list can be explained instead of believed.

Only the SMTP sender is replaced, as in the digest suite: what is under test is
which messages exist, not how they travel.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.config import settings
from app.models import IngestionEvent
from app.models.breach import Breach
from app.models.connector import Connector
from app.models.settings import SystemSettings
from app.schemas.settings import SystemSettingsUpdate
from app.services.alert_delivery_service import AlertDeliveryService
from app.services.alert_service import AlertService
from app.services.ingestion_events import (
    BREACH_NOISE_REASON,
    dispatch_notification_events,
)
from app.services.ingestion_service import ingest_breach_finding
from app.services.job_service import JobService
from app.services.settings_service import SettingsService

_BASE = "http://test"


class _Mailbox:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def send(self, *, to, subject, html_body, plain_body=None) -> bool:
        self.messages.append(
            {"to": to, "subject": subject, "html": html_body, "plain": plain_body}
        )
        return True

    @property
    def subjects(self) -> list[str]:
        return [message["subject"] for message in self.messages]


@pytest.fixture
def mailbox(monkeypatch) -> _Mailbox:
    sink = _Mailbox()
    monkeypatch.setattr(AlertService, "_send_email_smtp", sink.send)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    monkeypatch.setattr(settings, "ALERT_RECIPIENT_INTERVAL_SECONDS", 0)
    return sink


@pytest.fixture
async def breaches_connector(db_session):
    connector = Connector(
        name=f"conn-breach-announce-{uuid.uuid4().hex[:8]}",
        connector_type="breaches",
        status="enabled",
        default_job_type="breaches.hibp",
    )
    db_session.add(connector)
    await db_session.commit()
    await db_session.refresh(connector)
    return connector


@pytest.fixture()
async def client(db_session):
    from app.api.deps import get_db
    from app.main import app

    async def _override():
        yield db_session

    app.dependency_overrides[get_db] = _override
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url=_BASE
        ) as http:
            yield http
    finally:
        app.dependency_overrides.pop(get_db, None)


async def _scan(db, connector, label: str):
    """A persisted scan job, as the connector protocol creates one."""
    job = await JobService(db).create_job(
        job_type="breaches.hibp",
        created_by=None,
        title=f"Scan {label}",
        params={"module": "breaches", "connector": connector.name},
    )
    await db.commit()
    return job.id


async def _finish(db, job_id) -> None:
    from app.models.job import Job

    row = await db.get(Job, job_id)
    row.status = "success"
    row.finished_at = datetime.now(timezone.utc)
    await db.commit()


async def _incidents(db, connector, job_id, count: int, **overrides) -> None:
    for index in range(count):
        values = {
            "breach_name": f"Held incident {index:03d}",
            "title": f"Held incident {index:03d}",
            "domain": "example.com",
            "breach_date": "2020-05-06",
            "pwn_count": 10 + index,
            "data_classes": ["Email addresses"],
            "matched_email": f"held{index:03d}@example.com",
            "attributes": {"is_verified": True},
        }
        values.update(overrides)
        assert await ingest_breach_finding(
            db, connector, values, job_id=job_id, module_spec=None
        ) is True


async def _configure_email(db) -> SystemSettings:
    """The first save that makes the installation able to deliver, for real."""
    values = SystemSettingsUpdate(
        email_alerts_enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        alert_recipient_email="soc@example.com",
    )
    row = await SettingsService(db).get_singleton()
    return await SettingsService(db).update_settings(row, values)


async def _drain(db) -> list[dict]:
    service = AlertDeliveryService(db)
    results = []
    for _ in range(20):
        result = await service.process_one_group(max_attempts=3)
        if result["status"] == "idle":
            break
        results.append(result)
    return results


async def _list(client, headers, **params) -> dict:
    response = await client.get("/api/v1/breaches", headers=headers, params=params)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_a_finding_no_channel_could_receive_is_announced_once_when_one_appears(
    db_session, breaches_connector, client, auth_headers_viewer, mailbox
):
    """The defect F-06 describes, end to end: held, counted, then delivered once."""
    job = await _scan(db_session, breaches_connector, "no-channel")
    await _finish(db_session, job)
    # Nothing is configured yet, so the real delivery service has nowhere to send
    # and says so: this is the state an installation is in on the day it installs.
    await _incidents(db_session, breaches_connector, job, 3)
    await db_session.commit()

    assert await dispatch_notification_events(db_session) == 0
    body = await _list(client, auth_headers_viewer)
    assert body["unannounced"] == 3

    # The save that makes delivery possible claims the held rows and reports them
    # as one digest rather than replaying them one by one.
    await _configure_email(db_session)
    body = await _list(client, auth_headers_viewer)
    assert body["unannounced"] == 0, (
        "the finding was still reported as unannounced after a channel was "
        "configured and the backlog digest covered it"
    )

    # The digest is one notification about the held rows, in the operations stream
    # the outbox owns — the same path the phishing backlog uses.
    pending = list(
        (
            await db_session.execute(
                select(IngestionEvent).where(
                    IngestionEvent.kind == "notification",
                    IngestionEvent.processed_at.is_(None),
                )
            )
        ).scalars()
    )
    assert [event.module for event in pending] == ["module:operations"]
    assert await dispatch_notification_events(db_session) == 1

    delivered = await _drain(db_session)
    assert [result["count"] for result in delivered] == [1]
    assert len(mailbox.messages) == 1
    assert "Alert backlog" in mailbox.messages[0]["plain"]
    assert "breach" in mailbox.messages[0]["plain"]

    # Once: a second pass has nothing left to say about them.
    assert await dispatch_notification_events(db_session) == 0
    assert await _drain(db_session) == []
    assert len(mailbox.messages) == 1


@pytest.mark.asyncio
async def test_the_counter_reports_only_what_no_channel_has_announced(
    db_session, breaches_connector, client, auth_headers_viewer
):
    """A consumed notification is an answered one, not an unannounced finding."""
    job = await _scan(db_session, breaches_connector, "mixed")
    await _finish(db_session, job)
    await _configure_email(db_session)

    # A spam incident: the noise policy consumes its notification on purpose.
    await _incidents(
        db_session,
        breaches_connector,
        job,
        1,
        breach_name="Spam incident",
        matched_email="spam@example.com",
        attributes={"is_verified": False, "is_spam_list": True},
    )
    # ...and one ordinary incident, left waiting.
    await _incidents(
        db_session,
        breaches_connector,
        job,
        1,
        breach_name="Ordinary incident",
        matched_email="ordinary@example.com",
    )
    await db_session.commit()
    assert await dispatch_notification_events(db_session) == 1

    events = list(
        (
            await db_session.execute(
                select(IngestionEvent).where(
                    IngestionEvent.kind == "notification",
                    IngestionEvent.module == "breach",
                )
            )
        ).scalars()
    )
    consumed = [event for event in events if event.last_error == BREACH_NOISE_REASON]
    assert len(consumed) == 1 and consumed[0].processed_at is not None
    assert len(events) == 2

    # The spam row is on the page with its own flag; neither notification counts as
    # unannounced, because both were answered — one by delivery, one by policy.
    body = await _list(client, auth_headers_viewer)
    assert body["unannounced"] == 0
    assert {item["breach_name"] for item in body["items"]} == {
        "Spam incident",
        "Ordinary incident",
    }


@pytest.mark.asyncio
async def test_new_since_last_scan_is_measured_from_the_scan_that_finished(
    db_session, breaches_connector, client, auth_headers_viewer
):
    await _configure_email(db_session)
    first = await _scan(db_session, breaches_connector, "first")
    await _finish(db_session, first)
    await _incidents(
        db_session,
        breaches_connector,
        first,
        1,
        breach_name="Old incident",
        matched_email="old@example.com",
    )
    await db_session.commit()

    # Nothing has been scanned since, so the filter still sees everything and says
    # what it measured from.
    body = await _list(client, auth_headers_viewer, new_since_last_scan=True)
    assert {item["breach_name"] for item in body["items"]} == {"Old incident"}
    assert body["new_since"] is not None

    second = await _scan(db_session, breaches_connector, "second")
    await _finish(db_session, second)
    await _incidents(
        db_session,
        breaches_connector,
        second,
        1,
        breach_name="New incident",
        matched_email="new@example.com",
    )
    await db_session.commit()

    body = await _list(client, auth_headers_viewer, new_since_last_scan=True)
    assert {item["breach_name"] for item in body["items"]} == {"New incident"}
    assert body["total"] == 1

    # Without the filter both are listed: the boundary is a view, not a deletion.
    body = await _list(client, auth_headers_viewer)
    assert {item["breach_name"] for item in body["items"]} == {
        "Old incident",
        "New incident",
    }
    assert body["new_since"] is None


@pytest.mark.asyncio
async def test_a_scan_still_running_is_not_a_boundary_the_filter_can_use(
    db_session, breaches_connector, client, auth_headers_viewer
):
    """A running scan's own findings are not "old" the moment it starts."""
    from app.models.job import Job

    job = await _scan(db_session, breaches_connector, "running")
    row = await db_session.get(Job, job)
    row.status = "running"
    row.started_at = datetime.now(timezone.utc)
    await db_session.commit()
    await _incidents(
        db_session,
        breaches_connector,
        job,
        1,
        breach_name="In-flight incident",
        matched_email="inflight@example.com",
    )
    await db_session.commit()

    body = await _list(client, auth_headers_viewer, new_since_last_scan=True)
    assert body["new_since"] is None
    assert {item["breach_name"] for item in body["items"]} == {"In-flight incident"}


@pytest.mark.asyncio
async def test_the_filter_does_not_hide_rows_a_scan_never_touched(
    db_session, breaches_connector, client, auth_headers_viewer
):
    """Findings with no scan behind them are not dated by somebody else's scan."""
    await _configure_email(db_session)
    await _incidents(
        db_session,
        breaches_connector,
        None,
        1,
        breach_name="Manual incident",
        matched_email="manual@example.com",
    )
    await db_session.commit()
    job = await _scan(db_session, breaches_connector, "later")
    await _finish(db_session, job)

    # The manual finding predates the scan, so the filter excludes it — and the
    # response says what it was excluded by.
    body = await _list(client, auth_headers_viewer, new_since_last_scan=True)
    assert body["items"] == []
    assert body["new_since"] is not None
    assert (await db_session.execute(select(Breach))).scalars().all()
