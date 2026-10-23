"""A breach scan that is a backlog, not a report (WI-06, WI-05).

Two decisions are pinned here, both about what the channel does with what a scan
found rather than about what it found:

* past ``ALERT_BREACH_DIGEST_THRESHOLD`` new incidents, one scan's notifications
  wait for the daily digest instead of arriving as that many separate messages —
  the same hour the phishing digest uses, so an installation has one summary hour;
* an incident the source itself labels spam or fabricated is stored, visible and
  *not announced*, and the reason is recorded on the outbox row so the alert
  history can answer "why did this not become a message?".

The routing, the digest pass and the delivery path are the real ones; only the SMTP
sender is replaced, because what is under test is which messages exist.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import IngestionEvent
from app.models.breach import Breach
from app.models.settings import SystemSettings
from app.services.alert_delivery_service import AlertDeliveryService
from app.services.alert_policy import resolve_alert_policy
from app.services.alert_service import AlertService
from app.services.ingestion_events import (
    BREACH_DIGEST_REASON,
    BREACH_NOISE_REASON,
    dispatch_notification_events,
    queue_breach_digest,
    run_breach_digest,
)
from app.services.ingestion_service import ingest_breach_finding
from app.services.settings_service import SettingsService
from app.schemas.settings import SystemSettingsUpdate


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

    @property
    def plain(self) -> str:
        return "\n".join(message["plain"] or "" for message in self.messages)


@pytest.fixture
def mailbox(monkeypatch) -> _Mailbox:
    sink = _Mailbox()
    monkeypatch.setattr(AlertService, "_send_email_smtp", sink.send)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    monkeypatch.setattr(settings, "ALERT_RECIPIENT_INTERVAL_SECONDS", 0)
    return sink


@pytest.fixture
async def breaches_connector(db_session):
    import uuid

    from app.models.connector import Connector

    connector = Connector(
        name=f"conn-breach-digest-{uuid.uuid4().hex[:8]}",
        connector_type="breaches",
        status="enabled",
        default_job_type="breaches.hibp",
    )
    db_session.add(connector)
    await db_session.commit()
    await db_session.refresh(connector)
    return connector


async def configured_email(db) -> SystemSettings:
    row = SystemSettings(
        email_alerts_enabled=True, smtp_host="smtp.example.com", smtp_port=587
    )
    row.alert_recipient_email_decrypted = "soc@example.com"
    db.add(row)
    await db.commit()
    return row


async def save_budget(db, **values) -> SystemSettings:
    row = await SettingsService(db).get_singleton()
    return await SettingsService(db).update_settings(row, SystemSettingsUpdate(**values))


async def scan(db, connector, label: str) -> uuid.UUID:
    """A persisted scan job, as the connector protocol creates one.

    The digest groups a backlog by the scan that produced it, which is the job the
    connector claimed — a row whose job id names no job is a caller that holds no
    scan at all, and the ingest drops it rather than writing an invalid reference.
    """
    from app.services.job_service import JobService

    job = await JobService(db).create_job(
        job_type="breaches.hibp",
        created_by=None,
        title=f"Scan {label}",
        params={"module": "breaches", "connector": connector.name},
    )
    await db.commit()
    return job.id


async def scan_incidents(db, connector, job_id, count: int, **overrides) -> list[Breach]:
    """One scan's worth of new incidents, through the real ingest path."""
    rows = []
    for index in range(count):
        values = {
            "breach_name": f"Incident {index:03d}",
            "title": f"Incident {index:03d}",
            "domain": "example.com",
            "breach_date": "2020-05-06",
            "pwn_count": 100 + index,
            "data_classes": ["Email addresses"],
            "matched_email": f"account{index:03d}@example.com",
            "attributes": {"is_verified": True},
        }
        values.update(overrides)
        accepted = await ingest_breach_finding(
            db, connector, values, job_id=job_id, module_spec=None
        )
        assert accepted is True, values
    rows = list((await db.execute(select(Breach).order_by(Breach.breach_name))).scalars())
    await db.commit()
    return rows


async def finish(db, job) -> None:
    """The worker's own completion report: a scan's batch may flush once it is over.

    The delivery queue holds a job's findings until that job is terminal, which is
    what keeps a long scan from delivering half of itself; this is the report the
    connector protocol sends when the scan ends.
    """
    from app.models.job import Job

    row = await db.get(Job, job)
    row.status = "success"
    row.finished_at = datetime.now(timezone.utc)
    await db.commit()


async def notification_events(db) -> list[IngestionEvent]:
    return list(
        (
            await db.execute(
                select(IngestionEvent)
                .where(IngestionEvent.kind == "notification", IngestionEvent.module == "breach")
                .order_by(IngestionEvent.created_at, IngestionEvent.id)
                .execution_options(populate_existing=True)
            )
        ).scalars()
    )


async def drain(db) -> list[dict]:
    service = AlertDeliveryService(db)
    results = []
    for _ in range(20):
        result = await service.process_one_group(max_attempts=3)
        if result["status"] == "idle":
            break
        results.append(result)
    return results


@pytest.mark.asyncio
async def test_thirty_incidents_in_one_scan_become_one_message_and_one_digest(
    db_session, breaches_connector, mailbox
):
    """The plan's acceptance case: 30 new incidents, not 30 emails."""
    await configured_email(db_session)
    await save_budget(
        db_session, alert_breach_digest_threshold=20, alert_phishing_digest_hour_utc=6
    )
    job = await scan(db_session, breaches_connector, "thirty")
    await scan_incidents(db_session, breaches_connector, job, 30)
    await finish(db_session, job)

    assert await dispatch_notification_events(db_session) == 0
    events = await notification_events(db_session)
    assert len(events) == 30
    assert all(event.processed_at is None for event in events)
    assert {event.last_error for event in events} == {BREACH_DIGEST_REASON}
    # Nothing was delivered as a per-incident message, and the drain found nothing
    # to do because the rows belong to the digest.
    assert await drain(db_session) == []

    # The digest hour: the same pass the phishing digest uses.
    digest = await queue_breach_digest(db_session)
    assert digest["queued"] == 30
    assert digest["incidents"] == 30

    delivered = await drain(db_session)
    assert [result["count"] for result in delivered] == [30]
    assert len(mailbox.messages) == 1
    assert mailbox.subjects == [
        "[OpenDRP Alert] Breach digest: 30 new incidents from one scan"
    ]
    assert "Incident 000" in mailbox.plain and "Incident 029" in mailbox.plain

    # Covered, and the reason stays readable on the row.
    events = await notification_events(db_session)
    assert all(event.processed_at is not None for event in events)


@pytest.mark.asyncio
async def test_the_digest_pass_only_speaks_at_the_configured_hour(
    db_session, breaches_connector, mailbox
):
    await configured_email(db_session)
    await save_budget(
        db_session, alert_breach_digest_threshold=1, alert_phishing_digest_hour_utc=6
    )
    job = await scan(db_session, breaches_connector, "hour")
    await scan_incidents(db_session, breaches_connector, job, 3)
    await finish(db_session, job)
    await dispatch_notification_events(db_session)

    outside = await run_breach_digest(
        db_session, now=datetime(2026, 10, 17, 9, 15, tzinfo=timezone.utc)
    )
    assert outside["queued"] == 0
    assert outside["reason"] == "outside_digest_hour"
    assert outside["digest_hour_utc"] == 6
    assert await drain(db_session) == []

    due = await run_breach_digest(
        db_session, now=datetime(2026, 10, 17, 6, 15, tzinfo=timezone.utc)
    )
    assert due["queued"] == 3
    assert len(await drain(db_session)) == 1
    assert len(mailbox.messages) == 1


@pytest.mark.asyncio
async def test_a_threshold_of_zero_reports_one_message_per_scan(
    db_session, breaches_connector, mailbox
):
    """The deferral is off: today's behaviour, stated as a number."""
    await configured_email(db_session)
    await save_budget(db_session, alert_breach_digest_threshold=0)
    job = await scan(db_session, breaches_connector, "off")
    await scan_incidents(db_session, breaches_connector, job, 30)
    await finish(db_session, job)

    assert await dispatch_notification_events(db_session) == 30
    events = await notification_events(db_session)
    assert all(event.last_error is None for event in events)
    assert all(event.processed_at is not None for event in events)

    # Nothing was held for the digest, so the pass has nothing to report.
    assert await queue_breach_digest(db_session) == {
        "queued": 0,
        "incidents": 0,
        "remaining": 0,
    }
    delivered = await drain(db_session)
    assert len(mailbox.messages) == 1, "one scan is one message"
    assert sum(result["count"] for result in delivered) == 30


@pytest.mark.asyncio
async def test_disabling_the_digest_releases_what_was_held_for_it(
    db_session, breaches_connector, mailbox, monkeypatch
):
    """Off must not strand a backlog: the held rows come back into the drain."""
    await configured_email(db_session)
    await save_budget(db_session, alert_breach_digest_threshold=1)
    job = await scan(db_session, breaches_connector, "held")
    await scan_incidents(db_session, breaches_connector, job, 3)
    await finish(db_session, job)
    await dispatch_notification_events(db_session)
    assert {event.last_error for event in await notification_events(db_session)} == {
        BREACH_DIGEST_REASON
    }

    monkeypatch.setattr(settings, "ALERT_PHISHING_DIGEST_ENABLED", False)
    policy = await resolve_alert_policy(db_session)
    assert policy.digest_enabled is False

    # The held rows come back into the ordinary drain rather than sitting behind a
    # pass that will never run.
    assert await dispatch_notification_events(db_session) == 3
    assert len(await drain(db_session)) == 1
    assert len(mailbox.messages) == 1
    assert "Incident 000" in mailbox.plain


@pytest.mark.asyncio
async def test_a_spam_incident_is_stored_visible_and_not_announced(
    db_session, breaches_connector, mailbox
):
    """F-07: the source's own flags decide, so a spam list does not page anyone."""
    await configured_email(db_session)
    await save_budget(db_session, alert_breach_digest_threshold=0)
    job = await scan(db_session, breaches_connector, "spam")
    await scan_incidents(
        db_session,
        breaches_connector,
        job,
        1,
        attributes={"is_verified": False, "is_spam_list": True},
    )
    await finish(db_session, job)

    assert await dispatch_notification_events(db_session) == 0
    event = (await notification_events(db_session))[0]
    assert event.processed_at is not None
    assert event.last_error == BREACH_NOISE_REASON
    assert await drain(db_session) == []
    assert mailbox.messages == []

    # The incident itself is still there, with the flag that explains the silence.
    row = (await db_session.execute(select(Breach))).scalars().one()
    assert row.attributes["is_spam_list"] is True


@pytest.mark.asyncio
async def test_verified_only_also_silences_an_incident_the_source_has_not_confirmed(
    db_session, breaches_connector, mailbox
):
    await configured_email(db_session)
    await save_budget(
        db_session,
        alert_breach_digest_threshold=0,
        alert_breach_noise_policy="verified_only",
    )
    job = await scan(db_session, breaches_connector, "unverified")
    await scan_incidents(
        db_session,
        breaches_connector,
        job,
        1,
        attributes={"is_verified": False},
    )
    await scan_incidents(
        db_session,
        breaches_connector,
        job,
        1,
        breach_name="Confirmed Incident",
        attributes={"is_verified": True},
    )
    await finish(db_session, job)

    assert await dispatch_notification_events(db_session) == 1
    reasons = {
        event.payload["breach_name"]: event.last_error
        for event in await notification_events(db_session)
    }
    assert reasons == {
        "Incident 000": BREACH_NOISE_REASON,
        "Confirmed Incident": None,
    }
    assert len(await drain(db_session)) == 1
    assert len(mailbox.messages) == 1
    assert "Confirmed Incident" in mailbox.plain
    assert "is_spam_list" not in mailbox.plain


@pytest.mark.asyncio
async def test_report_everything_restores_the_behaviour_before_the_choice(
    db_session, breaches_connector, mailbox
):
    await configured_email(db_session)
    await save_budget(
        db_session,
        alert_breach_digest_threshold=0,
        alert_breach_noise_policy="all",
    )
    job = await scan(db_session, breaches_connector, "all")
    await scan_incidents(
        db_session,
        breaches_connector,
        job,
        1,
        attributes={"is_fabricated": True},
    )
    await finish(db_session, job)

    assert await dispatch_notification_events(db_session) == 1
    assert len(await drain(db_session)) == 1
    assert len(mailbox.messages) == 1
    assert "Incident 000" in mailbox.plain


@pytest.mark.asyncio
async def test_an_incident_with_no_flags_is_never_treated_as_spam(
    db_session, breaches_connector, mailbox
):
    """Silence has to be justified by a positive statement."""
    await configured_email(db_session)
    await save_budget(db_session, alert_breach_digest_threshold=0)
    job = await scan(db_session, breaches_connector, "noflags")
    await scan_incidents(
        db_session,
        breaches_connector,
        job,
        1,
        attributes={"source_id": "GEN-1"},
    )
    await finish(db_session, job)

    assert await dispatch_notification_events(db_session) == 1
    assert len(await drain(db_session)) == 1
    assert len(mailbox.messages) == 1


@pytest.mark.asyncio
async def test_the_noise_policy_is_read_at_drain_time_not_at_ingest(
    db_session, breaches_connector, mailbox
):
    """A save in Settings takes effect on the next drain, not the next scan.

    The same rule the budget follows: the flags are stored with the row, and the
    decision about what to do with them is made where the policy is resolved.
    """
    await configured_email(db_session)
    await save_budget(db_session, alert_breach_digest_threshold=0)
    job = await scan(db_session, breaches_connector, "late")
    await scan_incidents(
        db_session,
        breaches_connector,
        job,
        1,
        attributes={"is_spam_list": True},
    )
    await finish(db_session, job)
    await save_budget(db_session, alert_breach_noise_policy="all")

    assert await dispatch_notification_events(db_session) == 1
    assert len(await drain(db_session)) == 1
    assert len(mailbox.messages) == 1


@pytest.mark.asyncio
async def test_the_pass_reports_the_backlog_it_did_not_reach(
    db_session, breaches_connector, mailbox
):
    """AUD-088: `remaining` is the backlog, not the rest of the fetched window.

    A pass reads at most one message's worth of incidents. Until this test, the
    answer subtracted what it queued from what it *fetched*, so a pass that used
    its whole window reported `remaining: 0` while twenty incidents were still
    held — a digest several passes behind read as finished.
    """
    await configured_email(db_session)
    await save_budget(db_session, alert_breach_digest_threshold=1)
    job = await scan(db_session, breaches_connector, "window")
    await scan_incidents(db_session, breaches_connector, job, 30)
    await finish(db_session, job)
    await dispatch_notification_events(db_session)

    first = await queue_breach_digest(db_session, limit=10)
    assert first == {"queued": 10, "incidents": 10, "remaining": 20}

    second = await queue_breach_digest(db_session, limit=10)
    assert second == {"queued": 10, "incidents": 10, "remaining": 10}

    third = await queue_breach_digest(db_session, limit=10)
    assert third == {"queued": 10, "incidents": 10, "remaining": 0}


@pytest.mark.asyncio
async def test_a_digest_that_cannot_be_delivered_keeps_its_backlog(
    db_session, breaches_connector, mailbox
):
    """No channel is not "delivered": the incidents stay held for a later pass."""
    await save_budget(db_session, alert_breach_digest_threshold=1)
    job = await scan(db_session, breaches_connector, "nochannel")
    await scan_incidents(db_session, breaches_connector, job, 3)
    await finish(db_session, job)
    await dispatch_notification_events(db_session)

    result = await queue_breach_digest(db_session)
    assert result["queued"] == 0
    assert result["remaining"] == 3
    events = await notification_events(db_session)
    assert all(event.processed_at is None for event in events)


def test_the_digest_task_is_on_the_beat_and_the_alert_queue():
    """``send_breach_digest`` is the schedule's adapter and nothing else.

    Hourly, like the phishing digest, because the hour is an operator's value now:
    a schedule built at worker start could only ever carry the hour the container was
    recreated with.
    """
    from app.core.celery_app import celery_app

    beat = celery_app.conf.beat_schedule
    entry = beat["send-breach-digest-hourly"]
    assert entry["task"] == "send_breach_digest"
    assert str(entry["schedule"]) == str(beat["send-phishing-digest-hourly"]["schedule"])
    assert celery_app.conf.task_routes["send_breach_digest"] == {"queue": "alerts"}
