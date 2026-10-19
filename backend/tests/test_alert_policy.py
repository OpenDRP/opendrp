"""The six operator values that decide how loud the alert channel is.

The budget was environment-only: the threshold pair, the digest switch and its
hour, the deferral window and the change-notification flag were container
variables, and changing any of them meant recreating a container. They are now
also columns of ``system_settings``, written by the Settings page, and this file
pins the rule that joins the two sources (`app/services/alert_policy.py`):

* a row that states a value answers with it, and the environment answers the
  rest — stating one threshold must not reset the other five;
* a row that contradicts itself (a digest threshold at or above the direct one, or
  a stored number outside its own range) is *refused as a whole* rather than
  half-applied, because the fields are one decision about one channel;
* the readers — the delivery route, the daily digest's hour gate, the deferral
  window and the change notification — read that resolution on the path they
  already walk, so a save takes effect on the next scan rather than the next
  restart.

The last two tests are the API contract the Settings page is written against:
every value is exposed, and a save that would leave an inconsistent budget is
refused with a 400 instead of being stored and silently ignored by the resolver.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.core.config import settings as core_settings
from app.core.exceptions import BadRequestException
from app.models import Connector, IngestionEvent
from app.models.phishing import PhishingDomain
from app.models.settings import SystemSettings
from app.schemas.settings import SystemSettingsUpdate
from app.services.alert_policy import (
    policy_from_environment,
    policy_from_row,
    resolve_alert_policy,
)
from app.services.alert_service import phishing_alert_route
from app.services.ingestion_events import (
    dispatch_notification_events,
    record_event,
    run_phishing_digest,
)
from app.services.ingestion_service import ingest_findings
from app.services.phishing_score_service import alert_band
from app.services.settings_service import SettingsService

#: The middle band as the *environment* states it, used as the "protected" score
#: in the tests below: a candidate at the lowest digest threshold is a digest
#: candidate for a deployment that states nothing else.
_MIDDLE = core_settings.ALERT_CONFIDENCE_DIGEST


def _candidate(**overrides) -> PhishingDomain:
    """A candidate as the routing reads it: a score and a verdict, nothing more."""
    base = {
        "phishing_domain": "lookalike.example.com",
        "matched_asset": "example.com",
        "detection_source": "dnstwist",
        "status": "active",
        "confidence": _MIDDLE,
        "verdict": None,
    }
    base.update(overrides)
    return PhishingDomain(**base)


async def _save(db, **values) -> SystemSettings:
    """Save the budget through the real service, as the Settings page does."""
    row = await SettingsService(db).get_singleton()
    return await SettingsService(db).update_settings(row, SystemSettingsUpdate(**values))


async def _store_candidate(db, **overrides) -> PhishingDomain:
    row = _candidate(**overrides)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def _one_notification(db) -> IngestionEvent:
    return (
        await db.execute(
            select(IngestionEvent)
            .where(IngestionEvent.kind == "notification")
            .order_by(IngestionEvent.created_at, IngestionEvent.id)
            .execution_options(populate_existing=True)
        )
    ).scalars().first()


def test_an_installation_that_states_nothing_is_answered_by_the_environment():
    """The untouched installation: every value is the deployment's own."""
    policy = policy_from_row(None)
    environment = policy_from_environment()

    assert policy == environment
    assert policy.source == "environment"
    assert policy.invalid == ()
    assert policy.consistent


def test_a_row_that_states_nothing_is_not_a_decision():
    """An all-NULL row is a fresh installation, not a row of zeroes."""
    row = SystemSettings(singleton_key=1, version=1)

    assert policy_from_row(row) == policy_from_environment()


def test_a_stated_value_answers_its_own_field_and_leaves_the_rest_to_the_environment():
    """Raising one threshold must not reset the other five."""
    row = SystemSettings(
        singleton_key=1,
        version=1,
        alert_confidence_direct=45,
        alert_confidence_digest=15,
    )

    policy = policy_from_row(row)

    assert (policy.confidence_direct, policy.confidence_digest) == (45, 15)
    assert policy.digest_hour_utc == core_settings.ALERT_PHISHING_DIGEST_HOUR_UTC
    assert policy.no_channel_retry_hours == core_settings.ALERT_NO_CHANNEL_RETRY_HOURS
    assert policy.candidate_change_notifications is (
        core_settings.ALERT_CANDIDATE_CHANGE_NOTIFICATIONS
    )
    assert policy.source == "settings"
    assert policy.consistent


def test_a_row_that_contradicts_itself_is_refused_as_a_whole():
    """The pair is one decision: half of a contradictory one is nobody's answer."""
    row = SystemSettings(
        singleton_key=1,
        version=1,
        alert_confidence_direct=30,
        alert_confidence_digest=30,
    )

    policy = policy_from_row(row)

    # Every value is the environment's, and the *refusal* is what says a row was
    # seen and not honoured rather than never written.
    for field in (
        "confidence_direct",
        "confidence_digest",
        "digest_enabled",
        "digest_hour_utc",
        "no_channel_retry_hours",
        "candidate_change_notifications",
    ):
        assert getattr(policy, field) == getattr(policy_from_environment(), field)
    assert policy.source == "environment"
    assert policy.invalid == ("confidence_digest", "confidence_direct")
    # Nothing was half-applied: the values in force are a working set, and what the
    # row asked for is named as refused rather than silently used.
    # Not merely "the row was noticed": the refused pair is not used either, so the
    # installation keeps routing by the environment's consistent thresholds.
    assert policy.confidence_direct == core_settings.ALERT_CONFIDENCE_DIRECT


def test_a_stored_value_outside_its_own_range_is_refused():
    """The database is not the only writer that has ever existed."""
    row = SystemSettings(
        singleton_key=1, version=1, alert_phishing_digest_hour_utc=42
    )

    policy = policy_from_row(row)

    assert policy.invalid == ("digest_hour_utc",)
    assert policy.digest_hour_utc == core_settings.ALERT_PHISHING_DIGEST_HOUR_UTC


def test_the_digest_hour_moves_without_a_restart():
    """A saved hour is what the hourly tick compares against, not the container's."""
    row = SystemSettings(
        singleton_key=1, version=1, alert_phishing_digest_hour_utc=3
    )

    policy = policy_from_row(row)

    assert policy.digest_is_due(datetime(2026, 1, 1, 3, 15, tzinfo=timezone.utc))
    assert not policy.digest_is_due(datetime(2026, 1, 1, 4, 15, tzinfo=timezone.utc))
    assert not policy.digest_is_due(datetime(2026, 1, 1, 2, 59, tzinfo=timezone.utc))


def test_turning_the_digest_off_makes_the_budget_binary():
    """The middle band still exists; the channel does not report it."""
    policy = policy_from_row(
        SystemSettings(
            singleton_key=1, version=1, alert_phishing_digest_enabled=False
        )
    )
    candidate = _candidate(confidence=_MIDDLE)

    assert alert_band(candidate.confidence, policy=policy) == "digest"
    assert phishing_alert_route(candidate, policy=policy) == "list"
    assert (
        phishing_alert_route(candidate, policy=policy_from_environment()) == "digest"
    )


def test_a_lowered_direct_threshold_promotes_a_candidate_on_the_next_scan():
    """The same candidate, the same scan, a different answer after a save."""
    # Above the environment's digest threshold — a digest candidate as the
    # deployment states it — and exactly at the threshold the row states.
    candidate = _candidate(confidence=_MIDDLE + 5)
    policy = policy_from_row(
        SystemSettings(
            singleton_key=1, version=1, alert_confidence_direct=_MIDDLE + 5
        )
    )

    assert phishing_alert_route(candidate, policy=policy) == "immediate"
    assert (
        phishing_alert_route(candidate, policy=policy_from_environment()) == "digest"
    )


@pytest.mark.asyncio
async def test_the_resolver_reads_the_saved_row_and_the_environment_for_the_rest(
    db_session,
):
    """End to end through the service that writes the row."""
    await _save(db_session, alert_confidence_direct=42, alert_confidence_digest=12)

    policy = await resolve_alert_policy(db_session)

    assert (policy.confidence_direct, policy.confidence_digest) == (42, 12)
    assert policy.source == "settings"
    assert policy.invalid == ()
    assert policy.digest_hour_utc == core_settings.ALERT_PHISHING_DIGEST_HOUR_UTC


@pytest.mark.asyncio
async def test_a_save_that_would_contradict_the_row_is_refused_and_changes_nothing(
    db_session,
):
    """The save is the last place the contradiction can be caught cheaply."""
    await _save(db_session, alert_confidence_direct=50, alert_confidence_digest=20)

    with pytest.raises(BadRequestException) as refused:
        # Only the digest threshold is stated; the direct one comes from the row
        # that is being updated, which is why a per-field check could not see it.
        await _save(db_session, alert_confidence_digest=70)

    assert "digest threshold" in str(refused.value.detail)
    # A request's own session is what rolls back when the endpoint refuses the
    # save; the test's session is long-lived, so it says so explicitly.
    await db_session.rollback()

    policy = await resolve_alert_policy(db_session)
    assert (policy.confidence_direct, policy.confidence_digest) == (50, 20)
    assert policy.invalid == ()


@pytest.mark.asyncio
async def test_the_outbox_consumes_a_candidate_the_operator_s_thresholds_exclude(
    db_session, monkeypatch
):
    """The budget runs where it always ran — the release from the outbox."""
    enqueue = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "app.services.ingestion_events.AlertDeliveryService.enqueue", enqueue
    )
    # Below the environment's digest threshold, so the default budget says list
    # (`_MIDDLE` is that threshold, read from the environment this suite runs in).
    candidate = await _store_candidate(db_session, confidence=max(_MIDDLE - 10, 0))
    await record_event(
        db_session,
        kind="notification",
        module="phishing",
        entity_id=candidate.id,
        payload={"title": "candidate", "finding_id": str(candidate.id)},
    )
    await db_session.commit()

    assert await dispatch_notification_events(db_session) == 0
    row = await _one_notification(db_session)
    assert row.last_error == "phishing_below_threshold"
    assert row.processed_at is not None

    # The operator lowers the digest threshold to meet the candidate; the next
    # release reports it once a day instead of dropping it. A later fact about the
    # same candidate is a new outbox row — the arrival rule digests a revision
    # precisely so the first event cannot swallow it.
    await _save(db_session, alert_confidence_digest=max(_MIDDLE - 15, 0))
    await record_event(
        db_session,
        kind="notification",
        module="phishing",
        entity_id=candidate.id,
        payload={"title": "candidate again", "finding_id": str(candidate.id)},
        dedup="revision",
    )
    await db_session.commit()

    assert await dispatch_notification_events(db_session) == 0
    # Two arrivals, two reasons: the same candidate is below the budget in one case
    # and in the middle band in the other, and the history says which.
    reasons = sorted(
        row.last_error
        for row in (
            await db_session.execute(
                select(IngestionEvent)
                .where(IngestionEvent.kind == "notification")
                .execution_options(populate_existing=True)
            )
        ).scalars()
    )
    assert reasons == ["phishing_below_threshold", "phishing_digest_pending"]
    assert enqueue.await_count == 0


@pytest.mark.asyncio
async def test_the_operator_can_end_the_deferral_window(db_session, monkeypatch):
    """`0` holds nothing — the finding is consumed where it stands."""
    monkeypatch.setattr(
        "app.services.ingestion_events.AlertDeliveryService.enqueue",
        AsyncMock(return_value=None),
    )
    await record_event(
        db_session,
        kind="notification",
        module="dns",
        entity_id=uuid.uuid4(),
        payload={"title": "dns arrival"},
    )
    await db_session.commit()
    await _save(db_session, alert_no_channel_retry_hours=0)

    assert await dispatch_notification_events(db_session) == 0

    row = await _one_notification(db_session)
    assert row.last_error == "no_delivery_channel"
    assert row.processed_at is not None
    assert row.next_attempt_at is None, (
        "the window was set to zero, so the row must not be held for a retry"
    )


@pytest.mark.asyncio
async def test_the_default_window_still_holds_a_finding(db_session, monkeypatch):
    """The other half of the same reader: an unstated window is the environment's."""
    monkeypatch.setattr(
        "app.services.ingestion_events.AlertDeliveryService.enqueue",
        AsyncMock(return_value=None),
    )
    await record_event(
        db_session,
        kind="notification",
        module="dns",
        entity_id=uuid.uuid4(),
        payload={"title": "dns arrival"},
    )
    await db_session.commit()
    assert core_settings.ALERT_NO_CHANNEL_RETRY_HOURS > 0, (
        "this test pins the default as a hold; an installation that turned the "
        "window off is covered by the zero case above"
    )

    assert await dispatch_notification_events(db_session) == 0

    row = await _one_notification(db_session)
    assert row.processed_at is None
    assert row.next_attempt_at is not None
    # The instant is the configured number of hours away, so the window is the
    # operator's value and not an unrelated default.
    held_until = row.next_attempt_at
    if held_until.tzinfo is None:
        held_until = held_until.replace(tzinfo=timezone.utc)
    expected = datetime.now(timezone.utc) + timedelta(
        hours=core_settings.ALERT_NO_CHANNEL_RETRY_HOURS
    )
    assert abs((held_until - expected).total_seconds()) < 60


@pytest.mark.asyncio
async def test_the_digest_waits_for_the_operator_hour(db_session, monkeypatch):
    """The hourly tick asks the policy which tick is the one that sends."""
    queued = AsyncMock(return_value=object())
    monkeypatch.setattr(
        "app.services.ingestion_events.AlertDeliveryService.enqueue", queued
    )
    await _store_candidate(db_session)
    await _save(db_session, alert_phishing_digest_hour_utc=3)

    early = await run_phishing_digest(
        db_session, now=datetime(2026, 1, 1, 4, 15, tzinfo=timezone.utc)
    )

    assert early == {
        "queued": 0,
        "candidates": 0,
        "reason": "outside_digest_hour",
        "digest_hour_utc": 3,
    }
    assert queued.await_count == 0

    due = await run_phishing_digest(
        db_session, now=datetime(2026, 1, 1, 3, 15, tzinfo=timezone.utc)
    )

    assert due == {"queued": 1, "candidates": 1}


@pytest.mark.asyncio
async def test_a_disabled_digest_stops_the_digest_task_entirely(db_session, monkeypatch):
    """The switch is read by the pass, not only by the routing."""
    queued = AsyncMock(return_value=object())
    monkeypatch.setattr(
        "app.services.ingestion_events.AlertDeliveryService.enqueue", queued
    )
    await _store_candidate(db_session)
    await _save(db_session, alert_phishing_digest_enabled=False)

    result = await run_phishing_digest(
        db_session, now=datetime(2026, 1, 1, 6, 15, tzinfo=timezone.utc)
    )

    assert result == {"queued": 0, "candidates": 0, "reason": "digest_disabled"}
    assert queued.await_count == 0


@pytest.mark.asyncio
async def test_a_revision_is_silent_when_the_operator_asked_for_it(db_session):
    """Off withholds the message, not the update: the row and the list keep it."""

    connector = Connector(
        name="dnstwist-phishing-default",
        connector_type="phishing",
        default_job_type="phishing.dnstwist",
        status="enabled",
    )
    db_session.add(connector)
    await db_session.flush()
    await _save(db_session, alert_candidate_change_notifications=False)

    async def feed(**overrides):
        item = {"phishing_domain": "evil.example.com", "matched_asset": "example.com"}
        item.update(overrides)
        result = await ingest_findings(
            db_session, connector=connector, job_id=None, findings=[item]
        )
        await db_session.commit()
        return result

    # A first sighting is always reported, whatever the operator said about
    # revisions: the flag is about a *change*, and a new candidate has none.
    await feed()
    created = await _one_notification(db_session)
    assert created.payload["rule"] == "phishing.candidate.created"

    await feed(ip_address="203.0.113.10")
    changed = (
        await db_session.execute(
            select(IngestionEvent).where(IngestionEvent.kind == "notification")
        )
    ).scalars().all()
    assert [event.payload["rule"] for event in changed] == [
        "phishing.candidate.created"
    ], "a revision was reported although the operator turned revisions off"

    stored = (
        await db_session.execute(
            select(PhishingDomain).where(
                PhishingDomain.phishing_domain == "evil.example.com"
            )
        )
    ).scalar_one()
    assert stored.ip_address == "203.0.113.10", (
        "the change was withheld from the channel, not from the platform"
    )


@pytest.mark.asyncio
async def test_the_settings_api_exposes_the_budget_and_refuses_a_contradiction(
    client, db_session, auth_headers_admin
):
    """The contract the Settings page is written against (WI-13)."""
    fields = (
        "alert_confidence_direct",
        "alert_confidence_digest",
        "alert_phishing_digest_enabled",
        "alert_phishing_digest_hour_utc",
        "alert_no_channel_retry_hours",
        "alert_candidate_change_notifications",
    )

    response = await client.get("/api/v1/settings", headers=auth_headers_admin)
    assert response.status_code == 200
    body = response.json()
    assert all(field in body for field in fields)
    assert all(body[field] is None for field in fields), (
        "an untouched installation states nothing, so every budget value is null"
    )

    refused = await client.put(
        "/api/v1/settings",
        headers=auth_headers_admin,
        json={"alert_confidence_digest": 70},
    )
    assert refused.status_code == 400
    assert "digest threshold" in refused.json()["detail"]
    # The endpoint's session rolls back with the refused request; the test's
    # session is shared with the client, so it performs that step itself.
    await db_session.rollback()

    after = (await client.get("/api/v1/settings", headers=auth_headers_admin)).json()
    assert after["alert_confidence_digest"] is None

    accepted = await client.put(
        "/api/v1/settings",
        headers=auth_headers_admin,
        json={"alert_confidence_direct": 45, "alert_confidence_digest": 15},
    )
    assert accepted.status_code == 200

    saved = (await client.get("/api/v1/settings", headers=auth_headers_admin)).json()
    assert (saved["alert_confidence_direct"], saved["alert_confidence_digest"]) == (
        45,
        15,
    )
    assert saved["alert_phishing_digest_hour_utc"] is None


@pytest.mark.asyncio
async def test_the_alert_policy_endpoint_reports_what_is_in_force(
    client, auth_headers_admin
):
    """The page's one question about the budget — which values are routing now.

    The answer is not "read the six inputs and guess": a value nobody saved comes
    from the deployment, and the answer says so.
    """
    environment = policy_from_environment()

    response = await client.get(
        "/api/v1/settings/alert-policy", headers=auth_headers_admin
    )

    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "environment"
    assert body["invalid"] == []
    assert body["confidence_direct"] == environment.confidence_direct
    assert body["confidence_digest"] == environment.confidence_digest
    assert body["digest_hour_utc"] == environment.digest_hour_utc
    assert body["digest_enabled"] == environment.digest_enabled
    assert body["no_channel_retry_hours"] == environment.no_channel_retry_hours

    accepted = await client.put(
        "/api/v1/settings",
        headers=auth_headers_admin,
        json={"alert_confidence_direct": 45, "alert_confidence_digest": 15},
    )
    assert accepted.status_code == 200

    after = (
        await client.get(
            "/api/v1/settings/alert-policy", headers=auth_headers_admin
        )
    ).json()
    assert after["source"] == "settings"
    assert (after["confidence_direct"], after["confidence_digest"]) == (45, 15)
    # The four values the save did not mention are still the deployment's.
    assert after["no_channel_retry_hours"] == environment.no_channel_retry_hours
    assert after["candidate_change_notifications"] is (
        environment.candidate_change_notifications
    )


@pytest.mark.asyncio
async def test_a_row_another_writer_left_inconsistent_is_reported(
    client, db_session, auth_headers_admin
):
    """A refused row is named, not silently ignored: the operator is told which."""
    from sqlalchemy import update as sql_update

    await _save(db_session, alert_confidence_direct=50, alert_confidence_digest=20)
    # The API refuses this pair, but it is not the only writer that has ever
    # existed — an older client, a migration or psql can leave the row this way.
    await db_session.execute(
        sql_update(SystemSettings)
        .where(SystemSettings.singleton_key == 1)
        .values(alert_confidence_digest=60)
    )
    await db_session.commit()
    db_session.expire_all()

    body = (
        await client.get(
            "/api/v1/settings/alert-policy", headers=auth_headers_admin
        )
    ).json()

    # Both fields the row states are named: the pair is one decision, so the
    # refusal is about the row and not about the field that moved last.
    assert body["source"] == "environment"
    assert body["invalid"] == ["confidence_digest", "confidence_direct"]
    assert body["confidence_digest"] == core_settings.ALERT_CONFIDENCE_DIGEST
    assert body["confidence_direct"] == core_settings.ALERT_CONFIDENCE_DIRECT
