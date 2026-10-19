"""The registration pass paces itself, caches per row, and pauses per registry.

`enrich_one_event` resolves one event. The scheduled work is the batch
(`enrich_pending_events`), and what the batch adds is everything that only shows
up once there is more than one candidate:

* a scan finds many look-alikes at once and every WHOIS query is a request to a
  registry that counts them, so the pass asks each *answering server* at most once
  and the rest of that server's candidates wait for the next tick. Forty names
  under `.com` arrive at the registry as a trickle instead of a burst;
* the candidate row is the cache, and it is the better cache: the facts live on
  the row the platform reads anyway, so a candidate that already carries them is
  completed without a query, and the abuse contact — which many registries never
  publish — cannot make a complete row look partial;
* a registry that answers "limit exceeded" has said something about *us*. That is
  the one answer that is not about the name, so the event and every other pending
  event of that registry wait out a pause measured in minutes (WI-25) — where a
  per-event backoff would have produced a retry stream against a server that is
  asking us to stop;
* a lookup that did not answer is retried with the bounded backoff and, once its
  tries are spent, completed rather than left pending forever, so a registry nobody
  can reach cannot fill the queue that every later pass spends its batch on.

The tests drive the real models and the real session and patch only the lookup
itself — which is what lets them assert on the requests that were *not* made.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import IngestionEvent, PhishingDomain
from app.services import ingestion_events as drain
from app.services.phishing import whois_service


def _candidate(domain: str, **facts) -> PhishingDomain:
    return PhishingDomain(
        phishing_domain=domain,
        matched_asset="example.com",
        detection_source="test",
        **facts,
    )


def _whois_event(candidate_id: uuid.UUID) -> IngestionEvent:
    return IngestionEvent(
        event_key=f"whois:phishing:{candidate_id}",
        kind="whois",
        module="phishing",
        entity_id=candidate_id,
        payload={},
    )


def _utc(value: datetime) -> datetime:
    """SQLite stores a naive instant; the platform stores UTC."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _lookup(monkeypatch, answer=None) -> list[str]:
    """Patch the registry lookup, recording every domain it was asked about."""
    asked: list[str] = []

    async def _enrich(self, threat):
        asked.append(threat.phishing_domain)
        return answer(threat.phishing_domain) if answer else whois_service.ANSWERED

    monkeypatch.setattr(whois_service.WhoisService, "enrich", _enrich)
    return asked


def _seconds_until(moment: datetime | None) -> float:
    return (_utc(moment) - datetime.now(timezone.utc)).total_seconds()


@pytest.mark.asyncio
async def test_one_pass_asks_each_server_once_and_paces_the_rest(db_session, monkeypatch):
    candidates = [_candidate("evil-one.example.com"), _candidate("evil-two.example.com")]
    db_session.add_all(candidates)
    await db_session.flush()
    events = [_whois_event(candidate.id) for candidate in candidates]
    db_session.add_all(events)
    await db_session.commit()
    asked = _lookup(monkeypatch)

    summary = await drain.enrich_pending_events(db_session)

    # Both events were claimed — a batch, not one event per tick — but only one
    # request went to the registry, because both names are answered by the same
    # server. Its sibling is next pass's.
    assert summary["claimed"] == 2
    assert len(asked) == 1
    completed = [event for event in events if event.processed_at is not None]
    held = [event for event in events if event.processed_at is None]
    assert len(completed) == 1 and len(held) == 1
    assert held[0].last_error == "whois_pacing"
    delta = _seconds_until(held[0].next_attempt_at)
    assert drain.ENRICHMENT_PASS_SECONDS - 2 <= delta <= drain.ENRICHMENT_PASS_SECONDS + 5


@pytest.mark.asyncio
async def test_a_refusal_pauses_its_registry_and_not_a_registry_still_answering(
    db_session, monkeypatch
):
    candidates = [
        _candidate("evil-one.example.com"),
        _candidate("evil-two.example.com"),
        _candidate("evil-three.example.net"),
    ]
    db_session.add_all(candidates)
    await db_session.flush()
    events = {candidate.phishing_domain: _whois_event(candidate.id) for candidate in candidates}
    db_session.add_all(events.values())
    await db_session.commit()
    asked = _lookup(
        monkeypatch,
        answer=lambda domain: (
            whois_service.RATE_LIMITED
            if domain.endswith(".com")
            else whois_service.ANSWERED
        ),
    )

    summary = await drain.enrich_pending_events(db_session)

    # One request per server: the refusal came from `.com` — whichever of its two
    # names the claim reached first — and `.net`, another registry that has said
    # nothing to us, was still asked. Which sibling went first is the claim
    # order's business (creation time, then identifier) rather than the pacing
    # rule's, so the assertion counts the requests per server instead of naming
    # the one the batch happened to pick.
    asked_com = [name for name in asked if name.endswith(".com")]
    assert asked_com in (["evil-one.example.com"], ["evil-two.example.com"])
    asked_net = [name for name in asked if name.endswith(".net")]
    assert asked_net == ["evil-three.example.net"]
    assert len(asked) == 2
    assert summary["rate_limited"] == 1

    # The refusal holds its own registry, including the sibling that had not been
    # asked yet, for the pause rather than for a per-event backoff.
    for name in ("evil-one.example.com", "evil-two.example.com"):
        event = events[name]
        await db_session.refresh(event)
        assert event.processed_at is None
        assert event.last_error == "whois_rate_limited"
        delta = _seconds_until(event.next_attempt_at)
        assert (
            drain.WHOIS_RATE_LIMIT_PAUSE_SECONDS - 2
            <= delta
            <= drain.WHOIS_RATE_LIMIT_PAUSE_SECONDS + 5
        )

    # The registry that answered normally was resolved, not paused with the rest.
    answered = events["evil-three.example.net"]
    await db_session.refresh(answered)
    assert answered.processed_at is not None
    assert answered.last_error is None


@pytest.mark.asyncio
async def test_pacing_a_candidate_never_shortens_a_standing_pause(db_session):
    """A server-wide pause outranks the per-pass slot that follows it."""
    candidate = _candidate("evil.example.com")
    db_session.add(candidate)
    await db_session.flush()
    event = _whois_event(candidate.id)
    paused_until = datetime.now(timezone.utc) + timedelta(
        seconds=drain.WHOIS_RATE_LIMIT_PAUSE_SECONDS
    )
    event.next_attempt_at = paused_until
    event.last_error = "whois_rate_limited"
    db_session.add(event)
    await db_session.commit()

    outcome = await drain._hold_whois_event(
        db_session,
        event_id=event.id,
        attempt=event.attempts,
        seconds=drain.ENRICHMENT_PASS_SECONDS,
        reason="whois_pacing",
        now=datetime.now(timezone.utc),
    )

    assert outcome == "held"
    await db_session.refresh(event)
    # The row still waits out the pause, and still says why.
    assert _seconds_until(event.next_attempt_at) > drain.ENRICHMENT_PASS_SECONDS + 60
    assert event.last_error == "whois_rate_limited"


@pytest.mark.asyncio
async def test_a_lookup_that_did_not_answer_is_held_with_the_bounded_backoff(
    db_session, monkeypatch
):
    candidate = _candidate("evil.example.com")
    db_session.add(candidate)
    await db_session.flush()
    event = _whois_event(candidate.id)
    db_session.add(event)
    await db_session.commit()
    _lookup(monkeypatch, answer=lambda domain: whois_service.UNAVAILABLE)

    summary = await drain.enrich_pending_events(db_session)

    assert summary["unavailable"] == 1
    assert summary["held"] == 1
    await db_session.refresh(event)
    assert event.processed_at is None
    assert event.last_error == "whois_unavailable"
    # 30 * 2**1 on the first attempt, the backoff this drain always applied.
    assert 30 <= _seconds_until(event.next_attempt_at) <= 150


@pytest.mark.asyncio
async def test_a_lookup_that_never_answers_is_completed_once_its_tries_are_spent(
    db_session, monkeypatch
):
    candidate = _candidate("evil.example.com")
    db_session.add(candidate)
    await db_session.flush()
    event = _whois_event(candidate.id)
    event.attempts = drain.WHOIS_MAX_ATTEMPTS - 1
    db_session.add(event)
    await db_session.commit()
    _lookup(monkeypatch, answer=lambda domain: whois_service.UNAVAILABLE)

    summary = await drain.enrich_pending_events(db_session)

    assert summary["exhausted"] == 1
    await db_session.refresh(event)
    # Best effort, and honestly so: no more retries, and the row says which bound
    # was reached instead of looking like an answer that arrived.
    assert event.processed_at is not None
    assert event.last_error == "whois_unavailable_exhausted"


@pytest.mark.asyncio
async def test_a_name_nobody_registered_is_asked_again_later_not_in_thirty_seconds(
    db_session, monkeypatch
):
    candidate = _candidate("evil.example.com")
    db_session.add(candidate)
    await db_session.flush()
    event = _whois_event(candidate.id)
    db_session.add(event)
    await db_session.commit()
    _lookup(monkeypatch, answer=lambda domain: whois_service.NO_RECORD)

    summary = await drain.enrich_pending_events(db_session)

    assert summary["no_record"] == 1
    await db_session.refresh(event)
    assert event.processed_at is None
    assert event.last_error == "whois_no_record"
    delta = _seconds_until(event.next_attempt_at)
    assert (
        drain.WHOIS_NO_RECORD_RETRY_SECONDS - 5
        <= delta
        <= drain.WHOIS_NO_RECORD_RETRY_SECONDS + 5
    )


@pytest.mark.asyncio
async def test_a_candidate_whose_row_knows_the_facts_is_completed_without_a_lookup(
    db_session, monkeypatch
):
    candidate = _candidate(
        "evil.example.com",
        whois_registrar="Example Registrar",
        domain_created_at=datetime(2019, 4, 3, 12, 0, tzinfo=timezone.utc),
    )
    db_session.add(candidate)
    await db_session.flush()
    event = _whois_event(candidate.id)
    db_session.add(event)
    await db_session.commit()
    asked = _lookup(monkeypatch)

    summary = await drain.enrich_pending_events(db_session)

    # The row is the cache: nothing was asked, and nothing was left pending.
    assert asked == []
    assert summary["nothing_to_ask"] == 1
    assert summary["completed"] == 1
    await db_session.refresh(event)
    assert event.processed_at is not None
    assert event.last_error == "whois_facts_known"
    # And no arrival is reported for facts that were already known: the follow-up
    # message exists to carry what the first alert could not (WI-01).
    kinds = [
        row.payload.get("rule")
        for row in (await db_session.execute(select(IngestionEvent))).scalars()
        if row.kind == "notification"
    ]
    assert "phishing.enrichment.completed" not in kinds


@pytest.mark.asyncio
async def test_a_pause_is_scoped_only_by_a_plain_label(db_session):
    """The key becomes a LIKE pattern, so only a plain label may scope a pause."""
    candidates = [
        _candidate("evil-one.example.com"),
        _candidate("evil-two.example.net"),
    ]
    db_session.add_all(candidates)
    await db_session.flush()
    events = {candidate.phishing_domain: _whois_event(candidate.id) for candidate in candidates}
    db_session.add_all(events.values())
    await db_session.commit()
    now = datetime.now(timezone.utc)

    assert await drain._pause_whois_server(db_session, server="co*m", now=now) == 0
    assert await drain._pause_whois_server(db_session, server="com", now=now) == 1

    paused = events["evil-one.example.com"]
    untouched = events["evil-two.example.net"]
    await db_session.refresh(paused)
    await db_session.refresh(untouched)
    assert paused.last_error == "whois_rate_limited"
    assert untouched.last_error is None
    assert untouched.next_attempt_at is None
