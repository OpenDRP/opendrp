"""What the score decides about the channel, and what the middle band gets (WI-10).

Before the budget every candidate a scan produced was worth a message, so a
weekday's eighty parked look-alikes and the one clone of the login page arrived
identically and the channel taught its readers to ignore it (F-08). W1.4 splits
that one answer into three, and this file pins each of them where a reader can see
it: the candidates at or above the direct threshold still interrupt someone, the
middle band waits for one daily digest instead of going silent, and everything
below is list-only.

Two properties carry more weight than the thresholds themselves:

* the band is read *when the event is drained*, from the candidate's own stored
  score, so the decision is about the row as it stands rather than about what the
  connector believed when it reported (the same reason the alert itself is rendered
  from the row);
* a candidate the digest carried is not carried again the next day — and one that
  changed *is*, because a revision is a new fact about it and a summary that never
  mentions it again would make the change invisible.

The routing, the digest pass and the delivery path are the real ones here; only the
SMTP sender is replaced, because what is under test is which messages exist, not
whether a mail server accepts them.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import IngestionEvent
from app.models.phishing import PhishingDomain
from app.models.settings import SystemSettings
from app.services.alert_delivery_service import AlertDeliveryService
from app.services.alert_service import AlertService, phishing_alert_route
from app.services import phishing_score_service as scoring
from app.services.ingestion_events import (
    dispatch_notification_events,
    queue_phishing_digest,
    record_event,
)


class _Mailbox:
    """The messages an installation would have sent, captured at the boundary."""

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
    """An installation with a working email channel, and no SMTP server."""
    sink = _Mailbox()
    monkeypatch.setattr(AlertService, "_send_email_smtp", sink.send)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    # The per-recipient spacing is a real rate limit, and a digest test that waited
    # for it would be measuring the clock instead of the budget.
    monkeypatch.setattr(settings, "ALERT_RECIPIENT_INTERVAL_SECONDS", 0)
    return sink


async def configured_email(db) -> SystemSettings:
    row = SystemSettings(email_alerts_enabled=True, smtp_host="smtp.example.com", smtp_port=587)
    row.alert_recipient_email_decrypted = "soc@example.com"
    db.add(row)
    await db.commit()
    return row


async def candidate(db, domain: str, confidence: int, **overrides) -> PhishingDomain:
    values = {
        "phishing_domain": domain,
        "matched_asset": "example.com",
        "detection_source": "dnstwist",
        "confidence": confidence,
        "signals": overrides.pop("signals", {"source_corroboration": 0}),
    }
    values.update(overrides)
    row = PhishingDomain(**values)
    db.add(row)
    await db.flush()
    return row


async def arrival(db, row: PhishingDomain) -> None:
    """The notification a scan writes when it reports one candidate."""
    await record_event(
        db,
        kind="notification",
        module="phishing",
        entity_id=row.id,
        payload={
            "rule": "phishing.candidate.created",
            "severity": "info",
            "phishing_domain": row.phishing_domain,
            "matched_asset": row.matched_asset,
            "finding_id": str(row.id),
        },
    )
    await db.commit()


async def drain(db) -> list[dict]:
    """Deliver every queued group, as the worker's own loop does."""
    service = AlertDeliveryService(db)
    results = []
    for _ in range(10):
        result = await service.process_one_group(max_attempts=3)
        if result["status"] == "idle":
            break
        results.append(result)
    return results


async def events(db) -> list[IngestionEvent]:
    return list((await db.execute(select(IngestionEvent))).scalars())


#: Ten candidates across the three bands: three that interrupt someone, four for
#: the digest, three that are only in the list. The scores are the real ones — a
#: candidate's confidence is what its recorded signals add up to, so a message that
#: prints both cannot claim a score its own signals do not explain.
BANDS = (
    (
        "high-1.example.com",
        {"young_domain": 5, "brand_in_body": True, "title_match": True, "tls_issuer_reuse": True},
        "immediate",
    ),
    (
        "high-2.example.com",
        {"young_domain": 20, "title_match": True, "favicon_perceptual_match": True},
        "immediate",
    ),
    # At the threshold exactly: the band includes it.
    (
        "high-3.example.com",
        {"young_domain": 30, "title_match": True, "brand_in_body": True},
        "immediate",
    ),
    (
        "mid-1.example.com",
        {"young_domain": 12, "brand_in_body": True, "source_corroboration": 3},
        "digest",
    ),
    ("mid-2.example.com", {"html_similarity": 0.9, "tls_issuer_reuse": True}, "digest"),
    ("mid-3.example.com", {"young_domain": 30, "brand_in_body": True}, "digest"),
    (
        "mid-4.example.com",
        {"brand_in_body": True, "source_corroboration": 2},
        "digest",
    ),
    ("low-1.example.com", {"brand_in_body": True}, "list"),
    # A parked hint is worth −30, and a score is never negative: the honest answer
    # for a look-alike with nothing else going for it is zero.
    ("low-2.example.com", {"parked_hint": "sedo"}, "list"),
    ("low-3.example.com", {}, "list"),
)


def expected_confidence(signals: dict) -> int:
    return scoring.score_signals(signals)


async def seed_bands(db) -> dict[str, PhishingDomain]:
    rows = {}
    for domain, signals, _ in BANDS:
        rows[domain] = await candidate(db, domain, expected_confidence(signals), signals=signals)
        await arrival(db, rows[domain])
    return rows


class TestRouting:
    """The score path: what the bands do when nobody has decided anything (W1.4).

    Each stand-in carries the row's verdict field as ``None``, which is the ordinary
    state of a candidate and the only one these tests are about — the routing reads the
    verdict *first* (WI-12, W1.6), and a row without the field would not be a candidate
    row at all.
    """

    def test_the_band_decides_what_the_channel_does(self):
        class _Row:
            def __init__(self, confidence: int) -> None:
                self.confidence = confidence
                self.verdict = None

        assert phishing_alert_route(_Row(95)) == "immediate"
        assert phishing_alert_route(_Row(60)) == "immediate"
        assert phishing_alert_route(_Row(59)) == "digest"
        assert phishing_alert_route(_Row(30)) == "digest"
        assert phishing_alert_route(_Row(29)) == "list"
        assert phishing_alert_route(_Row(0)) == "list"
        # A candidate the drain cannot read is not suppressed: the caller has no
        # score to decide with, and dropping the message would be deciding anyway.
        assert phishing_alert_route(None) == "unknown"

    def test_disabling_the_digest_makes_the_budget_binary(self, monkeypatch):
        class _Row:
            confidence = 45
            verdict = None

        assert phishing_alert_route(_Row()) == "digest"
        monkeypatch.setattr(settings, "ALERT_PHISHING_DIGEST_ENABLED", False)
        assert phishing_alert_route(_Row()) == "list"

    def test_the_thresholds_are_read_at_call_time(self, monkeypatch):
        class _Row:
            confidence = 70
            verdict = None

        assert phishing_alert_route(_Row()) == "immediate"
        monkeypatch.setattr(settings, "ALERT_CONFIDENCE_DIRECT", 90)
        monkeypatch.setattr(settings, "ALERT_CONFIDENCE_DIGEST", 45)
        assert phishing_alert_route(_Row()) == "digest"


@pytest.mark.asyncio
async def test_ten_candidates_become_one_message_and_one_digest(db_session, mailbox):
    """The plan's own acceptance case, end to end through the real outbox."""
    await configured_email(db_session)
    rows = await seed_bands(db_session)

    dispatched = await dispatch_notification_events(db_session)
    delivered = await drain(db_session)
    assert dispatched == 3
    assert [result["count"] for result in delivered] == [3]
    assert len(mailbox.messages) == 1
    assert mailbox.subjects == ["[OpenDRP Alert] 3 new findings"]
    assert "high-1.example.com" in mailbox.plain
    assert "mid-1.example.com" not in mailbox.plain
    assert "low-1.example.com" not in mailbox.plain

    # The digest band waited for the pass, and the pass is one message.
    digest = await queue_phishing_digest(db_session)
    assert digest == {"queued": 4, "candidates": 4}
    assert [result["count"] for result in await drain(db_session)] == [4]

    assert len(mailbox.messages) == 2
    assert mailbox.subjects[1] == (
        "[OpenDRP Alert] Phishing digest: 4 candidates below the alert threshold"
    )
    digest_mail = mailbox.messages[1]["plain"]
    for domain, _, band in BANDS:
        if band == "digest":
            assert f"Domain={domain}" in digest_mail
        else:
            assert f"Domain={domain}" not in digest_mail
    # The middle band is reported with the score that kept it out of the inbox and
    # the signals that score came from (WI-08), or the reader cannot triage it.
    assert "Confidence=55" in digest_mail
    assert (
        "Signals=young_domain (+25); brand_in_body (+15); source_corroboration (+15)"
        in digest_mail
    )

    # Every candidate that was below the threshold is marked as digested, so the
    # next run reports what is new rather than the same four look-alikes.
    for domain, _, band in BANDS:
        assert (rows[domain].digest_queued_at is not None) is (band == "digest")


@pytest.mark.asyncio
async def test_a_consumed_event_says_which_band_consumed_it(db_session, mailbox):
    """The alert history has to tell "not worth a message" from "nothing to send to"."""
    await configured_email(db_session)
    rows = await seed_bands(db_session)
    await dispatch_notification_events(db_session)

    reasons = {
        event.payload["phishing_domain"]: event.last_error
        for event in await events(db_session)
    }
    assert reasons == {
        domain: {
            "immediate": None,
            "digest": "phishing_digest_pending",
            "list": "phishing_below_threshold",
        }[band]
        for domain, _, band in BANDS
    }
    # Consumed, not left pending: the row was handled, and the reason it produced no
    # message is recorded on it.
    assert all(
        event.processed_at is not None
        for event in await events(db_session)
        if event.payload["phishing_domain"] in rows
    )


@pytest.mark.asyncio
async def test_digest_disabled_delivers_only_the_direct_band(db_session, mailbox, monkeypatch):
    """Off is a legitimate policy: the inbox is for what the score is sure about."""
    await configured_email(db_session)
    await seed_bands(db_session)
    monkeypatch.setattr(settings, "ALERT_PHISHING_DIGEST_ENABLED", False)

    assert await dispatch_notification_events(db_session) == 3
    assert await queue_phishing_digest(db_session) == {
        "queued": 0,
        "candidates": 0,
        "reason": "digest_disabled",
    }
    assert [result["count"] for result in await drain(db_session)] == [3]
    assert len(mailbox.messages) == 1
    assert "mid-1.example.com" not in mailbox.plain


@pytest.mark.asyncio
async def test_the_digest_reports_a_candidate_once_and_a_change_again(db_session, mailbox):
    """Once a day is not "once, unless something changes" — a revision is a fact."""
    await configured_email(db_session)
    row = await candidate(db_session, "mid.example.com", 45)
    await db_session.commit()

    assert await queue_phishing_digest(db_session) == {"queued": 1, "candidates": 1}
    await drain(db_session)
    assert len(mailbox.messages) == 1

    # The same candidate, unchanged, is not tomorrow's news.
    assert await queue_phishing_digest(db_session) == {"queued": 0, "candidates": 0}

    # A revision is: the scan wrote a change event for it (W0.1), which the budget
    # consumed rather than delivered — and which makes the candidate tomorrow's news
    # again. Its own `updated_at` cannot be the marker: writing the digest mark is an
    # update of the same row, so every digested candidate would look changed at once.
    row.ip_address = "203.0.113.11"
    await db_session.flush()
    await record_event(
        db_session,
        kind="notification",
        module="phishing",
        entity_id=row.id,
        payload={"rule": "phishing.candidate.changed", "phishing_domain": row.phishing_domain},
        dedup="ip_address|203.0.113.11",
    )
    await db_session.commit()
    assert await queue_phishing_digest(db_session) == {"queued": 1, "candidates": 1}
    await drain(db_session)
    assert len(mailbox.messages) == 2


@pytest.mark.asyncio
async def test_a_resolved_candidate_is_not_digested(db_session, mailbox):
    """Closing a finding is how an operator says they are done reading about it."""
    await configured_email(db_session)
    await candidate(db_session, "mid.example.com", 45, status="resolved")
    await db_session.commit()

    assert await queue_phishing_digest(db_session) == {"queued": 0, "candidates": 0}
    assert await drain(db_session) == []
    assert mailbox.messages == []


@pytest.mark.asyncio
async def test_an_installation_with_no_channel_does_not_mark_the_candidate(db_session):
    """The mark means "reported", and nothing was reported."""
    row = await candidate(db_session, "mid.example.com", 45)
    await db_session.commit()

    assert await queue_phishing_digest(db_session) == {"queued": 0, "candidates": 1}
    assert row.digest_queued_at is None


@pytest.mark.asyncio
async def test_the_digest_fits_in_one_message_however_many_candidates_wait(
    db_session, mailbox, monkeypatch
):
    """The bound is what makes it a digest: the rest are simply tomorrow's.

    Without it a busy week would turn the daily summary into the per-finding stream
    the middle band exists to prevent — and the queue would send it as several
    messages, because a group is claimed up to the per-message limit.
    """
    await configured_email(db_session)
    monkeypatch.setattr(settings, "ALERT_MAX_FINDINGS_PER_MESSAGE", 2)
    for index in range(5):
        await candidate(db_session, f"mid-{index}.example.com", 45)
    await db_session.commit()

    async def waiting() -> int:
        return len(
            list(
                (
                    await db_session.execute(
                        select(PhishingDomain).where(
                            PhishingDomain.digest_queued_at.is_(None)
                        )
                    )
                ).scalars()
            )
        )

    assert await queue_phishing_digest(db_session) == {"queued": 2, "candidates": 2}
    await drain(db_session)
    assert len(mailbox.messages) == 1
    assert "2 candidates below the alert threshold" in mailbox.subjects[0]

    # The three the message did not carry are still waiting: they were not marked,
    # so the next pass considers them without anything having changed about them.
    assert await waiting() == 3
    assert await queue_phishing_digest(db_session) == {"queued": 2, "candidates": 2}
    await drain(db_session)
    assert len(mailbox.messages) == 2
    assert await waiting() == 1


@pytest.mark.asyncio
async def test_the_digest_body_carries_the_facts_of_each_candidate(db_session, mailbox):
    """A digest is only useful if it reads like the alert it replaces."""
    await configured_email(db_session)
    await candidate(
        db_session,
        "mid.example.com",
        50,
        ip_address="203.0.113.10",
        whois_registrar="Example Registrar",
        whois_abuse_email="abuse@example.com",
        domain_created_at=datetime.now(timezone.utc) - timedelta(days=12),
        signals={"young_domain": 12},
    )
    await db_session.commit()

    await queue_phishing_digest(db_session)
    await drain(db_session)

    plain = mailbox.messages[0]["plain"]
    assert "Domain=mid.example.com" in plain
    assert "Registrar=Example Registrar" in plain
    assert "Abuse contact=abuse@example.com" in plain
    assert "Age (days)=12" in plain
    assert "IP / ASN / Org=203.0.113.10" in plain
    assert "Confidence=50" in plain
    assert "Signals=young_domain (+25)" in plain
    # The payload keys that shaped the message are not columns of it: `digest` and
    # `rule` told the delivery path what to build, and printing them would be the
    # service-key leak W0.2 removed.
    assert "digest=" not in plain
    assert "rule=" not in plain
    assert "severity=" not in plain
