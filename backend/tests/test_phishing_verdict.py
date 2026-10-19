"""What an analyst's decision does to the score, and to the channel (WI-12, W1.6).

A scored candidate is still a *guess*: the weights are the platform's own opinion of
what a look-alike looks like, and the audit's own example is a parked domain with no
DNS history arriving in the same message as a clone of the login page that already
presents our certificate issuer (F-08). An analyst who opens the candidate and looks
at it is not guessing, so the decision has to outrank the number — otherwise the
platform asks a person for a judgement and then ignores it.

Three properties are pinned here, and each of them is a way the verdict could be
merely decorative:

* a confirmed candidate is delivered *however low it scores*, including the
  confirmation itself: a decision nobody hears about until the next scan has not
  reached the channel, and the candidate an analyst confirms is usually one the
  score kept out of it;
* a rejected candidate is silent — not list-only. `list` is a budget judgement the
  daily digest still reports on, and a candidate somebody has already judged would
  be re-reported every day, which is exactly what teaches an operator to stop
  reading;
* every decision is a row in the audit trail carrying the verdict it replaced and
  the score it overrode, because "who dismissed this, and why?" is asked after
  whoever did it has moved on.

The routing, the digest pass, the delivery path and the API are the real ones; only
the SMTP sender is replaced, because what is under test is which messages exist.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import IngestionEvent
from app.models.audit import AuditLog
from app.models.phishing import PhishingDomain
from app.models.settings import SystemSettings
from app.services.alert_delivery_service import AlertDeliveryService
from app.services.alert_service import AlertService, phishing_alert_route
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
    def plain(self) -> str:
        return "\n".join(message["plain"] or "" for message in self.messages)


@pytest.fixture
def mailbox(monkeypatch) -> _Mailbox:
    """An installation with a working email channel, and no SMTP server."""
    sink = _Mailbox()
    monkeypatch.setattr(AlertService, "_send_email_smtp", sink.send)
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    # The per-recipient spacing is a real rate limit, and a test that waited for it
    # would be measuring the clock rather than the routing.
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
        "signals": overrides.pop("signals", {}),
    }
    values.update(overrides)
    row = PhishingDomain(**values)
    db.add(row)
    await db.flush()
    return row


async def arrival(db, row: PhishingDomain, rule: str = "phishing.candidate.created", dedup=None) -> None:
    """The notification a scan writes when it reports (or re-reports) a candidate."""
    await record_event(
        db,
        kind="notification",
        module="phishing",
        entity_id=row.id,
        payload={
            "rule": rule,
            "severity": "info",
            "phishing_domain": row.phishing_domain,
            "matched_asset": row.matched_asset,
            "finding_id": str(row.id),
        },
        dedup=dedup,
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


class _StandIn:
    """The two fields the routing reads, without a database row."""

    def __init__(self, confidence: int = 0, verdict: str | None = None) -> None:
        self.confidence = confidence
        self.verdict = verdict


class TestRouting:
    def test_the_verdict_is_read_before_the_score(self):
        """Both directions, at the ends of the scale, and the untouched middle."""
        assert phishing_alert_route(_StandIn(confidence=100, verdict="rejected")) == "suppressed"
        assert phishing_alert_route(_StandIn(confidence=0, verdict="confirmed")) == "immediate"
        # Nothing decided: exactly the bands W1.4 shipped.
        assert phishing_alert_route(_StandIn(confidence=100)) == "immediate"
        assert phishing_alert_route(_StandIn(confidence=40)) == "digest"
        assert phishing_alert_route(_StandIn(confidence=0)) == "list"
        # A candidate the caller cannot read is still not a suppression.
        assert phishing_alert_route(None) == "unknown"

    @pytest.mark.asyncio
    async def test_a_rejection_is_silence_in_the_channel_and_in_the_digest(
        self, db_session, mailbox
    ):
        """A judged candidate stops being reported — including by tomorrow's digest."""
        await configured_email(db_session)
        # High enough to interrupt someone, and judged anyway: this is the case the
        # verdict exists for.
        loud = await candidate(db_session, "paypa1-login.example", 90, verdict="rejected")
        # Middle band: without the verdict this one *would* be digested.
        quiet = await candidate(db_session, "secure-chase.example", 40, verdict="rejected")
        await arrival(db_session, loud)
        await arrival(db_session, quiet)

        assert await dispatch_notification_events(db_session) == 0
        assert await drain(db_session) == []
        assert mailbox.messages == []

        # The reason is recorded rather than the event being held: the row stays
        # readable in the list, only the channel goes quiet.
        rows = await events(db_session)
        assert {row.last_error for row in rows} == {"phishing_verdict_rejected"}
        assert all(row.processed_at is not None for row in rows)

        digest = await queue_phishing_digest(db_session)
        assert digest["queued"] == 0
        assert mailbox.messages == []

    @pytest.mark.asyncio
    async def test_a_confirmation_below_the_threshold_still_alerts(
        self, db_session, client, auth_headers_analyst, mailbox
    ):
        """The confirmation is a message, not only a flag on a row."""
        await configured_email(db_session)
        low = await candidate(db_session, "nearly-ours.example", 0)
        await db_session.commit()

        response = await client.patch(
            f"/api/v1/phishing/threats/{low.id}",
            json={"verdict": "confirmed", "verdict_reason": "clone of our login page"},
            headers=auth_headers_analyst,
        )
        assert response.status_code == 200, response.text

        # The drain reads the candidate's own row, and this session has held that
        # instance since before the request committed it (the test sessionmaker sets
        # ``expire_on_commit=False``, so a cached row does not refresh itself). The
        # worker that runs the drain has its own session and sees the committed row,
        # which is what this states explicitly rather than relying on the identity
        # map happening to be empty.
        db_session.expire_all()
        assert await dispatch_notification_events(db_session) == 1
        await drain(db_session)
        assert len(mailbox.messages) == 1
        assert "nearly-ours.example" in mailbox.plain

    @pytest.mark.asyncio
    async def test_a_confirmed_candidate_re_alerts_when_it_changes(self, db_session, mailbox):
        """A change to a confirmed candidate is news, however the score reads."""
        await configured_email(db_session)
        row = await candidate(db_session, "changes-later.example", 0, verdict="confirmed")
        await arrival(db_session, row)
        assert await dispatch_notification_events(db_session) == 1
        await drain(db_session)
        assert len(mailbox.messages) == 1

        received_at = row.ip_address
        row.ip_address = "203.0.113.77"
        assert received_at != row.ip_address
        await arrival(
            db_session,
            row,
            rule="phishing.candidate.changed",
            dedup="ip_address|203.0.113.77",
        )
        assert await dispatch_notification_events(db_session) == 1
        await drain(db_session)
        assert len(mailbox.messages) == 2

    @pytest.mark.asyncio
    async def test_an_undecided_candidate_is_still_routed_by_its_score(self, db_session, mailbox):
        """The ordinary path is unchanged: nothing decided, nothing overridden."""
        await configured_email(db_session)
        digest_row = await candidate(db_session, "mid.example", 40)
        low = await candidate(db_session, "low.example", 0)
        await arrival(db_session, digest_row)
        await arrival(db_session, low)

        assert await dispatch_notification_events(db_session) == 0
        reasons = {row.last_error for row in await events(db_session)}
        assert reasons == {"phishing_digest_pending", "phishing_below_threshold"}

        digest = await queue_phishing_digest(db_session)
        assert digest["queued"] == 1
        await drain(db_session)
        assert len(mailbox.messages) == 1


class TestVerdictAPI:
    @pytest.mark.asyncio
    async def test_rejecting_without_a_reason_is_refused(
        self, client, db_session, auth_headers_analyst
    ):
        row = await candidate(db_session, "no-reason.example", 70)
        await db_session.commit()

        response = await client.patch(
            f"/api/v1/phishing/threats/{row.id}",
            json={"verdict": "rejected"},
            headers=auth_headers_analyst,
        )
        assert response.status_code == 400, response.text

        await db_session.refresh(row)
        assert row.verdict is None
        audited = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "phishing.threat.verdict")
            )
        ).scalars().all()
        assert audited == []

    @pytest.mark.asyncio
    async def test_a_reason_without_a_verdict_is_refused(
        self, client, db_session, auth_headers_analyst
    ):
        row = await candidate(db_session, "orphan-reason.example", 70)
        await db_session.commit()

        response = await client.patch(
            f"/api/v1/phishing/threats/{row.id}",
            json={"verdict_reason": "parked"},
            headers=auth_headers_analyst,
        )
        assert response.status_code == 400, response.text

    @pytest.mark.asyncio
    async def test_the_decision_is_readable_and_reversible(
        self, client, db_session, auth_headers_analyst, test_analyst
    ):
        row = await candidate(db_session, "reversible.example", 25)
        await db_session.commit()

        decided = await client.patch(
            f"/api/v1/phishing/threats/{row.id}",
            json={"verdict": "rejected", "verdict_reason": "marketplace placeholder"},
            headers=auth_headers_analyst,
        )
        assert decided.status_code == 200, decided.text
        body = decided.json()
        assert body["verdict"] == "rejected"
        assert body["verdict_reason"] == "marketplace placeholder"
        assert body["verdict_by"] == str(test_analyst.id)
        assert body["verdict_at"] is not None

        # Listing carries the decision too, or the list would keep showing an
        # undecided candidate while the channel is silent about it.
        listed = await client.get(
            "/api/v1/phishing/threats?size=50", headers=auth_headers_analyst
        )
        shown = {item["phishing_domain"]: item for item in listed.json()["items"]}
        assert shown["reversible.example"]["verdict"] == "rejected"

        # An un-decision: the candidate goes back to being routed by its score, and
        # the author goes with the verdict.
        cleared = await client.patch(
            f"/api/v1/phishing/threats/{row.id}",
            json={"verdict": None},
            headers=auth_headers_analyst,
        )
        assert cleared.status_code == 200, cleared.text
        assert cleared.json()["verdict"] is None
        assert cleared.json()["verdict_reason"] is None
        assert cleared.json()["verdict_by"] is None
        assert cleared.json()["verdict_at"] is None

    @pytest.mark.asyncio
    async def test_every_decision_is_an_audit_row(
        self, client, db_session, auth_headers_analyst, test_analyst
    ):
        row = await candidate(db_session, "audited.example", 80)
        await db_session.commit()

        for payload in (
            {"verdict": "rejected", "verdict_reason": "parked"},
            {"verdict": "confirmed", "verdict_reason": "appeared in our certificate feed"},
        ):
            response = await client.patch(
                f"/api/v1/phishing/threats/{row.id}", json=payload, headers=auth_headers_analyst
            )
            assert response.status_code == 200, response.text

        logs = (
            await db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == "phishing.threat.verdict")
                .order_by(AuditLog.seq)
            )
        ).scalars().all()
        assert len(logs) == 2

        first, second = logs
        assert first.user_id == test_analyst.id
        assert first.details["verdict"] == "rejected"
        assert first.details["previous_verdict"] is None
        assert first.details["reason"] == "parked"
        # The score the decision overrode, so a later reader can see what was
        # dismissed without opening the finding.
        assert first.details["confidence"] == 80
        assert second.details["verdict"] == "confirmed"
        assert second.details["previous_verdict"] == "rejected"
        assert second.details["phishing_domain"] == "audited.example"

    @pytest.mark.asyncio
    async def test_a_viewer_cannot_decide(self, client, db_session, auth_headers_viewer):
        row = await candidate(db_session, "viewer-cannot.example", 80)
        await db_session.commit()

        response = await client.patch(
            f"/api/v1/phishing/threats/{row.id}",
            json={"verdict": "confirmed"},
            headers=auth_headers_viewer,
        )
        assert response.status_code == 403

        await db_session.refresh(row)
        assert row.verdict is None

    @pytest.mark.asyncio
    async def test_the_stamp_is_the_moment_of_the_decision(
        self, client, db_session, auth_headers_analyst
    ):
        row = await candidate(db_session, "stamped.example", 10)
        await db_session.commit()
        before = datetime.now(timezone.utc)

        response = await client.patch(
            f"/api/v1/phishing/threats/{row.id}",
            json={"verdict": "confirmed"},
            headers=auth_headers_analyst,
        )
        assert response.status_code == 200

        await db_session.refresh(row)
        stamped = row.verdict_at
        assert stamped is not None
        assert stamped.replace(tzinfo=timezone.utc) >= before
        # Confirming needs no reason, and storing none is not an error.
        assert row.verdict_reason is None
