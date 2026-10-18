"""What a phishing alert says, and what it must never say (WI-01/WI-02, W0.2).

The message was assembled from the payload of the moment a candidate was first
seen — whatever the connector happened to report then. Everything the platform
learned afterwards was written to the row and never shown: a candidate found
before its registration was resolved arrived with no registrar, no abuse contact
and no age, and nothing told the reader that anything was missing. In the other
direction, every service key the event carried became a column, so the raw finding
was printed as a serialized Python dictionary inside the alert.

These tests pin the two halves of the fix and the follow-up it makes possible: the
facts of a delivered message are read from the stored row at send time, the columns
are a declared list rather than "whatever keys the event had", and a registration
resolved after the finding was reported produces exactly one additional message —
the one that now says who the registrar is.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import Connector, IngestionEvent, PhishingDomain
from app.models.alert_delivery import AlertDelivery
from app.models.settings import SystemSettings
from app.services.alert_delivery_service import AlertDeliveryService
from app.services.alert_service import AlertService
from app.services.ingestion_events import enrich_one_event
from app.services.ingestion_service import ingest_findings

#: A value only the raw finding carries. If it reaches a rendered message, the
#: message is printing the payload of the moment the candidate was found.
MARKER = "raw-finding-marker"
NOW = datetime.now(timezone.utc).replace(microsecond=0)


class _Settings:
    """Channel configuration only: the senders themselves are stubbed."""

    email_alerts_enabled = True
    telegram_alerts_enabled = False
    alert_email_user_ids: list[str] = []
    alert_recipient_email_decrypted = "soc@example.com"
    telegram_bot_token_decrypted = None
    telegram_chat_ids: list[str] = []


class _Captured:
    def __init__(self) -> None:
        self.email: list[dict] = []

    @property
    def plain(self) -> str:
        return self.email[0]["plain"]

    @property
    def html(self) -> str:
        return self.email[0]["html"]


@pytest.fixture
def message(db_session, monkeypatch):
    """An AlertService on the real session, with both senders captured."""
    service = AlertService(db_session)
    service._audit_alert = AsyncMock()
    sink = _Captured()

    async def _email(*, to, subject, html_body, plain_body=None):
        sink.email.append(
            {"to": to, "subject": subject, "html": html_body, "plain": plain_body}
        )
        return True

    monkeypatch.setattr(service, "_get_settings", AsyncMock(return_value=_Settings()))
    monkeypatch.setattr(service, "_send_email_smtp", _email)
    return service, sink


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


async def feed(db, connector, item) -> None:
    await ingest_findings(db, connector=connector, job_id=None, findings=[item])
    await db.commit()


async def queued(db) -> list[dict]:
    events = list((await db.execute(select(IngestionEvent))).scalars())
    return [event.payload for event in events if event.kind == "notification"]


async def candidate(db) -> PhishingDomain:
    return (await db.execute(select(PhishingDomain))).scalar_one()


async def deliver(service, sink, payloads) -> str:
    """Render one batch exactly as the delivery path does, and answer the mail."""
    await service.send_aggregated_alert_notification(
        threat_type="phishing", findings=payloads, job_id=None, channel="email", target=None
    )
    return sink.plain


@pytest.mark.asyncio
async def test_the_message_prints_the_row_as_it_stands_at_send_time(db_session, message):
    service, sink = message
    connector = await phishing_connector(db_session)
    await feed(
        db_session,
        connector,
        {
            "phishing_domain": "evil.example.com",
            "matched_asset": "example.com",
            "ip_address": "203.0.113.9",
        },
    )
    # The enrichment worker resolves the registration *after* the candidate was
    # reported, which is the ordinary order of events.
    row = await candidate(db_session)
    row.whois_registrar = "Example Registrar"
    row.whois_abuse_email = "abuse@example.com"
    row.domain_created_at = NOW - timedelta(days=1234)
    await db_session.commit()

    plain = await deliver(service, sink, await queued(db_session))

    assert "Domain=evil.example.com" in plain
    assert "Matched asset=example.com" in plain
    assert "Registrar=Example Registrar" in plain
    assert "Abuse contact=abuse@example.com" in plain
    assert "Age (days)=1234" in plain
    assert "IP / ASN / Org=203.0.113.9" in plain
    assert "First seen=" in plain
    # The HTML alternative is the same facts, so the columns of its table carry
    # them too rather than only the text part.
    assert "Registrar" in sink.html and "Example Registrar" in sink.html
    assert "Age (days)" in sink.html


@pytest.mark.asyncio
async def test_a_batch_reads_the_candidates_in_one_statement(db_session, message, monkeypatch):
    """A hundred-finding alert costs one read, not a hundred (F-17's lesson)."""
    service, sink = message
    connector = await phishing_connector(db_session)
    for index in range(5):
        await feed(
            db_session,
            connector,
            {
                "phishing_domain": f"evil-{index}.example.com",
                "matched_asset": "example.com",
            },
        )
    payloads = await queued(db_session)
    statements: list[str] = []
    original = db_session.execute

    async def counting(statement, *args, **kwargs):
        statements.append(str(statement))
        return await original(statement, *args, **kwargs)

    monkeypatch.setattr(db_session, "execute", counting)
    plain = await deliver(service, sink, payloads)

    assert len([text for text in statements if "drp_phishing_domains" in text]) == 1
    assert plain.count("Domain=") == 5


@pytest.mark.asyncio
async def test_the_message_never_prints_the_finding_or_the_service_keys(db_session, message):
    service, sink = message
    connector = await phishing_connector(db_session)
    await feed(
        db_session,
        connector,
        {
            "phishing_domain": "evil.example.com",
            "matched_asset": "example.com",
            "provider_field": MARKER,
        },
    )

    payloads = await queued(db_session)
    plain = await deliver(service, sink, payloads)

    # The raw finding belongs to the page this message links to and to the source
    # observations it is stored in, not to the mail — nor to the queue rows and
    # delivery rows every event is copied into.
    assert MARKER not in plain and MARKER not in sink.html
    assert "evidence" not in plain
    assert all("evidence" not in payload for payload in payloads)
    # Nor does any other service key of the event become a column.
    for key in ("finding_id", "created_at", "status", "detection_source", "rule", "title"):
        assert key not in plain, f"{key} became a column of the message"


@pytest.mark.asyncio
async def test_a_revision_prints_what_moved_beside_the_stored_row(db_session, message):
    service, sink = message
    connector = await phishing_connector(db_session)
    await feed(db_session, connector, {"phishing_domain": "evil.example.com", "matched_asset": "example.com", "ip_address": "203.0.113.10"})
    await feed(db_session, connector, {"phishing_domain": "evil.example.com", "matched_asset": "example.com", "ip_address": "203.0.113.11"})
    row = await candidate(db_session)
    row.whois_registrar = "Example Registrar"
    await db_session.commit()
    revisions = [
        payload
        for payload in await queued(db_session)
        if payload.get("rule") == "phishing.candidate.changed"
    ]

    plain = await deliver(service, sink, revisions)

    assert "Field=IP address" in plain
    assert "Previous value=203.0.113.10" in plain
    assert "Current value=203.0.113.11" in plain
    # The row is the source of the facts, so the revision shows what the platform
    # holds now, not what the payload of the change happened to repeat.
    assert "IP / ASN / Org=203.0.113.11" in plain
    assert "Registrar=Example Registrar" in plain


@pytest.mark.asyncio
async def test_the_delivery_worker_reads_the_row_too(db_session, monkeypatch):
    """The queued path renders the same message as the immediate one (W0.2).

    A delivery that had to be retried is rendered by the worker from the row it
    claimed, so the fix has to live in the renderer rather than in one caller.
    """
    row = SystemSettings(telegram_alerts_enabled=True, telegram_chat_ids=["-1001234"])
    row.telegram_bot_token_decrypted = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
    db_session.add(row)
    connector = await phishing_connector(db_session)
    await feed(
        db_session,
        connector,
        {
            "phishing_domain": "evil.example.com",
            "matched_asset": "example.com",
            "provider_field": MARKER,
        },
    )
    candidate_row = await candidate(db_session)
    candidate_row.whois_registrar = "Example Registrar"
    candidate_row.domain_created_at = NOW - timedelta(days=77)
    await db_session.commit()
    monkeypatch.setattr(settings, "ALERT_AGGREGATION_DELAY_SECONDS", 0)
    monkeypatch.setattr(settings, "ALERT_RECIPIENT_INTERVAL_SECONDS", 0)
    sent: list[str] = []

    async def _telegram(self, text, parse_mode="HTML", chat_id=None):
        sent.append(text)
        return True

    monkeypatch.setattr(AlertService, "_send_telegram", _telegram)
    queue = AlertDeliveryService(db_session)
    for payload in await queued(db_session):
        await queue.enqueue(threat_type="phishing", details=payload)
    await db_session.commit()

    assert (await queue.process_one_group(max_attempts=3))["status"] == "sent"

    text = "\n".join(sent)
    assert "Registrar: Example Registrar" in text
    assert "Age (days)" in text
    assert MARKER not in text
    assert (await db_session.execute(select(AlertDelivery))).scalars().all()


@pytest.mark.asyncio
async def test_completed_enrichment_is_one_follow_up(db_session, monkeypatch):
    """A resolved registration is reported once, and the reader sees why (WI-01)."""
    connector = await phishing_connector(db_session)
    await feed(db_session, connector, {"phishing_domain": "evil.example.com", "matched_asset": "example.com"})
    finding = await candidate(db_session)

    async def resolves(self, threat):
        threat.whois_registrar = "Example Registrar"
        threat.whois_abuse_email = "abuse@example.com"
        threat.domain_created_at = NOW - timedelta(days=30)

    monkeypatch.setattr("app.services.phishing.whois_service.WhoisService.enrich", resolves)
    assert await enrich_one_event(db_session) is True

    events = list((await db_session.execute(select(IngestionEvent))).scalars())
    completed = [
        event
        for event in events
        if event.payload.get("rule") == "phishing.enrichment.completed"
    ]
    assert len(completed) == 1
    assert completed[0].entity_id == finding.id
    assert completed[0].event_key.endswith(":enriched")

    # A second pass over the same candidate is the same fact, not a second message.
    second = IngestionEvent(
        event_key="whois:phishing:repeat",
        kind="whois",
        module="phishing",
        entity_id=finding.id,
        payload={},
    )
    db_session.add(second)
    await db_session.commit()
    assert await enrich_one_event(db_session) is True
    events = list((await db_session.execute(select(IngestionEvent))).scalars())
    assert (
        len(
            [
                event
                for event in events
                if event.payload.get("rule") == "phishing.enrichment.completed"
            ]
        )
        == 1
    )


@pytest.mark.asyncio
async def test_an_enrichment_that_resolved_nothing_is_not_an_event(db_session, monkeypatch):
    connector = await phishing_connector(db_session)
    await feed(db_session, connector, {"phishing_domain": "evil.example.com", "matched_asset": "example.com"})

    async def resolves_nothing(self, threat):
        return None

    monkeypatch.setattr(
        "app.services.phishing.whois_service.WhoisService.enrich", resolves_nothing
    )
    assert await enrich_one_event(db_session) is True
    events = list((await db_session.execute(select(IngestionEvent))).scalars())
    assert [event.payload.get("rule") for event in events if event.kind == "notification"] == [
        "phishing.candidate.created"
    ]


@pytest.mark.asyncio
async def test_the_message_says_how_many_sources_agreed(db_session, message):
    """Corroboration travels with the message, not only with the score (WI-30).

    Two providers reporting one look-alike is the fact the score pays +15 for, and a
    reader deciding whether to interrupt somebody's day with it has to be able to see
    that the two reports were two providers — and which ones. The names come from the
    evidence rows, so a connector renamed in the UI does not change what was observed.
    """
    service, sink = message
    finder = await phishing_connector(db_session)
    await feed(
        db_session,
        finder,
        {"phishing_domain": "evil.example.com", "matched_asset": "example.com"},
    )
    confirmer = Connector(
        name="netlas-phishing",
        connector_type="phishing",
        default_job_type="phishing.netlas",
        status="enabled",
        provider="netlas",
    )
    db_session.add(confirmer)
    await db_session.flush()
    await feed(
        db_session,
        confirmer,
        {"phishing_domain": "evil.example.com", "matched_asset": "example.com"},
    )

    text = await deliver(service, sink, await queued(db_session))

    # Both names beside the count, because "two sources" without them is a claim a
    # reader cannot check.
    assert "Sources=2 (dnstwist-phishing-default, netlas)" in text
