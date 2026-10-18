"""What a credential-breach alert says, and what it must never say.

The alert is the only part of this module an operator reads, and the defect these
tests were written for was not a missing fact but an excess of them: the breach
branch of ``_facts`` rendered the event payload with the generic rule — "every key
that is not one of the finding's own neutral facts" — so a delivered message
carried the row's ``id``, its ``created_at``, its ``status``, the connector's
``source``, a truncated ``description``, ``data_classes`` as a JSON array and the
whole ``attributes`` blob. A fifty-incident scan then needed twelve Telegram
messages and 56.6 KB of email, and the two facts that mattered (which incident,
which account) were buried in the machine's own bookkeeping.

Two properties are asserted here, and both are about the *shape* of the message
rather than one string in it:

* the declared columns are the only columns (``_BREACH_COLUMNS``), and the facts
  are read from the stored row as it stands at send time, not from the payload the
  connector submitted;
* a batch stays readable: fifty incidents fit into at most six Telegram parts and
  one email under 32 KB, which is what makes the message a report instead of a dump.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from html.parser import HTMLParser
from unittest.mock import AsyncMock

import pytest

from app.models.breach import Breach
from app.services.alert_service import AlertService


class _Rendered(HTMLParser):
    """Read a Telegram payload the way the provider's parser does.

    The message is HTML, so a fact wrapped for emphasis (the counted breakdown) is
    only readable as text once the tags are gone.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.parts: list[str] = []

    @property
    def text(self) -> str:
        return "".join(self.parts)

    def handle_starttag(self, tag, attrs):
        self.stack.append(tag)

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()

    def handle_data(self, data):
        self.parts.append(data)


def rendered(markup: str) -> str:
    parser = _Rendered()
    parser.feed(markup)
    parser.close()
    assert parser.stack == [], "unbalanced markup"
    return parser.text

#: The keys the payload of a delivered event carries that must never reach a
#: reader: the platform's own bookkeeping and the raw provider blob.
_MACHINE_KEYS = (
    "created_at",
    "status",
    "source",
    "description",
    "attributes",
    "last_seen_at",
)


class _Settings:
    email_alerts_enabled = True
    telegram_alerts_enabled = True
    alert_email_user_ids: list[str] = []
    alert_recipient_email_decrypted = "soc@example.com"
    telegram_bot_token_decrypted = "BOTTOKEN"
    telegram_chat_ids = ["-1001"]


class _Captured:
    def __init__(self) -> None:
        self.email: list[dict] = []
        self.telegram: list[str] = []

    @property
    def html(self) -> str:
        return self.email[0]["html"]

    @property
    def plain(self) -> str:
        return self.email[0]["plain"]

    @property
    def telegram_text(self) -> str:
        """The delivered message as the reader sees it, tags removed."""
        return "\n".join(rendered(part) for part in self.telegram)

    @property
    def telegram_markup(self) -> str:
        return "\n".join(self.telegram)


@pytest.fixture
def service(db_session):
    svc = AlertService(db_session)
    svc._audit_alert = AsyncMock()
    return svc


@pytest.fixture
def captured(service, monkeypatch):
    sink = _Captured()

    async def _email(*, to, subject, html_body, plain_body=None):
        sink.email.append(
            {"to": to, "subject": subject, "html": html_body, "plain": plain_body}
        )
        return True

    async def _telegram(text, parse_mode="HTML", chat_id=None):
        sink.telegram.append(text)
        return True

    monkeypatch.setattr(service, "_get_settings", AsyncMock(return_value=_Settings()))
    monkeypatch.setattr(service, "_send_email_smtp", _email)
    monkeypatch.setattr(service, "_send_telegram", _telegram)
    return sink


async def add_incident(db, **overrides) -> Breach:
    """One stored incident, with everything a message is expected to say."""
    values = {
        "source_id": "hibp",
        "breach_name": "Collection #1",
        "title": "Collection #1",
        "domain": "example.com",
        "breach_date": date(2020, 5, 6),
        "pwn_count": 1234567,
        "description": "A collection of credentials from many sources.",
        "data_classes": ["Email addresses", "Passwords"],
        "matched_email": "a@example.com",
        "matched_domain": "example.com",
        "attributes": {"is_verified": True, "masked_password": "su********et"},
    }
    values.update(overrides)
    row = Breach(**values)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


def payload_for(row: Breach, *, change_class: str | None = None) -> dict:
    """The event payload a stored incident's delivery carries, in full.

    Deliberately built the way the ingest writes it — every machine key included —
    because the question is whether the *rendering* refuses them.
    """
    payload = {
        "finding_id": str(row.id),
        "source": row.source_id,
        "description": row.description,
        "status": row.status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "breach_name": row.breach_name,
        "title": row.title,
        "domain": row.domain,
        "breach_date": str(row.breach_date),
        "pwn_count": row.pwn_count,
        "data_classes": row.data_classes,
        "matched_email": row.matched_email,
        "matched_domain": row.matched_domain,
        "attributes": row.attributes,
        "exposure_kind": row.exposure_kind,
        "last_seen_at": None,
    }
    if change_class:
        payload["change_class"] = change_class
    return payload


class TestBreachMessageContent:
    @pytest.mark.asyncio
    async def test_the_message_is_the_declared_columns_and_nothing_else(
        self, db_session, service, captured
    ):
        row = await add_incident(db_session)
        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=[payload_for(row)],
            job_id="job-content",
            channel="telegram",
            target="-1001",
        )

        text = captured.telegram_text
        # The facts an operator acts on, each under its own name. The first field of
        # a row is the message's own row header, which is why the class of the change
        # leads it.
        assert "1. New incident" in text
        assert "Incident: Collection #1" in text
        assert "Account: a@example.com" in text
        assert "Vendor domain: example.com" in text
        assert "Breach date: 2020-05-06" in text
        assert "Data classes: Email addresses, Passwords" in text
        assert "Accounts affected: 1234567" in text
        assert "Verification: verified" in text

        # The machine's own bookkeeping never becomes a line of the message.
        assert str(row.id) not in text, "the row's id reached a human"
        for key in _MACHINE_KEYS:
            assert f"{key}:" not in text, f"{key} reached a human"
        # ``data_classes`` is a list a reader is meant to read, not a JSON array.
        assert '["Email addresses"' not in captured.telegram_markup
        assert "is_verified" not in text
        assert "masked_password" not in text
        assert row.description not in text

    @pytest.mark.asyncio
    async def test_the_facts_are_read_from_the_row_at_send_time(
        self, db_session, service, captured
    ):
        """A payload captured at ingest must not outvote the stored incident.

        The same reason phishing reads its candidate: an incident is updated by
        later scans (it grew, it gained a class, it was confirmed), and a message
        sent after those updates has to report what the platform knows now.
        """
        row = await add_incident(db_session)
        stale = payload_for(row)
        stale.update(
            {
                "title": "Collection #1",
                "pwn_count": 1,
                "data_classes": ["Email addresses"],
                "domain": "stale.example",
            }
        )
        # A later scan's facts, written to the row after the event was queued.
        row.pwn_count = 987654321
        row.data_classes = ["Email addresses", "Passwords", "Credit cards"]
        row.domain = "example.com"
        await db_session.commit()

        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=[stale],
            job_id="job-stored",
            channel="email",
            target="soc@example.com",
        )

        plain = captured.plain
        assert "Accounts affected=987654321" in plain
        assert "Credit cards" in plain
        assert "stale.example" not in plain

    @pytest.mark.asyncio
    async def test_the_event_class_leads_a_reported_change(
        self, db_session, service, captured
    ):
        row = await add_incident(db_session)
        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=[payload_for(row, change_class="incident_grew")],
            job_id="job-grew",
            channel="telegram",
            target="-1001",
        )

        text = captured.telegram_text
        assert "1. Incident grew" in text
        # The class is the message's first column, which is what tells a reader why
        # an incident they have already seen is in their inbox again.
        assert text.index("Incident grew") < text.index("Incident: Collection")

    @pytest.mark.asyncio
    async def test_a_marker_is_printed_only_when_the_source_stated_one(
        self, db_session, service, captured
    ):
        spam = await add_incident(
            db_session,
            breach_name="Spam list",
            attributes={"is_verified": False, "is_spam_list": True},
        )
        unverified = await add_incident(
            db_session,
            breach_name="Unverified",
            attributes={"is_verified": False},
        )
        silently = await add_incident(
            db_session,
            breach_name="No flags",
            attributes={},
        )
        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=[payload_for(spam), payload_for(unverified), payload_for(silently)],
            job_id="job-flags",
            channel="telegram",
            target="-1001",
        )

        text = captured.telegram_text
        # A provider flag the source actually set is printed; a row with no flags at
        # all says nothing rather than "unknown", because an empty marker reads as a
        # claim the platform cannot make.
        assert "Verification: spam list" in text
        assert "Verification: unverified" in text
        assert text.count("Verification:") == 2

    @pytest.mark.asyncio
    async def test_incomplete_metadata_is_named_on_the_message(
        self, db_session, service, captured
    ):
        row = await add_incident(
            db_session,
            breach_name="Paste without a date",
            attributes={"metadata_incomplete": True},
        )
        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=[payload_for(row)],
            job_id="job-incomplete",
            channel="telegram",
            target="-1001",
        )

        assert "Verification: metadata incomplete" in captured.telegram_text

    @pytest.mark.asyncio
    async def test_a_paste_says_it_is_a_paste_and_dates_nothing_it_was_not_told(
        self, db_session, service, captured
    ):
        """WI-17: the class leads the row, and the date is not passed off as the paste's.

        A paste has no incident date; what a paste row stores is when this platform first
        saw it. The message has to say both things, or a reader takes the observation
        instant for the day the document was published (F-02).
        """
        row = await add_incident(
            db_session,
            breach_name="paste:abc123",
            title="Paste abc123 — syslog",
            attributes={"paste_id": "abc123", "metadata_incomplete": True},
            exposure_kind="paste",
        )
        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=[payload_for(row)],
            job_id="job-paste",
            channel="telegram",
            target="-1001",
        )

        text = captured.telegram_text
        assert "Exposure: Paste" in text
        assert "not stated (observed" in text
        assert "Verification: metadata incomplete" in text

    @pytest.mark.asyncio
    async def test_a_stealer_log_row_names_the_site_it_is_about(
        self, db_session, service, captured
    ):
        """WI-18: a site in a stealer log is not the same finding as a breached account."""
        row = await add_incident(
            db_session,
            breach_name="stealerlog:netflix.com",
            title="Stealer log — netflix.com",
            domain="netflix.com",
            attributes={"stealer_log_site": "netflix.com", "metadata_incomplete": True},
            exposure_kind="stealer_log",
        )
        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=[payload_for(row)],
            job_id="job-stealer",
            channel="telegram",
            target="-1001",
        )

        text = captured.telegram_text
        assert "Exposure: Stealer log" in text
        assert "netflix.com" in text

    @pytest.mark.asyncio
    async def test_a_breach_of_an_account_keeps_the_shape_it_always_had(
        self, db_session, service, captured
    ):
        """The default class is stated by silence: no new column on every message."""
        row = await add_incident(db_session)
        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=[payload_for(row)],
            job_id="job-breach-shape",
            channel="telegram",
            target="-1001",
        )

        assert "Exposure:" not in captured.telegram_text
        assert "not stated" not in captured.telegram_text

    @pytest.mark.asyncio
    async def test_a_payload_without_a_stored_row_renders_its_own_named_facts(
        self, service, captured
    ):
        """A caller holding only the finding still produces a message.

        This is the path a batch whose incident has since been deleted takes, and
        the one a service-level caller with no row uses. It names the same columns,
        and it still refuses the machine's keys.
        """
        finding = {
            "breach_name": "Payload only",
            "title": "Payload only",
            "domain": "payload.example",
            "breach_date": "2021-01-02",
            "pwn_count": 7,
            "data_classes": ["Email addresses"],
            "matched_email": "b@payload.example",
            "attributes": {"is_fabricated": True},
            "status": "active",
            "source": "somewhere",
            "created_at": "2026-10-01T00:00:00+00:00",
        }
        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=[finding],
            job_id="job-payload",
            channel="telegram",
            target="-1001",
        )

        text = captured.telegram_text
        assert "1. New incident" in text
        assert "Incident: Payload only" in text
        assert "Account: b@payload.example" in text
        assert "Accounts affected: 7" in text
        assert "Verification: fabricated list" in text
        for key in _MACHINE_KEYS:
            assert f"{key}:" not in text, f"{key} reached a human"


class TestBreachMessageSize:
    @pytest.mark.asyncio
    async def test_a_fifty_incident_scan_stays_readable(self, db_session, service, captured):
        """The measurement the audit took: twelve parts and 56.6 KB before.

        Both ceilings are asserted because they fail for different reasons: the
        Telegram parts bound how many messages an operator's client receives, and
        the email size is what a mail server will accept.
        """
        findings = []
        for index in range(50):
            row = await add_incident(
                db_session,
                breach_name=f"Incident {index:03d} Collection of credentials",
                matched_email=f"account{index:03d}@example.com",
                pwn_count=1000000 + index,
            )
            findings.append(payload_for(row, change_class="new_incident"))

        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=findings,
            job_id="job-fifty",
            channel="telegram",
            target="-1001",
        )
        assert len(captured.telegram) <= 6, f"{len(captured.telegram)} Telegram parts"

        captured.telegram.clear()
        captured.email.clear()
        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=findings,
            job_id="job-fifty",
            channel="email",
            target="soc@example.com",
        )
        html_size = len(captured.html.encode("utf-8"))
        assert html_size <= 32 * 1024, f"{html_size} bytes of email"
        # Every incident is still in the message: the fix is fewer *columns*, not
        # fewer findings.
        assert captured.html.count("<tr>") >= 50
        assert "account049@example.com" in captured.html

    @pytest.mark.asyncio
    async def test_the_summary_counts_the_incidents_and_their_vendors(
        self, db_session, service, captured
    ):
        findings = [
            payload_for(await add_incident(db_session, matched_email=f"a{i}@example.com"))
            for i in range(3)
        ]
        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=findings,
            job_id="job-count",
            channel="telegram",
            target="-1001",
        )

        text = captured.telegram_text
        assert "3 new findings" in text
        assert "Breach: Collection #1 × 3" in text
        assert "Domain: example.com × 3" in text
