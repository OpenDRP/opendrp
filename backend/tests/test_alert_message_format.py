"""What a delivered alert actually says, in each channel's own format.

A notification is the only part of this platform a human reads, and it is read
*because* something was found. Two failure modes are invisible in a delivery
log — the row still says `sent` — and both are caught here:

* markup the provider refuses. Telegram answers a message it cannot parse
  (unbalanced tags, or a slice that cut `</b>` in half) or one over its length
  limit with `400`, and the queue records that as a *permanent* failure, so an
  alert is lost to a length check rather than to an outage.
* a message that hides the shape of a finding set behind one aggregated number,
  which is indistinguishable from a scan that found nothing.

The regression these tests were written for: the summary was rendered with
backslash escapes left in the literal (`"...SUMMARY</b>\\n\\n"`), so Telegram
delivered one solid line — correct bold markup, no line breaks at all.
"""

from html.parser import HTMLParser
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.alert_service import AlertService

#: The ten findings the live phishing job produced, verbatim: one Shodan `ssl:`
#: search over two keyword domains, deduplicated to ten distinct hosts.
LIVE_PHISHING_BATCH = [
    {"phishing_domain": domain, "matched_asset": "pwned", "detection_source": "shodan_ssl"}
    for domain in (
        "dedicated.co.za",
        "pwned.monster",
        "pwned.gg",
        "amazonaws.com",
        "pwned-u.de",
        "pwned.pw",
        "pingidentity.cloud",
        "pwned.team",
        "fibertel.com.ar",
        "pwned.ru",
    )
]


class _Rendered(HTMLParser):
    """Read a payload the way the provider's parser does: tags, then text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.unbalanced: list[str] = []
        self.parts: list[str] = []

    @property
    def text(self) -> str:
        return "".join(self.parts)

    def handle_starttag(self, tag, attrs):
        self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.unbalanced.append(tag)
            return
        self.stack.pop()

    def handle_data(self, data):
        self.parts.append(data)


def _render(markup: str) -> _Rendered:
    parser = _Rendered()
    parser.feed(markup)
    parser.close()
    return parser


class _Settings:
    """Channel configuration only: the senders themselves are stubbed."""

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
        return self.telegram[0]


@pytest.fixture
def service():
    """An AlertService whose settings and audit sink are both replaceable."""
    svc = AlertService(MagicMock())
    svc._audit_alert = AsyncMock()
    return svc


@pytest.fixture
def captured(service, monkeypatch):
    """Capture both channels for one batch, and time settings for both."""
    sink = _Captured()

    async def _email(*, to, subject, html_body, plain_body=None):
        sink.email.append({"to": to, "subject": subject, "html": html_body, "plain": plain_body})
        return True

    async def _telegram(text, parse_mode="HTML", chat_id=None):
        sink.telegram.append(text)
        return True

    monkeypatch.setattr(service, "_get_settings", AsyncMock(return_value=_Settings()))
    monkeypatch.setattr(service, "_send_email_smtp", _email)
    monkeypatch.setattr(service, "_send_telegram", _telegram)
    return sink


class TestTelegramSummary:
    @pytest.mark.asyncio
    async def test_the_live_batch_arrives_as_readable_lines(self, service, captured):
        await service.send_aggregated_alert_notification(
            threat_type="phishing",
            findings=LIVE_PHISHING_BATCH,
            job_id="6aa001cb-a477-4ffe-87b5-9353dd444b67",
            channel="telegram",
            target="-1001",
        )

        text = captured.telegram_text
        rendered = _render(text)
        assert rendered.unbalanced == []
        assert not rendered.stack, "an unclosed tag is a Telegram 400, not a bold line"

        # The defect this file exists for: escapes left in the literal turn the
        # whole summary into one line, which is what the operator saw.
        assert "\\n" not in text
        assert rendered.text.count("\n") >= len(LIVE_PHISHING_BATCH)

        assert rendered.text.startswith("🚨 OpenDRP PHISHING")
        assert "10 new findings" in rendered.text
        assert "Source: shodan_ssl × 10" in rendered.text
        assert "Matched asset: pwned × 10" in rendered.text

        for index, finding in enumerate(LIVE_PHISHING_BATCH, start=1):
            assert f"{index}. {finding['phishing_domain']}" in rendered.text
            assert f"<code>{finding['phishing_domain']}</code>" in text

    @pytest.mark.asyncio
    async def test_a_long_batch_keeps_its_markup_whole(self, service, captured, monkeypatch):
        from app.core import config as config_module

        monkeypatch.setattr(config_module.settings, "ALERT_MAX_TELEGRAM_MESSAGE_LENGTH", 700)
        findings = [
            {
                "phishing_domain": f"lookalike-{index:03d}.example",
                "matched_asset": "pwned",
                "detection_source": "shodan_ssl",
            }
            for index in range(60)
        ]

        await service.send_aggregated_alert_notification(
            threat_type="phishing",
            findings=findings,
            job_id="job-long",
            channel="telegram",
            target="-1001",
        )

        text = captured.telegram_text
        rendered = _render(text)
        assert rendered.unbalanced == []
        assert not rendered.stack
        assert len(text) <= 700
        assert "lookalike-000.example" in rendered.text
        assert "more findings in OpenDRP" in rendered.text
        assert "lookalike-059.example" not in rendered.text

    @pytest.mark.asyncio
    async def test_an_injected_domain_cannot_close_the_markup(
        self, service, captured
    ):
        await service.send_aggregated_alert_notification(
            threat_type="phishing",
            findings=[
                {
                    "phishing_domain": "</code><b>INJECTED</b>",
                    "matched_asset": '</code><a href="https://evil.example">x</a>',
                    "detection_source": "shodan_ssl",
                }
            ],
            job_id="job-xss",
            channel="telegram",
            target="-1001",
        )

        text = captured.telegram_text
        rendered = _render(text)
        assert rendered.unbalanced == []
        assert not rendered.stack
        # The value stays text: escaped, and therefore inert to the parser.
        assert "&lt;/code&gt;&lt;b&gt;INJECTED&lt;/b&gt;" in text
        assert "<b>INJECTED</b>" not in text
        assert "<a href=\"https://evil.example\">" not in text
        assert "&lt;a href=&quot;https://evil.example&quot;&gt;" in text


class TestEmailSummary:
    @pytest.mark.asyncio
    async def test_every_finding_is_a_table_row_not_a_json_blob(self, service, captured):
        await service.send_aggregated_alert_notification(
            threat_type="phishing",
            findings=LIVE_PHISHING_BATCH,
            job_id="job-email",
            channel="email",
            target="soc@example.com",
        )

        html = captured.html
        assert "Findings" not in html  # the JSON blob the old template dumped
        assert '{"Domain"' not in html and "[{" not in html
        assert html.count("<tbody>") == 1
        assert "10 new findings" in html
        for finding in LIVE_PHISHING_BATCH:
            assert finding["phishing_domain"] in html
        for column in ("Domain", "Matched asset", "Source"):
            assert f"<th>{column}</th>" in html
        assert "shodan_ssl × 10" in html

        # The text alternative carries the same facts, so a text-only client
        # reads the batch rather than a fallback sentence.
        for index, finding in enumerate(LIVE_PHISHING_BATCH, start=1):
            assert f"{index:>3}. Domain={finding['phishing_domain']}" in captured.plain

    @pytest.mark.asyncio
    async def test_a_module_that_declares_nothing_is_still_delivered(self, service, captured):
        """A source's payload is not a schema the message layer may trust."""
        await service.send_aggregated_alert_notification(
            threat_type="module:code_leak",
            findings=[{}, {"title": "repo", "fields": {"secret": "AKIA…"}}],
            channel="email",
            target="soc@example.com",
        )

        html = captured.html
        assert "code_leak" in captured.email[0]["subject"]
        assert "<th>Finding</th>" in html
        assert "<th>secret</th>" in html
        assert "AKIA…" in html


class TestPlatformLink:
    @pytest.mark.asyncio
    async def test_a_loopback_origin_is_not_linked(self, service, captured, monkeypatch):
        from app.core import config as config_module

        monkeypatch.setattr(config_module.settings, "CORS_ORIGINS", ["http://localhost:3000"])

        await service.send_aggregated_alert_notification(
            threat_type="phishing",
            findings=LIVE_PHISHING_BATCH,
            job_id="job-link",
            channel="telegram",
            target="-1001",
        )

        assert "http://localhost:3000" not in captured.telegram_text
        assert "Open in OpenDRP" not in captured.telegram_text

    @pytest.mark.asyncio
    async def test_the_installation_origin_is_linked_with_the_finding_page(
        self, service, captured, monkeypatch
    ):
        from app.core import config as config_module

        monkeypatch.setattr(
            config_module.settings,
            "CORS_ORIGINS",
            ["http://localhost:3000", "https://drp.example.com"],
        )

        await service.send_aggregated_alert_notification(
            threat_type="phishing",
            findings=LIVE_PHISHING_BATCH,
            job_id="job-link",
            channel="email",
            target="soc@example.com",
        )

        assert '<a class="btn" href="https://drp.example.com/phishing">' in captured.html

    @pytest.mark.asyncio
    async def test_a_declared_module_links_to_its_own_page(self, service, captured, monkeypatch):
        from app.core import config as config_module

        monkeypatch.setattr(config_module.settings, "CORS_ORIGINS", ["https://drp.example.com"])

        await service.send_aggregated_alert_notification(
            threat_type="module:code_leak",
            findings=[{"title": "repo"}],
            job_id="job-link",
            channel="telegram",
            target="-1001",
        )

        assert "https://drp.example.com/modules/code_leak" in captured.telegram_text

    @pytest.mark.asyncio
    async def test_a_breach_batch_counts_its_breaches(self, service, captured, monkeypatch):
        from app.core import config as config_module

        monkeypatch.setattr(config_module.settings, "CORS_ORIGINS", ["https://drp.example.com"])

        await service.send_aggregated_alert_notification(
            threat_type="breach",
            findings=[
                {
                    "breach_name": "Collection #1",
                    "matched_email": "a@example.com",
                    "domain": "example.com",
                },
                {
                    "breach_name": "Collection #1",
                    "matched_email": "b@example.com",
                    "domain": "example.com",
                },
            ],
            job_id="job-breach",
            channel="telegram",
            target="-1001",
        )

        text = captured.telegram_text
        assert "OpenDRP CREDENTIAL BREACH" in text
        assert "2 new findings" in text
        rendered = _render(text)
        assert rendered.unbalanced == []
        assert "Breach: Collection #1 × 2" in rendered.text
        assert "https://drp.example.com/breaches" in text
