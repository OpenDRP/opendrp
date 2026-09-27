"""Alert delivery paths.

What matters here is not that a message is composed, but how a *failure* is
handled, because these run inside ingestion:

* a missing configuration returns False rather than raising, so a finding is
  never lost because an operator has not filled in SMTP yet;
* one broken recipient must not stop the others — every send is individually
  guarded and the aggregate outcome decides what the audit trail says;
* the audit record distinguishes "nothing was delivered" from "something was",
  which is what an operator needs when alerts silently stop arriving.

The generic ``module:`` branch is covered too: it is the reason a module
declared at runtime can alert without a template of its own.
"""

from __future__ import annotations

import smtplib
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.core.exceptions import BadRequestException
from app.services.alert_service import AlertService


def _settings(**overrides) -> SimpleNamespace:
    base = {
        "smtp_host": "smtp.example",
        "smtp_port": 587,
        "smtp_user": None,
        "smtp_password_decrypted": None,
        "smtp_from_email_decrypted": "alerts@example.com",
        "email_alerts_enabled": False,
        "alert_email_user_ids": None,
        "alert_recipient_email_decrypted": None,
        "telegram_bot_token_decrypted": None,
        "telegram_chat_ids": None,
        "telegram_alerts_enabled": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class _RecordingSmtp:
    instances: list["_RecordingSmtp"] = []

    def __init__(self, host, port, timeout=None, context=None) -> None:
        self.host = host
        self.port = port
        self.context = context
        self.calls: list[str] = []
        self.messages: list = []
        self.logged_in: tuple | None = None
        _RecordingSmtp.instances.append(self)

    def __enter__(self) -> "_RecordingSmtp":
        return self

    def __exit__(self, *_exc) -> bool:
        return False

    def ehlo(self) -> None:
        self.calls.append("ehlo")

    def starttls(self, context=None) -> None:
        self.calls.append("starttls")

    def login(self, user, password) -> None:
        self.logged_in = (user, password)

    def send_message(self, message) -> None:
        self.messages.append(message)


@pytest.fixture
def service():
    """An AlertService whose settings and audit sink are both replaceable."""
    svc = AlertService(MagicMock())
    svc._audit_alert = AsyncMock()
    return svc


@pytest.fixture
def smtp_factory(monkeypatch):
    _RecordingSmtp.instances = []
    monkeypatch.setattr(smtplib, "SMTP", _RecordingSmtp)
    monkeypatch.setattr(smtplib, "SMTP_SSL", _RecordingSmtp)
    return _RecordingSmtp


class TestEmailDelivery:
    @pytest.mark.asyncio
    async def test_without_a_host_nothing_is_sent_and_nothing_raises(self, service, monkeypatch):
        monkeypatch.setattr(service, "_get_settings", AsyncMock(return_value=_settings(smtp_host=None)))

        assert await service._send_email_smtp(to="a@b.example", subject="s", html_body="<p>x</p>") is False
        service._audit_alert.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_starttls_path_logs_in_and_sends_both_bodies(self, service, smtp_factory, monkeypatch):
        monkeypatch.setattr(
            service,
            "_get_settings",
            AsyncMock(
                return_value=_settings(smtp_user="user", smtp_password_decrypted="secret")
            ),
        )

        sent = await service._send_email_smtp(
            to="analyst@example.com",
            subject="Subject line",
            html_body="<p>html</p>",
            plain_body="plain",
        )

        assert sent is True
        server = smtp_factory.instances[0]
        assert server.calls == ["ehlo", "starttls", "ehlo"]
        assert server.logged_in == ("user", "secret")
        message = server.messages[0]
        assert message["To"] == "analyst@example.com"
        assert message["Subject"] == "Subject line"
        assert message["From"] == "alerts@example.com"
        # Both alternatives are attached, so a text-only client still reads it.
        payload = message.get_payload()
        assert "plain" in payload[0].get_content()
        assert "html" in payload[1].get_content()
        service._audit_alert.assert_awaited_once()
        assert service._audit_alert.await_args.kwargs["channel"] == "email"

    @pytest.mark.asyncio
    async def test_port_465_connects_with_tls_and_does_not_negotiate_starttls(
        self, service, smtp_factory, monkeypatch
    ):
        monkeypatch.setattr(service, "_get_settings", AsyncMock(return_value=_settings(smtp_port=465)))

        assert await service._send_email_smtp(to="a@b.example", subject="s", html_body="<p>x</p>")

        server = smtp_factory.instances[0]
        assert server.port == 465
        assert server.context is not None
        assert server.calls == []

    @pytest.mark.asyncio
    async def test_the_from_address_falls_back_to_the_login_then_to_a_local_default(
        self, service, smtp_factory, monkeypatch
    ):
        monkeypatch.setattr(
            service,
            "_get_settings",
            AsyncMock(
                return_value=_settings(smtp_from_email_decrypted=None, smtp_user="login@example.com")
            ),
        )
        await service._send_email_smtp(to="a@b.example", subject="s", html_body="<p>x</p>")
        assert smtp_factory.instances[0].messages[0]["From"] == "login@example.com"

        smtp_factory.instances = []
        monkeypatch.setattr(
            service,
            "_get_settings",
            AsyncMock(return_value=_settings(smtp_from_email_decrypted=None, smtp_user=None)),
        )
        await service._send_email_smtp(to="a@b.example", subject="s", html_body="<p>x</p>")
        assert smtp_factory.instances[0].messages[0]["From"] == "opendrp@localhost"


class _FakeTelegramClient:
    def __init__(self, *, status_code=200, text="", error: Exception | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self.error = error
        self.posts: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc) -> bool:
        return False

    async def get(self, url, params=None):
        return SimpleNamespace(status_code=200, text='{"ok": true, "result": {"type": "private"}}')

    async def post(self, url, json=None):
        self.posts.append((url, json or {}))
        if self.error is not None:
            raise self.error
        return SimpleNamespace(status_code=self.status_code, text=self.text)


class TestTelegramDelivery:
    @pytest.mark.asyncio
    async def test_without_a_token_or_chat_nothing_is_sent(self, service, monkeypatch):
        monkeypatch.setattr(service, "_get_settings", AsyncMock(return_value=_settings()))

        assert await service._send_telegram("hi") is False

    @pytest.mark.asyncio
    async def test_a_successful_send_is_audited(self, service, monkeypatch):
        client = _FakeTelegramClient()
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)
        monkeypatch.setattr(
            service,
            "_get_settings",
            AsyncMock(return_value=_settings(telegram_bot_token_decrypted="tok")),
        )

        assert await service._send_telegram("<b>hi</b>", chat_id="-100") is True

        url, payload = client.posts[0]
        assert url == "https://api.telegram.org/bottok/sendMessage"
        assert payload["chat_id"] == "-100"
        assert payload["parse_mode"] == "HTML"
        service._audit_alert.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_the_recipient_is_the_one_the_caller_resolved(self, service, monkeypatch):
        """Exactly one destination, taken from the argument.

        There is no second place a chat ID can come from: the send path used to
        fall back to a single legacy settings column when no ``chat_id`` was
        passed, which meant a chat that ``_resolve_telegram_chats()`` had
        deliberately skipped could still receive an alert.
        """
        client = _FakeTelegramClient()
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)
        monkeypatch.setattr(
            service,
            "_get_settings",
            AsyncMock(return_value=_settings(telegram_bot_token_decrypted="tok")),
        )

        await service._send_telegram("hi", chat_id="42")

        assert client.posts[0][1]["chat_id"] == "42"

    @pytest.mark.asyncio
    async def test_a_non_200_is_an_error_so_tenacity_can_retry_it(self, service, monkeypatch):
        client = _FakeTelegramClient(status_code=502, text="bad gateway")
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)
        monkeypatch.setattr(
            service,
            "_get_settings",
            AsyncMock(
                return_value=_settings(telegram_bot_token_decrypted="tok")
            ),
        )

        # Call the undecorated coroutine: the retry wrapper would sleep between
        # attempts, and the point here is the raised error, not the backoff.
        with pytest.raises(RuntimeError, match="TG 502"):
            await AlertService._send_telegram.__wrapped__(service, "hi", chat_id="-100")

        service._audit_alert.assert_not_awaited()


class TestTestTelegramMessage:
    @pytest.mark.asyncio
    async def test_without_a_token_it_is_refused(self, service):
        with pytest.raises(BadRequestException, match="not configured"):
            await service.send_test_telegram(_settings())

    @pytest.mark.asyncio
    async def test_without_any_chat_it_is_refused(self, service):
        with pytest.raises(BadRequestException, match="No Telegram chat IDs"):
            await service.send_test_telegram(_settings(telegram_bot_token_decrypted="tok"))

    @pytest.mark.asyncio
    async def test_it_sends_to_every_configured_chat_even_when_the_toggle_is_off(
        self, service, monkeypatch
    ):
        client = _FakeTelegramClient()
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)

        result = await service.send_test_telegram(
            _settings(
                telegram_bot_token_decrypted="tok",
                telegram_chat_ids=["1", "2"],
                telegram_alerts_enabled=False,
            )
        )

        assert result["sent"] == 2
        assert result["total"] == 2
        assert result["validated"] == 2
        assert [p[1]["chat_id"] for p in client.posts] == ["1", "2"]
        assert service._audit_alert.await_args.kwargs["action"] == "alert.test_sent"

    @pytest.mark.asyncio
    async def test_a_rejected_chat_is_reported_with_the_provider_error(self, service, monkeypatch):
        client = _FakeTelegramClient(status_code=403, text="bot was blocked")
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)

        result = await service.send_test_telegram(
            _settings(telegram_bot_token_decrypted="tok", telegram_chat_ids=["1"])
        )

        assert result["sent"] == 0
        assert result["results"][0]["error_code"] == "telegram_error"
        assert "Verify the chat ID" in result["results"][0]["error"]
        # Nothing arrived, so the audit must not claim a successful test.
        assert service._audit_alert.await_args.kwargs["action"] == "alert.dispatch.failed"

    @pytest.mark.asyncio
    async def test_a_transport_error_is_captured_per_chat_rather_than_raised(
        self, service, monkeypatch
    ):
        client = _FakeTelegramClient(error=httpx.ConnectError("no route"))
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)

        result = await service.send_test_telegram(
            _settings(telegram_bot_token_decrypted="tok", telegram_chat_ids=["1"])
        )

        assert result["results"][0]["ok"] is False
        assert result["results"][0]["error_code"] == "provider_unavailable"
        assert "temporarily unavailable" in result["results"][0]["error"]


class TestDeclaredModuleAlert:
    """A module declared at runtime alerts without a template of its own.

    The queue delivers one bounded summary per channel, built from the fields the
    module itself declared — so onboarding a source adds no rendering code.
    """

    @pytest.mark.asyncio
    async def test_the_summary_names_the_module_and_carries_its_findings(
        self, service, monkeypatch
    ):
        monkeypatch.setattr(
            service,
            "_get_settings",
            AsyncMock(
                return_value=_settings(
                    email_alerts_enabled=True,
                    alert_recipient_email_decrypted="soc@example.com",
                )
            ),
        )
        sent_email: list[dict] = []

        async def _capture_email(*, to, subject, html_body, plain_body=None):
            sent_email.append({"to": to, "subject": subject, "html": html_body})
            return True

        monkeypatch.setattr(service, "_send_email_smtp", _capture_email)

        result = await service.send_aggregated_alert_notification(
            threat_type="module:code_leak",
            findings=[
                {
                    "title": "github.com/acme/app",
                    "matched_asset": "acme.com",
                    "fields": {"repository": "github.com/acme/app"},
                }
            ],
            job_id="job-7",
            channel="email",
            target="soc@example.com",
        )

        assert result["sent"] == 1
        assert sent_email[0]["to"] == "soc@example.com"
        # The module is named by its own registry id, with no per-module copy in
        # the core: this is what a source onboarded as data gets.
        assert "code_leak" in sent_email[0]["subject"]
        assert "1 new finding" in sent_email[0]["subject"]
        assert "github.com/acme/app" in sent_email[0]["html"]
        assert service._audit_alert.await_args.kwargs["channel"] == "email"

    @pytest.mark.asyncio
    async def test_a_total_failure_is_audited_as_such(self, service, monkeypatch):
        monkeypatch.setattr(
            service,
            "_get_settings",
            AsyncMock(
                return_value=_settings(
                    email_alerts_enabled=True, alert_recipient_email_decrypted="soc@example.com"
                )
            ),
        )

        async def _boom(*, to, subject, html_body, plain_body=None):
            raise RuntimeError("smtp exploded")

        monkeypatch.setattr(service, "_send_email_smtp", _boom)

        with pytest.raises(RuntimeError):
            await service.send_aggregated_alert_notification(
                threat_type="module:code_leak",
                findings=[{"title": "x"}],
                channel="email",
                target="soc@example.com",
            )

        assert service._audit_alert.await_args.kwargs["action"] == "alert.dispatch.failed"
        assert service._audit_alert.await_args.kwargs["channel"] == "email"

    @pytest.mark.asyncio
    async def test_a_finding_missing_declared_fields_still_produces_a_message(
        self, service, monkeypatch
    ):
        """A source's payload is not a schema the message layer may trust."""
        monkeypatch.setattr(
            service,
            "_get_settings",
            AsyncMock(
                return_value=_settings(
                    telegram_alerts_enabled=True,
                    telegram_bot_token_decrypted="tok",
                    telegram_chat_ids=["-100"],
                )
            ),
        )
        monkeypatch.setattr(service, "_send_telegram", AsyncMock(return_value=True))

        await service.send_aggregated_alert_notification(
            threat_type="module:code_leak",
            findings=[{}],
            channel="telegram",
            target="-100",
        )

        assert "CODE_LEAK" in service._send_telegram.await_args.args[0]


class TestOperatorMessage:
    """Messages about the platform itself, not about a finding.

    The caller is the nightly integrity check, and its contract is the opposite
    of an alert dispatch: it *records* what happened, so a channel that is down
    must not raise and must not hide the channel that worked.
    """

    @pytest.fixture
    def channels(self, service, monkeypatch):
        """Both channels configured and both sends replaceable."""
        monkeypatch.setattr(
            service,
            "_get_settings",
            AsyncMock(
                return_value=_settings(
                    email_alerts_enabled=True,
                    telegram_alerts_enabled=True,
                    telegram_bot_token_decrypted="tok",
                )
            ),
        )
        monkeypatch.setattr(
            service, "_resolve_email_recipients", AsyncMock(return_value=["soc@example.com"])
        )
        monkeypatch.setattr(
            service, "_resolve_telegram_chats", MagicMock(return_value=["-100"])
        )
        email = AsyncMock(return_value=True)
        telegram = AsyncMock(return_value=True)
        monkeypatch.setattr(service, "_send_email_smtp", email)
        monkeypatch.setattr(service, "_send_telegram", telegram)
        return service, email, telegram

    @pytest.mark.asyncio
    async def test_every_configured_channel_is_used_and_reported(self, channels):
        service, email, telegram = channels

        result = await service.send_operator_message(
            subject="[OpenDRP] Audit chain verification failed",
            html_body="<p>body</p>",
            plain_body="checked=10 broken=4",
        )

        assert email.await_args.kwargs["to"] == "soc@example.com"
        assert email.await_args.kwargs["subject"] == "[OpenDRP] Audit chain verification failed"
        assert telegram.await_args.kwargs["chat_id"] == "-100"
        assert result == {
            "email_sent": True,
            "telegram_sent": True,
            "email_recipients": 1,
            "telegram_chats": 1,
            "errors": [],
        }

    @pytest.mark.asyncio
    async def test_a_broken_channel_does_not_stop_the_other_one(self, channels):
        service, email, telegram = channels

        async def _boom(*, to, subject, html_body, plain_body=None):
            raise RuntimeError("smtp exploded")

        service._send_email_smtp = _boom

        result = await service.send_operator_message(
            subject="[OpenDRP] Audit chain verification failed", html_body="<p>body</p>"
        )

        # The failure is named by type only: the exception's text can carry the
        # SMTP host and credentials, and this result is returned to a task that
        # writes it into the audit trail.
        assert result["errors"] == ["email:RuntimeError"]
        assert result["email_sent"] is False
        assert result["telegram_sent"] is True

    @pytest.mark.asyncio
    async def test_a_broken_telegram_does_not_mark_the_email_as_failed(self, channels):
        """The same guard in the other direction, since each channel is its own."""
        service, _, _telegram = channels

        async def _boom(_text, chat_id=None):
            raise RuntimeError("telegram exploded")

        service._send_telegram = _boom

        result = await service.send_operator_message(subject="s", html_body="<p>b</p>")

        assert result["errors"] == ["telegram:RuntimeError"]
        assert result["telegram_sent"] is False
        assert result["email_sent"] is True

    @pytest.mark.asyncio
    async def test_a_disabled_channel_is_not_resolved_at_all(self, service, monkeypatch):
        monkeypatch.setattr(
            service, "_get_settings", AsyncMock(return_value=_settings())
        )
        resolver = AsyncMock(return_value=["soc@example.com"])
        monkeypatch.setattr(service, "_resolve_email_recipients", resolver)
        monkeypatch.setattr(service, "_send_email_smtp", AsyncMock(return_value=True))

        result = await service.send_operator_message(subject="s", html_body="<p>b</p>")

        resolver.assert_not_awaited()
        assert result["email_recipients"] == 0
        assert result["email_sent"] is False

    @pytest.mark.asyncio
    async def test_the_telegram_copy_escapes_the_subject_and_falls_back_to_it(
        self, channels
    ):
        service, _, telegram = channels

        await service.send_operator_message(
            subject="chain <script>alert(1)</script> broken", html_body="<p>b</p>"
        )

        text = telegram.await_args.args[0]
        assert "<script>" not in text
        assert "&lt;script&gt;" in text
        # No plain body: the subject is the fallback, and an operator reading the
        # Telegram channel must still learn what happened.
        assert "broken" in text
