import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.core.config import settings
from app.core.exceptions import BadRequestException
from app.services.alert_service import (
    AlertDeliveryAmbiguousError,
    AlertDeliveryCancelledError,
    AlertDeliveryTransientError,
    AlertService,
)


class TestTemplateAutoescape:
    def test_the_finding_summary_escapes_every_field_it_renders(self, db_session):
        """One template serves every module, so its escaping has to hold for
        values that came from an untrusted source and from a module's own
        declared field names — which become the *columns* of the table."""
        svc = AlertService(db_session)
        html = svc._render_template(
            "emails/finding_summary.html",
            module_label='<svg onload="alert(1)">',
            title='"><script>alert(2)</script>',
            badge_class="",
            dashboard_url=None,
            job_id="job-1",
            total=2,
            included=1,
            groups=[('<img src=x onerror=alert(3)>', '<b>injected</b> × 1')],
            columns=['<svg onload="alert(4)">.tk', "Data classes"],
            rows=[[
                '<svg onload="alert(4)">.tk',
                '"><b>injected</b>',
            ]],
        )

        for raw in ("<svg onload", "<script>", "<img src=x", "<b>injected</b>"):
            assert raw not in html, f"{raw} reached the email body unescaped"
        assert "&lt;svg onload" in html
        assert "&lt;script&gt;" in html
        assert "&lt;b&gt;injected&lt;/b&gt;" in html


class TestTelegramProviderErrors:
    @pytest.mark.parametrize(
        ("status", "description", "code"),
        [
            (401, "Unauthorized", "invalid_token"),
            (403, "bot was blocked by the user", "bot_blocked"),
            (403, "not enough rights", "insufficient_rights"),
            (400, "chat not found", "chat_not_found"),
            (429, "Too Many Requests", "rate_limited"),
            (503, "temporary outage", "provider_unavailable"),
            (0, "", "provider_unavailable"),
            (400, "bad request", "telegram_error"),
        ],
    )
    def test_provider_error_is_stable_and_safe(self, status, description, code):
        response = MagicMock(status_code=status, text=f'{{"description": "{description}"}}')
        result_code, message = AlertService._telegram_provider_error(response)
        assert result_code == code
        assert "token" not in message.lower() or code == "invalid_token"
        assert "secret" not in message.lower()


class TestMissingCredentialsReturnFalse:
    @pytest.mark.asyncio
    async def test_no_telegram_token_returns_false(self, db_session):
        svc = AlertService(db_session)

        class _FakeS:
            telegram_bot_token_decrypted = None
            smtp_host = None
            smtp_port = 587
            smtp_user = None
            smtp_password_decrypted = None
            smtp_from_email_decrypted = None

        with patch.object(
            AlertService, "_get_settings", new_callable=AsyncMock, return_value=_FakeS()
        ):
            ok = await svc._send_telegram("test", parse_mode="HTML", chat_id="12345")
        assert ok is False

    @pytest.mark.asyncio
    async def test_no_smtp_host_returns_false(self, db_session):
        svc = AlertService(db_session)

        class _FakeS:
            smtp_host = None
            smtp_port = 587
            smtp_user = None
            smtp_password_decrypted = None
            smtp_from_email_decrypted = None

        with patch.object(
            AlertService, "_get_settings", new_callable=AsyncMock, return_value=_FakeS()
        ):
            ok = await svc._send_email_smtp(
                to="ops@example.com", subject="X", html_body="<p>1</p>"
            )
        assert ok is False


class TestTelegramHtmlEscape:
    """Telegram parses HTML, so nothing a source supplied may arrive as markup."""

    @staticmethod
    def _settings() -> object:
        class _FakeS:
            alert_recipient_email_decrypted = None
            telegram_bot_token_decrypted = "BOTTOKEN"
            email_alerts_enabled = False
            telegram_alerts_enabled = True
            telegram_chat_ids = ["-1001"]
            alert_email_user_ids = []
            smtp_host = None
            smtp_port = 587
            smtp_user = None
            smtp_password_decrypted = None
            smtp_from_email_decrypted = None

        return _FakeS()

    @pytest.mark.asyncio
    async def test_the_summary_escapes_the_phishing_payload(self, db_session):
        svc = AlertService(db_session)
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        post_mock = AsyncMock(return_value=fake_resp)

        with patch.object(
            AlertService, "_get_settings", new_callable=AsyncMock, return_value=self._settings()
        ), patch("httpx.AsyncClient.post", post_mock):
            await svc.send_aggregated_alert_notification(
                threat_type="phishing",
                findings=[
                    {
                        "phishing_domain": "</code><b>INJECTED</b><code>",
                        "matched_asset": '"><h1>XSS</h1>',
                    }
                ],
                job_id="job-1",
                channel="telegram",
                target="-1001",
            )

        post_mock.assert_awaited_once()
        payload = post_mock.call_args.kwargs["json"]
        assert payload["parse_mode"] == "HTML"
        text = payload["text"]
        assert "</code><b>INJECTED</b><code>" not in text
        assert "&lt;/code&gt;&lt;b&gt;INJECTED&lt;/b&gt;&lt;code&gt;" in text
        assert "<h1>XSS</h1>" not in text
        assert "&lt;h1&gt;XSS&lt;/h1&gt;" in text

    @pytest.mark.asyncio
    async def test_the_summary_escapes_a_declared_module_title(self, db_session):
        svc = AlertService(db_session)
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        post_mock = AsyncMock(return_value=fake_resp)

        with patch.object(
            AlertService, "_get_settings", new_callable=AsyncMock, return_value=self._settings()
        ), patch("httpx.AsyncClient.post", post_mock):
            await svc.send_aggregated_alert_notification(
                threat_type="module:code_leak",
                findings=[{"title": 'github.com/acme/app"><b>BOLD TITLE</b>'}],
                job_id="job-2",
                channel="telegram",
                target="-1001",
            )

        text = post_mock.call_args.kwargs["json"]["text"]
        assert "<b>BOLD TITLE</b>" not in text
        assert "&lt;b&gt;BOLD TITLE&lt;/b&gt;" in text


def _settings(**overrides) -> SimpleNamespace:
    base = {
        "smtp_host": None,
        "smtp_port": 587,
        "smtp_user": None,
        "smtp_password_decrypted": None,
        "smtp_from_email_decrypted": None,
        "email_alerts_enabled": False,
        "alert_email_user_ids": None,
        "alert_recipient_email_decrypted": None,
        "telegram_bot_token_decrypted": "123:abc",
        "telegram_chat_ids": ["-1001"],
        "telegram_alerts_enabled": False,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class _RaisingClient:
    def __init__(self, error: Exception) -> None:
        self.error = error

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc) -> bool:
        return False

    async def post(self, _url, json=None):
        raise self.error


class TestTelegramTransportClassification:
    @pytest.mark.asyncio
    async def test_a_connect_error_is_transient(self, db_session, monkeypatch):
        svc = AlertService(db_session)
        svc._audit_alert = AsyncMock()
        monkeypatch.setattr(
            httpx, "AsyncClient", lambda **kwargs: _RaisingClient(httpx.ConnectError("no route"))
        )
        with patch.object(
            AlertService, "_get_settings", new_callable=AsyncMock, return_value=_settings()
        ):
            with pytest.raises(AlertDeliveryTransientError, match="telegram connection unavailable"):
                await svc._send_telegram("hi", chat_id="-1001")

    @pytest.mark.asyncio
    async def test_a_lost_response_is_ambiguous(self, db_session, monkeypatch):
        svc = AlertService(db_session)
        svc._audit_alert = AsyncMock()
        monkeypatch.setattr(
            httpx, "AsyncClient", lambda **kwargs: _RaisingClient(asyncio.TimeoutError())
        )
        with patch.object(
            AlertService, "_get_settings", new_callable=AsyncMock, return_value=_settings()
        ):
            with pytest.raises(AlertDeliveryAmbiguousError, match="acceptance unknown"):
                await svc._send_telegram("hi", chat_id="-1001")


class TestChatResult:
    def test_a_200_without_a_json_body_is_still_a_valid_chat(self):
        result = AlertService._telegram_chat_result(
            "-1", SimpleNamespace(status_code=200, text="<html>not json</html>")
        )
        assert result == {
            "chat_id": "-1",
            "ok": True,
            "chat_type": None,
            "username": None,
            "title": None,
        }

    def test_a_non_200_is_reported_with_its_provider_code(self):
        result = AlertService._telegram_chat_result(
            "-1",
            SimpleNamespace(
                status_code=403, text='{"description": "bot was blocked by the user"}'
            ),
        )
        assert result["ok"] is False
        assert result["error_code"] == "bot_blocked"


class TestChatValidation:
    @pytest.mark.asyncio
    async def test_an_unusable_token_is_refused_before_the_request(self, db_session):
        svc = AlertService(db_session)
        with pytest.raises(BadRequestException, match="unusable"):
            await svc.validate_telegram_chats(
                _settings(telegram_bot_token_decrypted="123456789:@evil.example/x")
            )

    @pytest.mark.asyncio
    async def test_a_spent_deadline_names_the_reason(self, db_session, monkeypatch):
        svc = AlertService(db_session)
        svc._audit_alert = AsyncMock()
        monkeypatch.setattr(settings, "ALERT_HEALTH_CHECK_TIMEOUT_SECONDS", 0.0)

        result = await svc.validate_telegram_chats(
            _settings(telegram_chat_ids=["-1", "-2"])
        )

        assert result["valid"] == 0
        assert {item["error_code"] for item in result["results"]} == {"deadline_exceeded"}

    @pytest.mark.asyncio
    async def test_a_transport_error_is_reported_per_chat(self, db_session, monkeypatch):
        svc = AlertService(db_session)
        svc._audit_alert = AsyncMock()
        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _RaisingClient(httpx.ConnectError("x")))

        class _Getter(_RaisingClient):
            async def get(self, _url, params=None):
                raise self.error

        monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _Getter(httpx.ConnectError("x")))

        result = await svc.validate_telegram_chats(_settings())

        assert result["results"][0]["error_code"] == "provider_unavailable"


class TestTestSendEdges:
    @pytest.mark.asyncio
    async def test_a_chat_that_failed_validation_is_passed_through(self, db_session):
        svc = AlertService(db_session)
        svc._audit_alert = AsyncMock()
        svc.validate_telegram_chats = AsyncMock(
            return_value={
                "valid": 0,
                "total": 1,
                "results": [
                    {
                        "chat_id": "-1",
                        "ok": False,
                        "error_code": "chat_not_found",
                        "error": "Telegram cannot find this chat.",
                    }
                ],
            }
        )

        result = await svc.send_test_telegram(_settings())

        assert result["sent"] == 0
        assert result["results"][0]["error_code"] == "chat_not_found"
        assert result["validation_failed"] == 1

    @pytest.mark.asyncio
    async def test_a_spent_deadline_is_reported_rather_than_raised(
        self, db_session, monkeypatch
    ):
        svc = AlertService(db_session)
        svc._audit_alert = AsyncMock()
        svc.validate_telegram_chats = AsyncMock(
            return_value={
                "valid": 1,
                "total": 1,
                "results": [{"chat_id": "-1", "ok": True}],
            }
        )
        monkeypatch.setattr(settings, "ALERT_HEALTH_CHECK_TIMEOUT_SECONDS", 0.0)

        result = await svc.send_test_telegram(_settings())

        assert result["results"][0]["error_code"] == "deadline_exceeded"


class TestNotificationBuild:
    def test_a_finding_on_a_known_origin_links_to_its_own_page(self, db_session, monkeypatch):
        svc = AlertService(db_session)
        monkeypatch.setattr(settings, "CORS_ORIGINS", ["https://drp.example.com"])
        finding_id = "11111111-1111-1111-1111-111111111111"
        item = {"finding_id": finding_id, "Current value": "evil.example"}

        notification = svc._build_notification(
            threat_type="phishing",
            label="Phishing",
            subject="s",
            findings=[item],
            bounded=[item],
            job_id="job-1",
            link="https://drp.example.com/phishing",
        )

        assert notification.rows[0]["Finding link"] == (
            f"https://drp.example.com/phishing?finding_id={finding_id}"
        )
        assert notification.rows[0]["Current value"] == "evil.example"

    def test_no_usable_origin_means_no_link(self, db_session, monkeypatch):
        svc = AlertService(db_session)
        monkeypatch.setattr(settings, "CORS_ORIGINS", ["not-a-url", "http://127.0.0.1:3000"])

        assert svc._platform_link("phishing") is None


class TestAggregatedDeliveryEdges:
    @pytest.mark.asyncio
    async def test_no_enabled_destination_is_cancelled(self):
        svc = AlertService(AsyncMock())
        svc._audit_alert = AsyncMock()
        with patch.object(
            AlertService, "_get_settings", new_callable=AsyncMock, return_value=_settings()
        ):
            with pytest.raises(AlertDeliveryCancelledError, match="No enabled destination"):
                await svc.send_aggregated_alert_notification(
                    threat_type="phishing",
                    findings=[{"phishing_domain": "evil.example"}],
                    job_id="job-1",
                    channel="email",
                )

    @pytest.mark.asyncio
    async def test_the_subject_names_the_worst_severity(self):
        svc = AlertService(AsyncMock())
        svc._audit_alert = AsyncMock()
        subjects: list[str] = []

        async def _email(*, to, subject, html_body, plain_body=None):
            subjects.append(subject)
            return True

        svc._send_email_smtp = _email
        with patch.object(
            AlertService,
            "_get_settings",
            new_callable=AsyncMock,
            return_value=_settings(
                email_alerts_enabled=True,
                alert_recipient_email_decrypted="soc@example.com",
            ),
        ):
            await svc.send_aggregated_alert_notification(
                threat_type="phishing",
                findings=[
                    {"phishing_domain": "evil.example", "severity": "high"},
                    {"phishing_domain": "low.example", "severity": "info"},
                ],
                job_id="job-1",
                channel="email",
            )

        assert subjects == ["[OpenDRP Alert] Phishing: 2 new findings (high)"]

    @pytest.mark.asyncio
    async def test_a_breach_subject_names_the_change_class(self):
        svc = AlertService(AsyncMock())
        svc._audit_alert = AsyncMock()
        subjects: list[str] = []

        async def _email(*, to, subject, html_body, plain_body=None):
            subjects.append(subject)
            return True

        svc._send_email_smtp = _email
        with patch.object(
            AlertService,
            "_get_settings",
            new_callable=AsyncMock,
            return_value=_settings(
                email_alerts_enabled=True,
                alert_recipient_email_decrypted="soc@example.com",
            ),
        ):
            await svc.send_aggregated_alert_notification(
                threat_type="breach",
                findings=[
                    {"matched_email": "a@example.com", "breach_name": "X", "change_class": "incident_grew"},
                    {"matched_email": "b@example.com", "breach_name": "X", "change_class": "incident_grew"},
                ],
                job_id="job-1",
                channel="email",
            )

        assert subjects == [
            "[OpenDRP Alert] Credential breach: 2 new findings (Incident grew)"
        ]

    @pytest.mark.asyncio
    async def test_a_provider_that_declines_is_a_failure(self):
        svc = AlertService(AsyncMock())
        svc._audit_alert = AsyncMock()

        async def _email(**_kwargs):
            return False

        svc._send_email_smtp = _email
        with patch.object(
            AlertService,
            "_get_settings",
            new_callable=AsyncMock,
            return_value=_settings(
                email_alerts_enabled=True,
                alert_recipient_email_decrypted="soc@example.com",
            ),
        ):
            with pytest.raises(RuntimeError, match="did not accept"):
                await svc.send_aggregated_alert_notification(
                    threat_type="phishing",
                    findings=[{"phishing_domain": "evil.example"}],
                    job_id="job-1",
                    channel="email",
                )

        assert svc._audit_alert.await_args.kwargs["action"] == "alert.dispatch.failed"
