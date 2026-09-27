from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.alert_service import AlertService


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
