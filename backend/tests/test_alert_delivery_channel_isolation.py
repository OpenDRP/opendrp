from unittest.mock import AsyncMock

import pytest

from app.services.alert_service import AlertService


@pytest.mark.asyncio
async def test_channel_delivery_does_not_report_success_for_an_unavailable_channel(db_session, monkeypatch):
    service = AlertService(db_session)
    service._audit_alert = AsyncMock()
    monkeypatch.setattr(
        service,
        "_get_settings",
        AsyncMock(
            return_value=type(
                "Settings",
                (),
                {
                    "email_alerts_enabled": True,
                    "telegram_alerts_enabled": True,
                    "alert_email_user_ids": [],
                    "alert_recipient_email_decrypted": "soc@example.com",
                    "telegram_bot_token_decrypted": "token",
                    "telegram_chat_ids": [],
                    "smtp_host": "smtp.example.com",
                    "smtp_port": 587,
                },
            )()
        ),
    )
    email = AsyncMock(return_value=True)
    telegram = AsyncMock(return_value=False)
    monkeypatch.setattr(service, "_send_email_smtp", email)
    monkeypatch.setattr(service, "_send_telegram", telegram)

    # The queue claims these as two rows. The email row succeeds without
    # touching Telegram; the Telegram row fails and is therefore retried.
    settings_module = __import__("app.core.config", fromlist=["settings"])
    monkeypatch.setattr(settings_module.settings, "ALERT_MAX_FINDINGS_PER_MESSAGE", 50)
    monkeypatch.setattr(settings_module.settings, "ALERT_MAX_TELEGRAM_MESSAGE_LENGTH", 3800)
    result = await service.send_aggregated_alert_notification(
        threat_type="phishing",
        findings=[{"phishing_domain": "evil.example"}],
        job_id="job-1",
        channel="email",
        target="soc@example.com",
    )
    assert result["sent"] == 1
    email.assert_awaited_once()
    telegram.assert_not_awaited()

    with pytest.raises(RuntimeError, match="Telegram provider"):
        await service.send_aggregated_alert_notification(
            threat_type="phishing",
            findings=[{"phishing_domain": "evil.example"}],
            job_id="job-1",
            channel="telegram",
            target="-100",
        )
    telegram.assert_awaited_once()
