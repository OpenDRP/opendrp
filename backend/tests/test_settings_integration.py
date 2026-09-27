from typing import AsyncGenerator
from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.exceptions import BadRequestException
from app.main import app
from app.services.settings_service import SettingsService


BASE = "http://test"


@pytest.fixture()
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    from app.api.deps import get_db

    async def _get_db_override():
        yield db_session

    app.dependency_overrides[get_db] = _get_db_override
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url=BASE
        ) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_db, None)


class TestSettingsRouter:
    @pytest.mark.asyncio
    async def test_get_settings_admin_ok_returns_encrypted_decrypted_hybrid(
        self, client, auth_headers_admin, db_session
    ):
        s = await SettingsService(db_session).get_singleton()
        s.smtp_host = "smtp.example.com"
        db_session.add(s)
        await db_session.commit()
        await db_session.refresh(s)

        r = await client.get("/api/v1/settings", headers=auth_headers_admin)
        assert r.status_code == 200, r.text
        body = r.json()
        assert "shodan_api_key" not in body
        assert "hibp_api_key" not in body
        assert body["smtp_host"] == "smtp.example.com"

    @pytest.mark.asyncio
    async def test_update_settings_decrypt_round_trip(
        self, client, auth_headers_admin, db_session
    ):
        await SettingsService(db_session).get_singleton()
        tg_token = "1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ1234567890"
        smtp_pw = "my-smtp-PW1-very-LONG-secret!!"
        payload = {
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_from_email": "ops@example.com",
            "alert_recipient_email": "soc@example.com",
            "smtp_password": smtp_pw,
            "telegram_bot_token": tg_token,
            "smtp_user": "ops@example.com",
        }
        r = await client.put(
            "/api/v1/settings", json=payload, headers=auth_headers_admin
        )
        assert r.status_code == 200, r.text
        response = r.json()
        # Operational addresses are encrypted at rest and masked on the API
        # response, just like SMTP and Telegram secrets.
        assert response["smtp_from_email"] != "ops@example.com"
        assert "*" in response["smtp_from_email"]
        assert response["alert_recipient_email"] != "soc@example.com"
        assert "*" in response["alert_recipient_email"]
        updated = await SettingsService(db_session).get_singleton()
        assert updated.telegram_bot_token_decrypted == tg_token
        assert updated.smtp_password_decrypted == smtp_pw
        assert updated.smtp_from_email_decrypted == "ops@example.com"
        assert updated.alert_recipient_email_decrypted == "soc@example.com"

    @pytest.mark.asyncio
    async def test_the_removed_legacy_chat_field_is_rejected(
        self, client, auth_headers_admin, db_session
    ):
        """A pre-0.1.0 settings payload fails loudly instead of being dropped.

        The single-chat field is gone from the schema, and the settings model
        forbids unknown keys. Reporting "saved" while the chat ID went nowhere is
        the alternative, and it is the one that reaches production.
        """
        await SettingsService(db_session).get_singleton()
        r = await client.put(
            "/api/v1/settings",
            json={"telegram_chat_id": "-100999888777"},
            headers=auth_headers_admin,
        )
        assert r.status_code == 422, r.text

    @pytest.mark.asyncio
    async def test_update_settings_with_masked_secrets_preserves_existing(
        self, client, auth_headers_admin, db_session
    ):
        s = await SettingsService(db_session).get_singleton()
        db_session.add(s)
        await db_session.commit()

        payload = {
            "telegram_bot_token": "",
        }
        r = await client.put(
            "/api/v1/settings", json=payload, headers=auth_headers_admin
        )
        assert r.status_code == 200, r.text
        updated = await SettingsService(db_session).get_singleton()
        assert updated.telegram_bot_token_decrypted is None

    @pytest.mark.asyncio
    async def test_masked_addresses_can_be_resubmitted_without_erasing_them(
        self, client, auth_headers_admin, db_session
    ):
        s = await SettingsService(db_session).get_singleton()
        s.smtp_from_email_decrypted = "alerts@example.com"
        s.alert_recipient_email_decrypted = "soc@example.com"
        await db_session.commit()

        first = await client.get("/api/v1/settings", headers=auth_headers_admin)
        assert first.status_code == 200
        masked = first.json()
        response = await client.put(
            "/api/v1/settings",
            json={
                "smtp_from_email": masked["smtp_from_email"],
                "alert_recipient_email": masked["alert_recipient_email"],
                "smtp_host": "smtp.example.com",
            },
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text
        refreshed = await SettingsService(db_session).get_singleton()
        assert refreshed.smtp_from_email_decrypted == "alerts@example.com"
        assert refreshed.alert_recipient_email_decrypted == "soc@example.com"

    @pytest.mark.asyncio
    async def test_update_settings_null_port_keeps_value_not_500(
        self, client, auth_headers_admin, db_session
    ):
        s = await SettingsService(db_session).get_singleton()
        s.smtp_port = 2525
        s.smtp_host = "smtp.example.com"
        await db_session.commit()

        for bad in (None, ""):
            r = await client.put(
                "/api/v1/settings", json={"smtp_port": bad}, headers=auth_headers_admin
            )
            assert r.status_code == 200, (bad, r.text)
            assert r.json()["smtp_port"] == 2525

    @pytest.mark.asyncio
    async def test_update_settings_clears_smtp_from_email(
        self, client, auth_headers_admin, db_session
    ):
        s = await SettingsService(db_session).get_singleton()
        s.smtp_from_email_decrypted = "alerts@example.com"
        await db_session.commit()

        r = await client.put(
            "/api/v1/settings",
            json={"smtp_from_email": ""},
            headers=auth_headers_admin,
        )
        assert r.status_code == 200, r.text
        assert r.json()["smtp_from_email"] is None
        refreshed = await SettingsService(db_session).get_singleton()
        assert refreshed.smtp_from_email_decrypted is None

    @pytest.mark.asyncio
    async def test_viewer_settings_forbidden_403(
        self, client, auth_headers_viewer
    ):
        r = await client.get("/api/v1/settings", headers=auth_headers_viewer)
        assert r.status_code == 403


class TestSettingsServiceSmtpBranches:
    @pytest.mark.asyncio
    async def test_send_test_email_raises_when_no_recipient(self, db_session):
        svc = SettingsService(db_session)
        s = await svc.get_singleton()
        s.smtp_host = "smtp.example.com"
        s.smtp_port = 587
        s.alert_recipient_email = None
        with pytest.raises(BadRequestException, match="recipient"):
            await svc.send_test_email(s)

    @pytest.mark.asyncio
    async def test_send_test_email_raises_when_no_smtp_host(self, db_session):
        svc = SettingsService(db_session)
        s = await svc.get_singleton()
        # Written through the encrypted setter, as the API does: the plain
        # column holds Fernet ciphertext, and `decrypt_value` no longer falls
        # back to returning whatever it finds when it cannot decrypt.
        s.alert_recipient_email_decrypted = "soc@example.com"
        s.smtp_host = None
        s.smtp_port = None
        with pytest.raises(BadRequestException, match="SMTP settings"):
            await svc.send_test_email(s)

    @pytest.mark.asyncio
    async def test_send_test_email_starttls_port_587_branch(self, db_session):
        from smtplib import SMTP

        svc = SettingsService(db_session)
        s = await svc.get_singleton()
        s.smtp_host = "smtp.example.com"
        s.smtp_port = 587
        s.smtp_user = "ops@example.com"
        s.smtp_password_decrypted = "Passw0rd!"
        # Written through the encrypted setter, as the API does: the plain
        # column holds Fernet ciphertext, and `decrypt_value` no longer falls
        # back to returning whatever it finds when it cannot decrypt.
        s.alert_recipient_email_decrypted = "soc@example.com"

        with patch("app.services.settings_service.smtplib.SMTP", spec=SMTP) as mock_cls:
            instance = MagicMock()
            mock_cls.return_value.__enter__.return_value = instance
            res = await svc.send_test_email(s, to="custom-test@example.com")
        assert res == {"status": "sent", "to": "custom-test@example.com"}
        instance.ehlo.assert_called()
        instance.starttls.assert_called_once()
        instance.login.assert_called_once_with("ops@example.com", "Passw0rd!")
        instance.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_test_email_ssl_port_465_branch(self, db_session):
        from smtplib import SMTP_SSL

        svc = SettingsService(db_session)
        s = await svc.get_singleton()
        s.smtp_host = "smtp.example.com"
        s.smtp_port = 465
        s.smtp_security_mode = "ssl"
        s.smtp_user = None
        s.smtp_password = None
        # Written through the encrypted setter, as the API does: the plain
        # column holds Fernet ciphertext, and `decrypt_value` no longer falls
        # back to returning whatever it finds when it cannot decrypt.
        s.alert_recipient_email_decrypted = "soc@example.com"

        with patch(
            "app.services.settings_service.smtplib.SMTP_SSL", spec=SMTP_SSL
        ) as mock_cls:
            instance = MagicMock()
            mock_cls.return_value.__enter__.return_value = instance
            res = await svc.send_test_email(s)
        assert res["status"] == "sent"
        instance.login.assert_not_called()
        instance.send_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_test_email_starttls_failure_is_not_downgraded(
        self, db_session
    ):
        svc = SettingsService(db_session)
        s = await svc.get_singleton()
        s.smtp_host = "smtp.example.com"
        s.smtp_port = 587
        s.smtp_user = None
        # Written through the encrypted setter, as the API does: the plain
        # column holds Fernet ciphertext, and `decrypt_value` no longer falls
        # back to returning whatever it finds when it cannot decrypt.
        s.alert_recipient_email_decrypted = "soc@example.com"

        def _boom(*args, **kwargs):
            raise RuntimeError("starttls server advertises no tls")

        with patch("app.services.settings_service.smtplib.SMTP") as mock_cls:
            instance = MagicMock()
            instance.starttls.side_effect = _boom
            mock_cls.return_value.__enter__.return_value = instance
            with pytest.raises(BadRequestException, match="Failed to send email"):
                await svc.send_test_email(s)
        instance.send_message.assert_not_called()
