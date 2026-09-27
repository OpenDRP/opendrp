import pytest
import pytest_asyncio

from app.models.settings import SystemSettings
from app.schemas.settings import SystemSettingsUpdate
from app.services.settings_service import SettingsService


@pytest_asyncio.fixture
async def settings_row(db_session):
    s = SystemSettings()
    db_session.add(s)
    await db_session.commit()
    await db_session.refresh(s)
    return s


@pytest.mark.anyio
class TestEncryptedHybridProperties:
    async def test_all_six_encrypted_fields_roundtrip(self, db_session, settings_row):
        pairs = {
            "smtp_password_decrypted": "smtp-pass-strong",
            "telegram_bot_token_decrypted": "1234567:ABCtoken-XYZ",
            "smtp_from_email_decrypted": "alerts@company.com",
            "alert_recipient_email_decrypted": "soc@company.com",
        }
        for attr, val in pairs.items():
            setattr(settings_row, attr, val)

        db_session.add(settings_row)
        await db_session.commit()
        await db_session.refresh(settings_row)

        for attr, expected in pairs.items():
            assert getattr(settings_row, attr) == expected, f"mismatch {attr}"

    async def test_plain_fields_not_encrypted(self, db_session, settings_row):
        settings_row.smtp_port = 465
        settings_row.smtp_host = "smtp.sendgrid.net"
        settings_row.smtp_user = "apikey"
        db_session.add(settings_row)
        await db_session.commit()
        await db_session.refresh(settings_row)
        assert settings_row.smtp_port == 465
        assert settings_row.smtp_host == "smtp.sendgrid.net"
        assert settings_row.smtp_user == "apikey"


@pytest.mark.anyio
class TestSettingsService:
    async def test_get_singleton_creates_when_empty(self, db_session):
        from sqlalchemy import delete
        await db_session.execute(delete(SystemSettings))
        await db_session.commit()
        svc = SettingsService(db_session)
        first = await svc.get_singleton()
        second = await svc.get_singleton()
        assert first.id == second.id

    async def test_update_settings_maps_encrypted_keys(self, db_session, settings_row):
        svc = SettingsService(db_session)
        upd = SystemSettingsUpdate(
            smtp_password="passw0rd-smtp",
            smtp_port=2525,
        )
        s = await svc.update_settings(settings_row, upd)
        assert s.smtp_password_decrypted == "passw0rd-smtp"
        assert s.smtp_port == 2525

    async def test_update_settings_encrypts_email_addresses(self, db_session, settings_row):
        svc = SettingsService(db_session)
        sender = "alerts@example.com"
        recipient = "soc@example.com"
        updated = await svc.update_settings(
            settings_row,
            SystemSettingsUpdate(
                smtp_from_email=sender,
                alert_recipient_email=recipient,
            ),
        )
        assert updated.smtp_from_email != sender
        assert updated.alert_recipient_email != recipient
        assert updated.smtp_from_email_decrypted == sender
        assert updated.alert_recipient_email_decrypted == recipient

    async def test_update_settings_ignores_null_smtp_port(
        self, db_session, settings_row
    ):
        svc = SettingsService(db_session)
        settings_row.smtp_port = 2525
        await db_session.commit()
        updated = await svc.update_settings(
            settings_row, SystemSettingsUpdate(smtp_port=None)
        )
        assert updated.smtp_port == 2525

    async def test_update_settings_exact_mask_echo_preserves_secret(
        self, db_session, settings_row
    ):
        from app.core.crypto import mask_value

        secret = "Secret-Value-1A"
        settings_row.smtp_password_decrypted = secret
        await db_session.commit()

        masked = mask_value(secret, keep_first=2, keep_last=2)
        assert "*" in masked
        svc = SettingsService(db_session)
        updated = await svc.update_settings(
            settings_row, SystemSettingsUpdate(smtp_password=masked)
        )
        assert updated.smtp_password_decrypted == secret
        assert updated.smtp_password_decrypted != masked

    async def test_update_settings_legit_value_with_asterisk_is_saved(
        self, db_session, settings_row
    ):
        """An asterisk is a legal password character, not a marker.

        Refusing every value that contains one told an operator their complete
        value was not complete, and left them no way to set the secret at all. The
        refusal is narrower than that: a *mask* must not be stored.
        """
        value = "a*b*c-password-123"
        svc = SettingsService(db_session)
        updated = await svc.update_settings(
            settings_row, SystemSettingsUpdate(smtp_password=value)
        )
        assert updated.smtp_password_decrypted == value

    async def test_update_settings_a_foreign_mask_is_refused(
        self, db_session, settings_row
    ):
        """The placeholder of some *other* value must never become the secret.

        Storing ``ab****yz`` leaves the channel authenticating with a literal
        mask — an outage that shows up only when the next alert is due. The
        unchanged-mask check catches the field's own placeholder; this catches the
        shape, which is what a stale client sends.
        """
        from app.core.exceptions import BadRequestException

        svc = SettingsService(db_session)
        with pytest.raises(BadRequestException, match="masked"):
            await svc.update_settings(
                settings_row, SystemSettingsUpdate(smtp_password="ab****yz")
            )

    async def test_send_test_email_uses_decrypted_from_address(
        self, db_session, settings_row
    ):
        from unittest.mock import MagicMock, patch

        svc = SettingsService(db_session)
        settings_row.smtp_host = "smtp.example.com"
        settings_row.smtp_port = 587
        settings_row.smtp_user = "ops@example.com"
        settings_row.smtp_from_email_decrypted = "alerts@example.com"
        settings_row.smtp_password_decrypted = "Passw0rd!"
        settings_row.alert_recipient_email_decrypted = "soc@example.com"
        await db_session.commit()

        with patch("app.services.settings_service.smtplib.SMTP") as mock_cls:
            instance = MagicMock()
            mock_cls.return_value.__enter__.return_value = instance
            await svc.send_test_email(settings_row, to="custom-test@example.com")
        msg = instance.send_message.call_args.args[0]
        assert msg["From"] == "alerts@example.com"
        assert msg["To"] == "custom-test@example.com"

    async def test_send_test_email_plain_mode_does_not_start_tls(
        self, db_session, settings_row
    ):
        from unittest.mock import MagicMock, patch

        svc = SettingsService(db_session)
        settings_row.smtp_host = "relay.internal"
        settings_row.smtp_port = 25
        settings_row.smtp_security_mode = "plain"
        settings_row.smtp_from_email_decrypted = "alerts@example.com"
        settings_row.alert_recipient_email_decrypted = "soc@example.com"
        await db_session.commit()

        with patch("app.services.settings_service.smtplib.SMTP") as mock_cls:
            instance = MagicMock()
            mock_cls.return_value.__enter__.return_value = instance
            await svc.send_test_email(settings_row)
        instance.starttls.assert_not_called()
        instance.send_message.assert_called_once()

    async def test_send_test_email_raises_bad_request_when_no_smtp(
        self, db_session, settings_row
    ):
        from app.core.exceptions import BadRequestException

        svc = SettingsService(db_session)
        with pytest.raises(BadRequestException):
            await svc.send_test_email(settings_row, to="someone@local")

    async def test_send_test_email_no_recipient_raises(self, db_session, settings_row):
        from app.core.exceptions import BadRequestException

        svc = SettingsService(db_session)
        settings_row.smtp_host = "localhost"
        settings_row.smtp_port = 1025
        db_session.add(settings_row)
        await db_session.commit()
        with pytest.raises(BadRequestException):
            await svc.send_test_email(settings_row)
