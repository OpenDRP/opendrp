"""The settings service's refusals: what a save or a test send must not do.

``test_settings_integration`` covers the ordinary save and the two SMTP modes.
This file pins the branches that only run when something is wrong: a recipient
list that names nobody, a masked secret that arrives without its value, a row
that contradicts its own policy, a concurrent writer, and a test send aimed at a
destination the platform refuses to dial.
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.orm.exc import StaleDataError

from app.core.audit import AuditLog
from app.core.exceptions import BadRequestException, ConflictException
from app.services.settings_service import (
    SettingsService,
    is_unchanged_masked_value,
)


async def _row(db):
    """The singleton, with no SMTP host: each test states what it needs."""
    return await SettingsService(db).get_singleton()


class TestMaskDetection:
    def test_a_mask_helper_failure_never_reads_as_a_kept_secret(self, monkeypatch):
        """If the mask cannot be computed, the submitted value is taken as new.

        The opposite answer would silently drop a secret the operator just typed:
        a failure in a helper is not evidence that nothing changed.
        """
        from app.services import settings_service as module

        def _broken(*_args, **_kwargs):
            raise RuntimeError("no key material")

        monkeypatch.setattr(module, "mask_value", _broken)

        assert is_unchanged_masked_value("ab****yz", "the-real-secret") is False

    def test_the_empty_and_missing_cases_are_not_masks(self):
        assert is_unchanged_masked_value(None, "secret") is False
        assert is_unchanged_masked_value("", "secret") is False
        assert is_unchanged_masked_value("ab****yz", None) is False


class TestRecipients:
    @pytest.mark.asyncio
    async def test_an_unknown_recipient_is_refused(
        self, client, db_session, auth_headers_admin
    ):
        """A recipient id is a reference; an id that names no row delivers nowhere."""
        response = await client.put(
            "/api/v1/settings",
            headers=auth_headers_admin,
            json={"alert_email_user_ids": [str(uuid.uuid4())]},
        )

        assert response.status_code == 400
        assert "existing active users" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_a_deactivated_recipient_is_refused(
        self, client, db_session, test_inactive_admin, auth_headers_admin
    ):
        """An inactive account has no mailbox the platform may treat as a channel."""
        response = await client.put(
            "/api/v1/settings",
            headers=auth_headers_admin,
            json={"alert_email_user_ids": [str(test_inactive_admin.id)]},
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_an_active_recipient_is_accepted(
        self, client, db_session, test_viewer, auth_headers_admin
    ):
        response = await client.put(
            "/api/v1/settings",
            headers=auth_headers_admin,
            json={"alert_email_user_ids": [str(test_viewer.id)]},
        )

        assert response.status_code == 200, response.text
        assert response.json()["alert_email_user_ids"] == [str(test_viewer.id)]


class TestTransportPolicy:
    @pytest.mark.asyncio
    async def test_plain_smtp_with_credentials_is_refused_on_save(
        self, client, db_session, auth_headers_admin
    ):
        """The password would cross the wire in the clear; the save is refused."""
        response = await client.put(
            "/api/v1/settings",
            headers=auth_headers_admin,
            json={
                "smtp_security_mode": "plain",
                "smtp_user": "ops@example.com",
                "smtp_password": "Passw0rd!",
            },
        )

        assert response.status_code == 400
        assert "STARTTLS or implicit TLS" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_plain_smtp_with_credentials_is_refused_on_a_test_send(
        self, db_session
    ):
        """A row restored from a backup can hold a mode the form would not accept."""
        row = await _row(db_session)
        row.smtp_host = "smtp.example.com"
        row.smtp_port = 25
        row.smtp_security_mode = "plain"
        row.smtp_user = "ops@example.com"
        row.smtp_password_decrypted = "Passw0rd!"
        row.alert_recipient_email_decrypted = "soc@example.com"
        await db_session.commit()

        with pytest.raises(BadRequestException, match="credentials require TLS"):
            await SettingsService(db_session).send_test_email(row)


class TestConcurrency:
    @pytest.mark.asyncio
    async def test_a_stale_write_is_a_conflict_rather_than_a_lost_save(
        self, db_session, monkeypatch
    ):
        """A row another request replaced must not be overwritten silently."""
        from app.schemas.settings import SystemSettingsUpdate

        service = SettingsService(db_session)
        row = await _row(db_session)

        async def _stale():
            raise StaleDataError("UPDATE statement matched no rows")

        monkeypatch.setattr(db_session, "flush", _stale)

        with pytest.raises(ConflictException, match="changed concurrently"):
            await service.update_settings(row, SystemSettingsUpdate(telegram_alerts_enabled=False))


class TestTestSend:
    async def _configured(self, db) -> object:
        row = await _row(db)
        row.smtp_host = "smtp.example.com"
        row.smtp_port = 465
        row.smtp_security_mode = "ssl"
        row.smtp_from_email_decrypted = "opendrp@example.com"
        row.alert_recipient_email_decrypted = "soc@example.com"
        await db.commit()
        return row

    @pytest.mark.asyncio
    async def test_an_ssl_send_logs_in_when_credentials_are_present(self, db_session):
        """Implicit TLS authenticates with the same credentials as STARTTLS."""
        events: list[tuple] = []

        class _FakeSMTPSSL:
            def __init__(self, host, port, *, context=None, timeout=None):
                events.append(("connect", host, port, context is not None))

            def __enter__(self):
                return self

            def __exit__(self, *_exc_info):
                return False

            def login(self, user, password):
                events.append(("login", user, password))

            def send_message(self, message):
                events.append(("send", message["To"]))

        row = await self._configured(db_session)
        row.smtp_user = "ops@example.com"
        row.smtp_password_decrypted = "Passw0rd!"
        await db_session.commit()

        with patch("app.services.settings_service.smtplib.SMTP_SSL", _FakeSMTPSSL):
            result = await SettingsService(db_session).send_test_email(row)

        assert result["status"] == "sent"
        assert events[0] == ("connect", "smtp.example.com", 465, True)
        assert ("login", "ops@example.com", "Passw0rd!") in events
        assert ("send", "soc@example.com") in events

    @pytest.mark.asyncio
    async def test_a_blocked_destination_is_refused_with_a_named_reason(
        self, client, db_session, auth_headers_admin
    ):
        """The metadata endpoint is not a mail server; the refusal says why."""
        row = await _row(db_session)
        row.smtp_host = "169.254.169.254"
        row.smtp_port = 465
        row.smtp_from_email_decrypted = "opendrp@example.com"
        row.alert_recipient_email_decrypted = "soc@example.com"
        await db_session.commit()

        response = await client.post(
            "/api/v1/settings/test-email", headers=auth_headers_admin, json={}
        )

        assert response.status_code == 400
        assert "OUTBOUND_ALLOWED_HOSTS" in response.json()["detail"]
        rows = (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "outbound.blocked")
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].details["operation"] == "settings_test_email"
        assert rows[0].details["reason"]

    @pytest.mark.asyncio
    async def test_a_refused_destination_still_answers_when_the_audit_write_fails(
        self, client, db_session, auth_headers_admin, monkeypatch
    ):
        """The operator gets the refusal, not a database error standing in for it."""
        row = await _row(db_session)
        row.smtp_host = "169.254.169.254"
        row.smtp_port = 465
        row.alert_recipient_email_decrypted = "soc@example.com"
        await db_session.commit()

        async def _unavailable(*_args, **_kwargs):
            raise RuntimeError("audit sink is down")

        monkeypatch.setattr("app.core.audit.AuditLogger.emit_background", _unavailable)

        response = await client.post(
            "/api/v1/settings/test-email", headers=auth_headers_admin, json={}
        )

        assert response.status_code == 400
        assert "OUTBOUND_ALLOWED_HOSTS" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_an_unsupported_stored_mode_is_refused_not_downgraded(
        self, db_session
    ):
        """Nothing in this path may fall back to a weaker transport than asked for."""
        row = await self._configured(db_session)
        row.smtp_security_mode = "starttls-but-maybe"
        await db_session.commit()

        with pytest.raises(BadRequestException, match="unsupported SMTP security mode"):
            await SettingsService(db_session).send_test_email(row)

    @pytest.mark.asyncio
    async def test_a_send_that_runs_out_of_time_names_the_timeout(self, db_session):
        row = await self._configured(db_session)

        async def _timeout(_deliver):
            raise asyncio.TimeoutError()

        with patch("app.services.alert_service.bounded_smtp", _timeout):
            with pytest.raises(BadRequestException, match="timed out"):
                await SettingsService(db_session).send_test_email(row)

    @pytest.mark.asyncio
    async def test_a_delivery_error_is_sanitized_into_the_answer(self, db_session):
        """The operator gets a reason, not a stack trace or a credential."""
        row = await self._configured(db_session)

        async def _failed(_deliver):
            raise RuntimeError("login failed for ops@example.com password=Passw0rd!")

        with patch("app.services.alert_service.bounded_smtp", _failed):
            with pytest.raises(BadRequestException) as excinfo:
                await SettingsService(db_session).send_test_email(row)

        assert "Failed to send email" in str(excinfo.value)
