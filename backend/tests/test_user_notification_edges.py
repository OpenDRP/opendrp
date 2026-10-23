"""The notification path's failures, and the task that owns its retries.

``test_user_notifications`` pins scheduling, the sent row and the credential-free
message. This file pins the outcomes that only happen when delivery goes wrong:
an installation with no SMTP, a provider that refuses, a settings row that
disappears between the check and the send, and the retry boundary that decides
whether an attempt is recorded at all.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.services.alert_transport import AlertDeliveryPermanentError
from app.services.settings_service import SettingsService
from app.services.user_notifications import (
    deliver_user_invitation,
    deliver_user_notification,
    render,
)


async def _configure(db, *, host: str | None = "smtp.example.com", port: int = 587) -> None:
    row = await SettingsService(db).get_singleton()
    row.smtp_host = host
    row.smtp_port = port
    row.smtp_from_email_decrypted = "opendrp@example.com"
    await db.commit()


async def _rows(db, prefix: str) -> list[AuditLog]:
    return list(
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.action.like(f"{prefix}%"))
                .order_by(AuditLog.timestamp, AuditLog.id)
            )
        ).scalars()
    )


class TestRendering:
    def test_an_event_outside_the_closed_list_is_refused(self):
        """A typo must fail here rather than arrive as a mail that says nothing."""
        with pytest.raises(ValueError, match="unknown user notification event"):
            render("password_resetted", actor_email=None, ip_address=None)


class TestNotificationOutcomes:
    @pytest.mark.asyncio
    async def test_an_installation_without_smtp_records_that_it_did_not_send(
        self, db_session, test_viewer
    ):
        await _configure(db_session, host=None)

        outcome = await deliver_user_notification(
            db_session, event="password_reset", target_email=test_viewer.email
        )

        assert outcome == "skipped"
        rows = await _rows(db_session, "user.notification.")
        assert [row.action for row in rows] == ["user.notification.skipped"]
        assert rows[0].details["reason"] == "smtp_not_configured"

    @pytest.mark.asyncio
    async def test_a_refused_message_is_a_permanent_failure_not_a_retry(
        self, db_session, test_viewer, monkeypatch
    ):
        """A provider rejection will be rejected again; the row says so once."""
        await _configure(db_session)

        async def _refused(_self, **_kwargs):
            raise AlertDeliveryPermanentError("mailbox does not exist")

        monkeypatch.setattr("app.services.alert_service.AlertService.send_email", _refused)

        outcome = await deliver_user_notification(
            db_session, event="deactivated", target_email=test_viewer.email
        )

        assert outcome == "failed"
        rows = await _rows(db_session, "user.notification.")
        assert [row.action for row in rows] == ["user.notification.failed"]
        assert "mailbox does not exist" in rows[0].details["reason"]

    @pytest.mark.asyncio
    async def test_a_channel_that_vanished_mid_send_is_not_a_delivery(
        self, db_session, test_viewer, monkeypatch
    ):
        """``send_email`` answers False when settings were cleared under it."""
        await _configure(db_session)
        monkeypatch.setattr(
            "app.services.alert_service.AlertService.send_email",
            AsyncMock(return_value=False),
        )

        outcome = await deliver_user_notification(
            db_session, event="mfa_reset", target_email=test_viewer.email
        )

        assert outcome == "failed"
        rows = await _rows(db_session, "user.notification.")
        assert rows[0].details["reason"] == "smtp became unconfigured"


class TestInvitationOutcomes:
    @pytest.mark.asyncio
    async def test_an_invitation_without_smtp_is_recorded_as_skipped(
        self, db_session
    ):
        await _configure(db_session, host=None)

        outcome = await deliver_user_invitation(
            db_session,
            target_email="new@example.com",
            invitation_url="https://drp.example.com/accept-invitation?token=x",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )

        assert outcome == "skipped"
        rows = await _rows(db_session, "user.invitation.")
        assert rows[0].details["reason"] == "smtp_not_configured"

    @pytest.mark.asyncio
    async def test_an_invitation_without_a_link_is_not_mailed(
        self, db_session
    ):
        """No public origin means no link, and a link-less invitation is useless."""
        await _configure(db_session)

        outcome = await deliver_user_invitation(
            db_session,
            target_email="new@example.com",
            invitation_url=None,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )

        assert outcome == "skipped"
        rows = await _rows(db_session, "user.invitation.")
        assert rows[0].details["reason"] == "public_origin_not_configured"

    @pytest.mark.asyncio
    async def test_a_refused_invitation_records_the_reason(
        self, db_session, monkeypatch
    ):
        await _configure(db_session)

        async def _refused(_self, **_kwargs):
            raise ValueError("recipient domain is not routable")

        monkeypatch.setattr("app.services.alert_service.AlertService.send_email", _refused)

        outcome = await deliver_user_invitation(
            db_session,
            target_email="new@example.com",
            invitation_url="https://drp.example.com/accept-invitation?token=x",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )

        assert outcome == "failed"
        rows = await _rows(db_session, "user.invitation.")
        assert "not routable" in rows[0].details["reason"]

    @pytest.mark.asyncio
    async def test_a_transient_invitation_failure_waits_for_the_last_attempt(
        self, db_session, monkeypatch
    ):
        await _configure(db_session)

        async def _unreachable(_self, **_kwargs):
            raise RuntimeError("connection reset")

        monkeypatch.setattr(
            "app.services.alert_service.AlertService.send_email", _unreachable
        )
        link = "https://drp.example.com/accept-invitation?token=x"
        expires = datetime.now(timezone.utc) + timedelta(days=7)

        first = await deliver_user_invitation(
            db_session,
            target_email="new@example.com",
            invitation_url=link,
            expires_at=expires,
            final_attempt=False,
        )
        assert first == "retry"
        assert await _rows(db_session, "user.invitation.") == []

        last = await deliver_user_invitation(
            db_session,
            target_email="new@example.com",
            invitation_url=link,
            expires_at=expires,
            final_attempt=True,
        )
        assert last == "failed"
        rows = await _rows(db_session, "user.invitation.")
        assert [row.action for row in rows] == ["user.invitation.failed"]
