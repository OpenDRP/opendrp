"""Telling the account holder what an administrator did, without leaking a credential.

RWI-15/USR-08. The notice is scheduled *after* the mutation commits, so an SMTP
outage costs a message and not a password reset. The properties pinned here are
the ones the plan's acceptance criteria name: one reset produces exactly one
message, a missing or broken SMTP leaves the mutation successful and records an
outcome, and the message never contains the password, the hash, the TOTP secret
or a recovery code.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.services.settings_service import SettingsService
from app.services.user_notifications import (
    EVENTS,
    deliver_user_invitation,
    deliver_user_notification,
    render,
)

PASSWORD = "TestPass123!"
NEW_PASSWORD = "ResetPass456!"


async def _configure_smtp(db, *, host: str | None = "smtp.example.com") -> None:
    """Point the singleton at (or away from) a mail server.

    The fields are written directly because this file is not about the settings
    page; ``SettingsService`` is still used to make sure the singleton exists, so
    the test does not depend on whether another test happened to create it.
    """
    row = await SettingsService(db).get_singleton()
    row.smtp_host = host
    # The port column is NOT NULL; "no mail server" is an empty host.
    row.smtp_port = 587
    row.smtp_from_email_decrypted = "opendrp@example.com"
    await db.commit()


async def _actions(db) -> list[AuditLog]:
    rows = (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.action.like("user.notification.%"))
            .order_by(AuditLog.timestamp, AuditLog.id)
        )
    ).scalars().all()
    return list(rows)


async def _invitation_actions(db) -> list[AuditLog]:
    rows = (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.action.like("user.invitation.%"))
            .order_by(AuditLog.timestamp, AuditLog.id)
        )
    ).scalars().all()
    return list(rows)


def _public_origin(monkeypatch, origin: str | None) -> None:
    """Point the platform at the origin its links should name (or at none)."""
    from app.core import config as config_module

    monkeypatch.setattr(
        config_module.settings, "CORS_ORIGINS", [origin] if origin else []
    )


class TestScheduling:
    @pytest.mark.asyncio
    async def test_a_password_reset_schedules_exactly_one_message(
        self, client, db_session, test_admin, test_viewer, auth_headers_admin, monkeypatch
    ):
        await _configure_smtp(db_session)
        schedule = AsyncMock()
        monkeypatch.setattr(
            "app.tasks.user_tasks.send_user_notification_task.apply_async", schedule
        )

        response = await client.put(
            f"/api/v1/users/{test_viewer.id}",
            json={"new_password": NEW_PASSWORD},
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text

        assert schedule.call_count == 1
        kwargs = schedule.call_args.kwargs["kwargs"]
        assert kwargs["event"] == "password_reset"
        assert kwargs["target_email"] == test_viewer.email
        assert kwargs["target_user_id"] == str(test_viewer.id)
        assert kwargs["actor_email"] == test_admin.email
        assert kwargs["ip_address"]

    @pytest.mark.asyncio
    async def test_deactivation_tells_the_owner(
        self, client, db_session, test_viewer, auth_headers_admin, monkeypatch
    ):
        await _configure_smtp(db_session)
        schedule = AsyncMock()
        monkeypatch.setattr(
            "app.tasks.user_tasks.send_user_notification_task.apply_async", schedule
        )

        response = await client.put(
            f"/api/v1/users/{test_viewer.id}",
            json={"is_active": False},
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text
        assert schedule.call_count == 1
        assert schedule.call_args.kwargs["kwargs"]["event"] == "deactivated"

    @pytest.mark.asyncio
    async def test_clearing_a_second_factor_tells_the_owner(
        self, client, db_session, test_viewer, auth_headers_admin, monkeypatch
    ):
        from datetime import datetime, timezone

        await _configure_smtp(db_session)
        test_viewer.totp_secret = "encrypted-placeholder"
        test_viewer.totp_enabled_at = datetime.now(timezone.utc)
        await db_session.commit()
        schedule = AsyncMock()
        monkeypatch.setattr(
            "app.tasks.user_tasks.send_user_notification_task.apply_async", schedule
        )

        response = await client.post(
            f"/api/v1/users/{test_viewer.id}/mfa/reset", headers=auth_headers_admin
        )
        assert response.status_code == 200, response.text
        assert schedule.call_count == 1
        assert schedule.call_args.kwargs["kwargs"]["event"] == "mfa_reset"

    @pytest.mark.asyncio
    async def test_deletion_tells_the_owner_at_the_freed_address(
        self, client, db_session, test_viewer, auth_headers_admin, monkeypatch
    ):
        await _configure_smtp(db_session)
        schedule = AsyncMock()
        monkeypatch.setattr(
            "app.tasks.user_tasks.send_user_notification_task.apply_async", schedule
        )
        address = test_viewer.email

        response = await client.delete(
            f"/api/v1/users/{test_viewer.id}", headers=auth_headers_admin
        )
        assert response.status_code == 204, response.text
        assert schedule.call_count == 1
        kwargs = schedule.call_args.kwargs["kwargs"]
        assert kwargs["event"] == "deleted"
        # The row is gone; the address was captured before the delete.
        assert kwargs["target_email"] == address

    @pytest.mark.asyncio
    async def test_without_smtp_the_reset_succeeds_and_nothing_is_scheduled(
        self, client, db_session, test_viewer, auth_headers_admin, monkeypatch
    ):
        """The mutation is not a mail operation, and an installation may have no SMTP."""
        await _configure_smtp(db_session, host=None)
        schedule = AsyncMock()
        monkeypatch.setattr(
            "app.tasks.user_tasks.send_user_notification_task.apply_async", schedule
        )

        response = await client.put(
            f"/api/v1/users/{test_viewer.id}",
            json={"new_password": NEW_PASSWORD},
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text
        schedule.assert_not_called()

        rows = await _actions(db_session)
        assert [row.action for row in rows] == ["user.notification.skipped"]
        assert rows[0].details["reason"] == "smtp_not_configured"
        assert rows[0].details["event"] == "password_reset"

    @pytest.mark.asyncio
    async def test_an_unreachable_broker_does_not_fail_the_mutation(
        self, client, db_session, test_viewer, auth_headers_admin, monkeypatch
    ):
        """A queue that is down is recorded, not turned into a 500 on the reset."""
        await _configure_smtp(db_session)

        def unavailable(**kwargs):
            raise RuntimeError("no broker")

        monkeypatch.setattr(
            "app.tasks.user_tasks.send_user_notification_task.apply_async", unavailable
        )

        response = await client.put(
            f"/api/v1/users/{test_viewer.id}",
            json={"new_password": NEW_PASSWORD},
            headers=auth_headers_admin,
        )
        assert response.status_code == 200, response.text

        rows = await _actions(db_session)
        assert [row.action for row in rows] == ["user.notification.failed"]
        assert rows[0].details["reason"] == "celery_unavailable"


class TestTask:
    def test_the_task_opens_its_own_session_and_reports_the_outcome(self, monkeypatch):
        """The worker path: no request, no request-scoped session, one answer."""
        from app.tasks.user_tasks import send_user_notification_task

        calls: list[dict] = []

        class _Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

        async def fake_deliver(db, **kwargs):
            calls.append(kwargs)
            return "skipped"

        monkeypatch.setattr(
            "app.core.database.AsyncSessionLocal", lambda: _Session()
        )
        monkeypatch.setattr(
            "app.services.user_notifications.deliver_user_notification", fake_deliver
        )

        result = send_user_notification_task.run(
            event="deleted",
            target_email="gone@example.com",
            target_user_id="00000000-0000-0000-0000-000000000001",
            actor_email="admin@example.com",
            ip_address="203.0.113.9",
        )

        assert result == {"status": "skipped"}
        assert calls[0]["event"] == "deleted"
        assert calls[0]["target_email"] == "gone@example.com"
        # The first attempt is not the final one: only the last may write the
        # failure row, or a retried message would be described as several outcomes.
        assert calls[0]["final_attempt"] is False


class TestDelivery:
    @pytest.mark.asyncio
    async def test_one_message_and_a_sent_row(
        self, db_session, test_admin, test_viewer, monkeypatch
    ):
        await _configure_smtp(db_session)
        sent = AsyncMock(return_value=True)
        monkeypatch.setattr("app.services.alert_service.AlertService.send_email", sent)

        outcome = await deliver_user_notification(
            db_session,
            event="password_reset",
            target_email=test_viewer.email,
            target_user_id=str(test_viewer.id),
            actor_email=test_admin.email,
            ip_address="203.0.113.9",
        )

        assert outcome == "sent"
        assert sent.call_count == 1
        message = sent.call_args.kwargs
        assert message["to"] == test_viewer.email
        assert test_admin.email in message["plain_body"]
        assert "203.0.113.9" in message["plain_body"]
        rows = await _actions(db_session)
        assert [row.action for row in rows] == ["user.notification.sent"]

    @pytest.mark.asyncio
    async def test_the_message_carries_no_credential(self, db_session, test_viewer):
        """The negative half: nothing a reader could use to sign in is in the mail."""
        secret = "totp-secret-marker-123456"
        recovery = ["recovery-code-marker-1", "recovery-code-marker-2"]
        test_viewer.totp_secret = secret
        test_viewer.mfa_recovery_codes = recovery
        test_viewer.password_hash = "$2b$12$hash-marker"
        await db_session.commit()

        for event in EVENTS:
            subject, html, plain = render(
                event,
                actor_email="admin@example.com",
                ip_address="198.51.100.7",
            )
            body = subject + html + plain
            assert secret not in body
            assert "$2b$12$hash-marker" not in body
            for code in recovery:
                assert code not in body
            assert NEW_PASSWORD not in body

    @pytest.mark.asyncio
    async def test_a_broken_smtp_server_is_a_failed_row_not_an_exception(
        self, db_session, test_viewer, monkeypatch
    ):
        await _configure_smtp(db_session)

        async def refused(_self, **kwargs):
            raise RuntimeError("connection refused")

        monkeypatch.setattr("app.services.alert_service.AlertService.send_email", refused)

        outcome = await deliver_user_notification(
            db_session,
            event="deactivated",
            target_email=test_viewer.email,
            target_user_id=str(test_viewer.id),
        )

        assert outcome == "failed"
        rows = await _actions(db_session)
        assert [row.action for row in rows] == ["user.notification.failed"]
        assert rows[0].details["reason"]

    @pytest.mark.asyncio
    async def test_a_transient_failure_asks_for_a_retry_before_it_is_recorded(
        self, db_session, test_viewer, monkeypatch
    ):
        await _configure_smtp(db_session)

        async def refused(_self, **kwargs):
            raise RuntimeError("timed out")

        monkeypatch.setattr("app.services.alert_service.AlertService.send_email", refused)

        first = await deliver_user_notification(
            db_session,
            event="mfa_reset",
            target_email=test_viewer.email,
            target_user_id=str(test_viewer.id),
            final_attempt=False,
        )
        assert first == "retry"
        # A retry is not an outcome yet: recording one row per attempt would
        # describe one message as several.
        assert await _actions(db_session) == []

        final = await deliver_user_notification(
            db_session,
            event="mfa_reset",
            target_email=test_viewer.email,
            target_user_id=str(test_viewer.id),
            final_attempt=True,
        )
        assert final == "failed"
        assert [row.action for row in await _actions(db_session)] == [
            "user.notification.failed"
        ]


class TestInvitations:
    """The one mail that carries a link, and the two reasons it is not sent.

    The invitation is a credential the administrator never learns, so where the
    link may point is a security decision, not a formatting one: a link to the
    reader's own machine is not mailed at all, and the administrator is told the
    message was not queued so they can hand the link on themselves.
    """

    @pytest.mark.asyncio
    async def test_an_invitation_is_mailed_when_smtp_and_a_public_origin_are_configured(
        self, client, db_session, auth_headers_admin, monkeypatch
    ):
        await _configure_smtp(db_session)
        _public_origin(monkeypatch, "https://drp.example.com")
        schedule = AsyncMock()
        monkeypatch.setattr(
            "app.tasks.user_tasks.send_user_invitation_task.apply_async", schedule
        )

        response = await client.post(
            "/api/v1/users/invite",
            json={"email": "invited@example.com", "role": "viewer"},
            headers=auth_headers_admin,
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["email_scheduled"] is True

        assert schedule.call_count == 1
        call = schedule.call_args.kwargs
        # One attempt at the broker, not the producer's default retry loop.
        assert call["retry"] is False
        payload = call["kwargs"]
        assert payload["target_email"] == "invited@example.com"
        assert payload["invitation_url"] == (
            "https://drp.example.com/accept-invitation?token="
            f"{body['invitation_token']}"
        )
        # The scheduled window is the one the response promised.
        assert datetime.fromisoformat(payload["expires_at"]) == datetime.fromisoformat(
            body["expires_at"]
        )

    @pytest.mark.asyncio
    async def test_a_link_to_the_reader_s_own_machine_is_not_mailed(
        self, client, db_session, auth_headers_admin, monkeypatch
    ):
        """`localhost` in a mail is a link to whoever reads it, so nothing is sent."""
        await _configure_smtp(db_session)
        _public_origin(monkeypatch, "http://localhost:3000")
        schedule = AsyncMock()
        monkeypatch.setattr(
            "app.tasks.user_tasks.send_user_invitation_task.apply_async", schedule
        )

        response = await client.post(
            "/api/v1/users/invite",
            json={"email": "invited@example.com", "role": "viewer"},
            headers=auth_headers_admin,
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["email_scheduled"] is False
        # The link is still returned: the administrator passes it on themselves.
        assert body["invitation_token"]
        schedule.assert_not_called()

        rows = await _invitation_actions(db_session)
        assert [row.action for row in rows] == ["user.invitation.skipped"]
        assert rows[0].details["reason"] == "public_origin_not_configured"
        assert rows[0].details["event"] == "invitation"

    @pytest.mark.asyncio
    async def test_an_unreachable_broker_leaves_the_invitation_usable(
        self, client, db_session, auth_headers_admin, monkeypatch
    ):
        """A queue that is down costs the mail, not the invitation."""
        await _configure_smtp(db_session)
        _public_origin(monkeypatch, "https://drp.example.com")

        def unavailable(**kwargs):
            raise RuntimeError("no broker")

        monkeypatch.setattr(
            "app.tasks.user_tasks.send_user_invitation_task.apply_async", unavailable
        )

        response = await client.post(
            "/api/v1/users/invite",
            json={"email": "invited@example.com", "role": "viewer"},
            headers=auth_headers_admin,
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["email_scheduled"] is False

        rows = await _invitation_actions(db_session)
        assert [row.action for row in rows] == ["user.invitation.failed"]
        assert rows[0].details["reason"] == "celery_unavailable"

        # The account still works with the link the administrator was handed.
        accept = await client.post(
            "/api/v1/auth/accept-invitation",
            json={
                "token": body["invitation_token"],
                "new_password": "InvitedPass123!",
            },
        )
        assert accept.status_code == 200, accept.text

    @pytest.mark.asyncio
    async def test_the_mail_carries_the_link_and_records_the_send(
        self, db_session, test_admin, monkeypatch
    ):
        await _configure_smtp(db_session)
        sent = AsyncMock(return_value=True)
        monkeypatch.setattr("app.services.alert_service.AlertService.send_email", sent)
        link = "https://drp.example.com/accept-invitation?token=TOKEN-MARKER"

        outcome = await deliver_user_invitation(
            db_session,
            target_email="invited@example.com",
            invitation_url=link,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            actor_email=test_admin.email,
            ip_address="203.0.113.9",
        )

        assert outcome == "sent"
        assert sent.call_count == 1
        message = sent.call_args.kwargs
        assert message["to"] == "invited@example.com"
        assert "[OpenDRP] You have been invited" in message["subject"]
        assert link in message["plain_body"]
        assert "TOKEN-MARKER" in message["html_body"]
        rows = await _invitation_actions(db_session)
        assert [row.action for row in rows] == ["user.invitation.sent"]
        assert rows[0].details["target_email"] == "invited@example.com"
