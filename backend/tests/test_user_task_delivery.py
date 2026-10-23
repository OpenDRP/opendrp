"""The two Celery bodies that carry a user message.

``test_user_notifications`` covers the service they call and the first attempt of
the notification task. What is left are the parts only the worker sees: the retry
it asks Celery for, the attempt count that decides whether a failure is recorded,
and the invitation task, whose body executes no test at all before this file.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from celery.exceptions import Retry

from app.tasks.user_tasks import (
    MAX_ATTEMPTS,
    RETRY_DELAY_SECONDS,
    send_user_invitation_task,
    send_user_notification_task,
)


class _Session:
    """A stand-in for ``AsyncSessionLocal()``; the service call is patched."""

    def __init__(self) -> None:
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc_info) -> bool:
        self.closed = True
        return False


@pytest.fixture
def worker(monkeypatch):
    """The tasks with their session factory, delivery functions and clock replaced."""

    def _install(deliver_notification=None, deliver_invitation=None):
        import app.core.database as database
        import app.services.user_notifications as notifications

        sessions: list[_Session] = []

        def _factory():
            session = _Session()
            sessions.append(session)
            return session

        monkeypatch.setattr(database, "AsyncSessionLocal", _factory)
        if deliver_notification is not None:
            monkeypatch.setattr(
                notifications, "deliver_user_notification", deliver_notification
            )
        if deliver_invitation is not None:
            monkeypatch.setattr(
                notifications, "deliver_user_invitation", deliver_invitation
            )
        return sessions

    return _install


class TestNotificationTask:
    def test_a_retry_outcome_asks_celery_for_the_configured_delay(self, worker):
        """The service's ``retry`` is the task's instruction, not a log line."""
        calls: list[dict] = []

        async def _deliver(_db, **kwargs):
            calls.append(kwargs)
            return "retry"

        sessions = worker(deliver_notification=_deliver)

        with pytest.raises(Retry):
            send_user_notification_task.run(event="deleted", target_email="gone@example.com")

        # The budget is the task's own declaration, not a loop inside its body.
        assert send_user_notification_task.max_retries == MAX_ATTEMPTS - 1
        assert send_user_notification_task.default_retry_delay == RETRY_DELAY_SECONDS
        assert calls[0]["final_attempt"] is False
        # The session is closed on the way out, retry or not.
        assert sessions[0].closed is True

    def test_the_last_attempt_is_the_only_one_allowed_to_record(self, worker):
        """``max_retries`` counts retries; the failure row belongs to attempt three."""
        calls: list[dict] = []

        async def _deliver(_db, **kwargs):
            calls.append(kwargs)
            return "failed"

        worker(deliver_notification=_deliver)

        send_user_notification_task.push_request(retries=MAX_ATTEMPTS - 1)
        try:
            result = send_user_notification_task.run(
                event="mfa_reset", target_email="owner@example.com"
            )
        finally:
            send_user_notification_task.pop_request()

        assert result == {"status": "failed"}
        assert calls[0]["final_attempt"] is True


class TestInvitationTask:
    def test_the_link_is_mailed_as_it_was_rendered_at_creation(self, worker):
        """The task parses the stored window; it never re-derives the URL."""
        calls: list[dict] = []

        async def _deliver(_db, **kwargs):
            calls.append(kwargs)
            return "sent"

        sessions = worker(deliver_invitation=_deliver)
        expires = (datetime.now(timezone.utc) + timedelta(days=7)).replace(microsecond=0)

        result = send_user_invitation_task.run(
            target_email="new@example.com",
            invitation_url="https://drp.example.com/accept-invitation?token=T",
            expires_at=expires.isoformat(),
            actor_email="admin@example.com",
            ip_address="203.0.113.9",
        )

        assert result == {"status": "sent"}
        assert calls[0]["invitation_url"].endswith("token=T")
        assert calls[0]["expires_at"] == expires
        assert calls[0]["final_attempt"] is False
        assert sessions[0].closed is True

    def test_an_invitation_retry_is_requested_the_same_way(self, worker):
        async def _deliver(_db, **_kwargs):
            return "retry"

        worker(deliver_invitation=_deliver)

        with pytest.raises(Retry):
            send_user_invitation_task.run(
                target_email="new@example.com",
                invitation_url="https://drp.example.com/accept-invitation?token=T",
                expires_at=datetime.now(timezone.utc).isoformat(),
            )
