"""Delivery of account-change notices to the account holder.

The mutation has already committed by the time this task exists, so the task has
one job: make an honest attempt and record what happened. A transient failure is
retried a bounded number of times under the platform's ordinary task limits; once
those are spent, the attempt is written as ``user.notification.failed`` rather
than retried forever, because a notification that is an hour late is still useful
and one that is retried until the queue fills is not.
"""

from __future__ import annotations

from app.core.celery_app import async_task, celery_app

#: Attempts in total, including the first. The Celery limit counts *retries*, so
#: the decorator gets one less; the final attempt is the one allowed to write the
#: failure row.
MAX_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 60


@celery_app.task(
    name="send_user_notification",
    bind=True,
    max_retries=MAX_ATTEMPTS - 1,
    default_retry_delay=RETRY_DELAY_SECONDS,
    ignore_result=False,
)
@async_task
async def send_user_notification_task(
    self=None,
    *,
    event: str,
    target_email: str,
    target_user_id: str | None = None,
    actor_email: str | None = None,
    ip_address: str | None = None,
) -> dict:
    from app.core.database import AsyncSessionLocal
    from app.services.user_notifications import deliver_user_notification

    request = getattr(self, "request", None)
    retries = int(getattr(request, "retries", 0) or 0)
    final_attempt = retries >= MAX_ATTEMPTS - 1

    async with AsyncSessionLocal() as db:
        outcome = await deliver_user_notification(
            db,
            event=event,
            target_email=target_email,
            target_user_id=target_user_id,
            actor_email=actor_email,
            ip_address=ip_address,
            final_attempt=final_attempt,
        )

    if outcome == "retry":
        raise self.retry(countdown=RETRY_DELAY_SECONDS)
    return {"status": outcome}


@celery_app.task(
    name="send_user_invitation",
    bind=True,
    max_retries=MAX_ATTEMPTS - 1,
    default_retry_delay=RETRY_DELAY_SECONDS,
    ignore_result=False,
)
@async_task
async def send_user_invitation_task(
    self=None,
    *,
    target_email: str,
    invitation_url: str,
    expires_at: str,
    actor_email: str | None = None,
    ip_address: str | None = None,
) -> dict:
    """Mail one invitation. The URL is passed as it was rendered at creation."""
    from datetime import datetime

    from app.core.database import AsyncSessionLocal
    from app.services.user_notifications import deliver_user_invitation

    request = getattr(self, "request", None)
    retries = int(getattr(request, "retries", 0) or 0)
    final_attempt = retries >= MAX_ATTEMPTS - 1

    async with AsyncSessionLocal() as db:
        outcome = await deliver_user_invitation(
            db,
            target_email=target_email,
            invitation_url=invitation_url,
            expires_at=datetime.fromisoformat(expires_at),
            actor_email=actor_email,
            ip_address=ip_address,
            final_attempt=final_attempt,
        )

    if outcome == "retry":
        raise self.retry(countdown=RETRY_DELAY_SECONDS)
    return {"status": outcome}
