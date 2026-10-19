"""One message to the account holder when an administrator changes their account.

An administrator can reset a password, clear a second factor, deactivate an
account or delete it, and the person whose account it is otherwise finds out at
the next sign-in — possibly days later, and from a failure they cannot explain.
The alert channels are not the right recipient: they report findings to the
security team, while this is one account telling its owner what was done to it,
by whom, from where, and what to do next.

Three properties decide the shape of this module:

* **It never blocks the mutation.** The message is scheduled after the mutation
  has committed, so an SMTP outage costs a notification, not a password reset. A
  task that cannot reach SMTP leaves a ``user.notification.failed`` row and
  nothing else (D11).
* **It carries no credential.** The message names the event and the operator; it
  never contains the new password, a hash, a TOTP secret or a recovery code.
  Sending a password by email would undo the reason the account is forced to
  change it at the next sign-in.
* **It uses the alert transport, not a second one.** ``AlertService.send_email``
  is the thin public door onto the same SMTP client, the same TLS rules and the
  same outbound policy (``ensure_allowed``) that alerts already use; a second
  mail path would be a second place for those rules to drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import structlog
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditLogger
from app.core.safe_errors import sanitize_external_error

log = structlog.get_logger()

#: The events a caller may notify about. A closed list rather than free text: the
#: subject and the next step are what the reader acts on, so a typo must fail here
#: instead of arriving as a mail that says nothing useful.
EVENTS: dict[str, "NotificationEvent"] = {}


@dataclass(frozen=True)
class NotificationEvent:
    key: str
    #: What happened, in the sentence the owner reads first.
    happened: str
    #: What the owner should do about it.
    next_step: str
    #: The mail subject; short, because it is read in a list.
    subject: str


def _event(key: str, *, happened: str, next_step: str, subject: str) -> None:
    EVENTS[key] = NotificationEvent(
        key=key, happened=happened, next_step=next_step, subject=subject
    )


_event(
    "password_reset",
    happened="An administrator reset your password.",
    next_step=(
        "The password you had before no longer works. Sign in with the temporary "
        "password you were given and choose a new one; the platform asks for it "
        "before anything else opens. If you were not expecting this, contact your "
        "administrator immediately."
    ),
    subject="[OpenDRP] Your password was reset",
)
_event(
    "mfa_reset",
    happened="An administrator cleared the second factor on your account.",
    next_step=(
        "Your authenticator app no longer grants access. At your next sign-in the "
        "platform asks you to enrol a new authenticator before the rest of the "
        "platform opens. If you were not expecting this, contact your "
        "administrator immediately."
    ),
    subject="[OpenDRP] Your second factor was cleared",
)
_event(
    "deactivated",
    happened="An administrator deactivated your account.",
    next_step=(
        "You can no longer sign in. If you believe this is a mistake, contact your "
        "administrator — reactivation is a deliberate act by them, not something "
        "the platform does on request."
    ),
    subject="[OpenDRP] Your account was deactivated",
)
_event(
    "deleted",
    happened="An administrator deleted your account.",
    next_step=(
        "The account and its sessions are gone and this address is free to be "
        "registered again. If you believe this is a mistake, contact your "
        "administrator."
    ),
    subject="[OpenDRP] Your account was deleted",
)

jinja_env = Environment(
    loader=FileSystemLoader("app/templates"),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


class NotificationTransient(RuntimeError):
    """A failure worth retrying: the message may yet be delivered."""


class NotificationPermanent(RuntimeError):
    """A failure that a retry cannot fix (refused sender, blocked destination)."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _readable(instant: datetime) -> str:
    """The instant as the reader should see it: UTC, and labelled as such."""
    return instant.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def render(event: str, *, actor_email: str | None, ip_address: str | None,
           occurred_at: datetime | None = None) -> tuple[str, str, str]:
    """The subject, HTML and plain text of one notification.

    Pure on purpose: everything sensitive is *absent* by construction, because
    there is no parameter through which a password, a hash or a recovery code
    could arrive. ``test_user_notifications`` checks the rendered body for the
    account's secrets as well, so a future field cannot quietly reintroduce one.
    """
    definition = EVENTS.get(event)
    if definition is None:
        raise ValueError(f"unknown user notification event: {event}")
    when = _readable(occurred_at or _utc_now())
    actor = actor_email or "an administrator"
    source = ip_address or "an unknown address"
    html = jinja_env.get_template("emails/user_notification.html").render(
        subject=definition.subject,
        happened=definition.happened,
        next_step=definition.next_step,
        actor_email=actor,
        source_ip=source,
        occurred_at=when,
    )
    plain = (
        f"{definition.subject}\n\n"
        f"{definition.happened}\n\n"
        f"When: {when}\n"
        f"By: {actor}\n"
        f"From: {source}\n\n"
        f"{definition.next_step}\n\n"
        "This is an automated security notice from OpenDRP. Do not reply."
    )
    return definition.subject, html, plain


async def _record(
    db: AsyncSession,
    action: str,
    *,
    event: str,
    target_email: str,
    target_user_id: str | None,
    actor_email: str | None,
    ip_address: str | None,
    reason: str | None = None,
) -> None:
    details: dict[str, Any] = {
        "target_user_id": target_user_id,
        "target_email": target_email,
        "event": event,
        "channel": "email",
        "actor_email": actor_email,
        "source_ip": ip_address,
    }
    if reason:
        details["reason"] = reason
    await AuditLogger.emit_background(
        db,
        action=action,
        ip_address=ip_address or "internal:notification",
        user_id=None,
        details=details,
    )


async def deliver_user_notification(
    db: AsyncSession,
    *,
    event: str,
    target_email: str,
    target_user_id: str | None = None,
    actor_email: str | None = None,
    ip_address: str | None = None,
    final_attempt: bool = True,
) -> str:
    """Send one notification and record the outcome.

    Returns ``sent``, ``skipped``, ``failed`` or ``retry``. ``retry`` is the only
    outcome that writes no row: the task is going to try again, and a result row
    per attempt would describe one mail as several outcomes.
    """
    from app.services.alert_service import AlertDeliveryPermanentError, AlertService
    from app.services.settings_service import SettingsService

    settings_row = await SettingsService(db).get_singleton()
    if not (settings_row.smtp_host and settings_row.smtp_port):
        await _record(
            db,
            "user.notification.skipped",
            event=event,
            target_email=target_email,
            target_user_id=target_user_id,
            actor_email=actor_email,
            ip_address=ip_address,
            reason="smtp_not_configured",
        )
        return "skipped"

    subject, html, plain = render(
        event, actor_email=actor_email, ip_address=ip_address
    )
    service = AlertService(db, ip_address=ip_address or "internal:notification")
    try:
        accepted = await service.send_email(
            to=target_email, subject=subject, html_body=html, plain_body=plain
        )
        if not accepted:
            # The settings changed between the check above and the send (an
            # administrator cleared the SMTP host, say). "Not configured" is not
            # a delivery, and it is not worth a retry either.
            raise NotificationPermanent("smtp became unconfigured")
    except (AlertDeliveryPermanentError, NotificationPermanent, ValueError) as exc:
        await _record(
            db,
            "user.notification.failed",
            event=event,
            target_email=target_email,
            target_user_id=target_user_id,
            actor_email=actor_email,
            ip_address=ip_address,
            reason=sanitize_external_error(exc),
        )
        return "failed"
    except Exception as exc:  # transient: network, TLS, an ambiguous SMTP error
        if final_attempt:
            await _record(
                db,
                "user.notification.failed",
                event=event,
                target_email=target_email,
                target_user_id=target_user_id,
                actor_email=actor_email,
                ip_address=ip_address,
                reason=sanitize_external_error(exc),
            )
            return "failed"
        log.warning(
            "user_notification_retry",
            notification_event=event,
            error=type(exc).__name__,
        )
        return "retry"

    await _record(
        db,
        "user.notification.sent",
        event=event,
        target_email=target_email,
        target_user_id=target_user_id,
        actor_email=actor_email,
        ip_address=ip_address,
    )
    return "sent"


def render_invitation(
    *, invitation_url: str, expires_at: datetime, actor_email: str | None
) -> tuple[str, str, str]:
    """The invitation message — the one mail in the platform that carries a token.

    It does so because the token *is* the message: a single-use link whose only
    purpose is to let the owner choose their own password. It is not a credential
    to an existing account and it expires; the account-change notices elsewhere
    in this module stay token-free on purpose (RWI-15).
    """
    subject = "[OpenDRP] You have been invited"
    when = _readable(expires_at)
    actor = actor_email or "an administrator"
    html = jinja_env.get_template("emails/user_invitation.html").render(
        invitation_url=invitation_url,
        expires_at=when,
        actor_email=actor,
    )
    plain = (
        f"{subject}\n\n"
        f"{actor} created an OpenDRP account for this address.\n\n"
        "Choose your password here (single use, expires " + when + "):\n"
        f"{invitation_url}\n\n"
        "If you were not expecting this, contact your administrator and ignore "
        "the link. This message contains no password, and the platform will "
        "never ask you for one by mail.\n"
    )
    return subject, html, plain


async def deliver_user_invitation(
    db: AsyncSession,
    *,
    target_email: str,
    invitation_url: str | None,
    expires_at: datetime,
    actor_email: str | None = None,
    ip_address: str | None = None,
    final_attempt: bool = True,
) -> str:
    """Mail one invitation; ``sent``/``skipped``/``failed``/``retry``."""
    from app.services.alert_service import AlertDeliveryPermanentError, AlertService
    from app.services.settings_service import SettingsService

    settings_row = await SettingsService(db).get_singleton()
    if not (settings_row.smtp_host and settings_row.smtp_port):
        await _record(
            db, "user.invitation.skipped",
            event="invitation", target_email=target_email, target_user_id=None,
            actor_email=actor_email, ip_address=ip_address,
            reason="smtp_not_configured",
        )
        return "skipped"
    if not invitation_url:
        await _record(
            db, "user.invitation.skipped",
            event="invitation", target_email=target_email, target_user_id=None,
            actor_email=actor_email, ip_address=ip_address,
            reason="public_origin_not_configured",
        )
        return "skipped"

    subject, html, plain = render_invitation(
        invitation_url=invitation_url, expires_at=expires_at, actor_email=actor_email
    )
    service = AlertService(db, ip_address=ip_address or "internal:notification")
    try:
        await service.send_email(
            to=target_email, subject=subject, html_body=html, plain_body=plain
        )
    except (AlertDeliveryPermanentError, ValueError) as exc:
        await _record(
            db, "user.invitation.failed",
            event="invitation", target_email=target_email, target_user_id=None,
            actor_email=actor_email, ip_address=ip_address,
            reason=sanitize_external_error(exc),
        )
        return "failed"
    except Exception as exc:
        if final_attempt:
            await _record(
                db, "user.invitation.failed",
                event="invitation", target_email=target_email, target_user_id=None,
                actor_email=actor_email, ip_address=ip_address,
                reason=sanitize_external_error(exc),
            )
            return "failed"
        log.warning(
            "user_invitation_retry",
            notification_event="invitation",
            error=type(exc).__name__,
        )
        return "retry"

    await _record(
        db, "user.invitation.sent",
        event="invitation", target_email=target_email, target_user_id=None,
        actor_email=actor_email, ip_address=ip_address,
    )
    return "sent"


async def notify_invitation(
    db: AsyncSession,
    *,
    target_email: str,
    token: str,
    expires_at: datetime,
    actor_email: str | None,
    ip_address: str | None,
) -> bool:
    """Schedule the invitation mail, or record why it was not scheduled.

    Returns whether a message was queued, which the API reports so the
    administrator knows whether to hand the link on themselves.
    """
    from app.services.invitations import invitation_url
    from app.services.settings_service import SettingsService

    url = invitation_url(token)
    settings_row = await SettingsService(db).get_singleton()
    reason: str | None = None
    if not (settings_row.smtp_host and settings_row.smtp_port):
        reason = "smtp_not_configured"
    elif url is None:
        reason = "public_origin_not_configured"
    if reason is not None:
        await _record(
            db, "user.invitation.skipped",
            event="invitation", target_email=target_email, target_user_id=None,
            actor_email=actor_email, ip_address=ip_address, reason=reason,
        )
        return False

    from app.tasks.user_tasks import send_user_invitation_task

    try:
        send_user_invitation_task.apply_async(
            kwargs={
                "target_email": target_email,
                "invitation_url": url,
                "expires_at": expires_at.isoformat(),
                "actor_email": actor_email,
                "ip_address": ip_address,
            },
            queue="default",
            retry=False,
        )
    except Exception as exc:
        log.warning(
            "user_invitation_schedule_failed",
            notification_event="invitation",
            error=type(exc).__name__,
        )
        await _record(
            db, "user.invitation.failed",
            event="invitation", target_email=target_email, target_user_id=None,
            actor_email=actor_email, ip_address=ip_address,
            reason="celery_unavailable",
        )
        return False
    return True


async def notify_owner(
    db: AsyncSession,
    *,
    event: str,
    target_email: str,
    target_user_id: str | None,
    actor_email: str | None,
    ip_address: str | None,
) -> None:
    """Schedule the message after the mutation has committed.

    Never raises: the caller has already changed the account, and a broker that
    is down must not turn a successful reset into an error the administrator
    retries. The failure is recorded where the operator looks for it.
    """
    from app.services.settings_service import SettingsService

    # An installation without SMTP is not a failure to schedule: it is the answer.
    # Deciding it here keeps the broker out of the path entirely, so a deployment
    # that cannot send mail never accumulates retries it cannot satisfy.
    settings_row = await SettingsService(db).get_singleton()
    if not (settings_row.smtp_host and settings_row.smtp_port):
        await _record(
            db,
            "user.notification.skipped",
            event=event,
            target_email=target_email,
            target_user_id=target_user_id,
            actor_email=actor_email,
            ip_address=ip_address,
            reason="smtp_not_configured",
        )
        return

    from app.tasks.user_tasks import send_user_notification_task

    try:
        send_user_notification_task.apply_async(
            kwargs={
                "event": event,
                "target_email": target_email,
                "target_user_id": target_user_id,
                "actor_email": actor_email,
                "ip_address": ip_address,
            },
            queue="default",
            # One attempt at the broker, not the producer's default retry loop:
            # this runs inside the administrator's request, after the mutation has
            # committed, and a broker that is down must cost a recorded failure
            # rather than a request that hangs for minutes (D11).
            retry=False,
        )
    except Exception as exc:
        log.warning(
            "user_notification_schedule_failed",
            notification_event=event,
            error=type(exc).__name__,
        )
        await _record(
            db,
            "user.notification.failed",
            event=event,
            target_email=target_email,
            target_user_id=target_user_id,
            actor_email=actor_email,
            ip_address=ip_address,
            reason="celery_unavailable",
        )
