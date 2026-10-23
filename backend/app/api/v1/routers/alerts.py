"""Operational health checks for configured alert channels."""

import asyncio
import concurrent.futures
import smtplib
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, NamedTuple

import httpx
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_admin, require_active_account
from app.core.audit import AuditLogger
from app.core.exceptions import ConflictException, NotFoundException
from app.core.outbound import (
    TELEGRAM_API_HOST,
    OutboundBlocked,
    ensure_allowed,
    validate_telegram_token,
)
from app.core.config import settings as core_settings
from app.models.settings import SystemSettings
from app.schemas.common import HealthState
from app.services import alert_health_cache
from app.services.settings_service import SettingsService

router = APIRouter(prefix="/alerts", tags=["Alerts"])

# Bound SMTP probe work even when clients time out: cancelling an asyncio
# waiter cannot stop an in-progress synchronous socket operation. A slot is
# released only when the worker thread actually exits.
_SMTP_PROBE_MAX_WORKERS = 4
_SMTP_PROBE_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=_SMTP_PROBE_MAX_WORKERS,
    thread_name_prefix="smtp-health-probe",
)
_SMTP_PROBE_SLOTS = asyncio.Semaphore(_SMTP_PROBE_MAX_WORKERS)


class ProbeResult(NamedTuple):
    """What a channel probe found, plus *why* it was refused.

    ``health``, ``message`` and ``latency_ms`` are for the operator and are what
    the endpoint returns; ``blocked_reason`` is for the audit trail and is ``None``
    for every ordinary result, including an ordinary failure. The two audiences
    are the reason this is a record rather than the 3-tuple it used to be: the
    endpoint has to report a refused destination as `outbound.blocked`, and
    parsing that back out of the message string would make the audit record
    depend on prose.
    """

    health: str
    message: str
    latency_ms: int | None
    blocked_reason: str | None = None
    # How the probe itself fared, separate from what it found (D8). ``saturated``
    # means the pool had no free slot, so no observation of the channel was made;
    # reporting that as ``degraded`` blamed the channel for the probe's queue.
    probe_state: str = "ok"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _configured_smtp(s: SystemSettings) -> bool:
    return bool(s.smtp_host and s.smtp_port and (s.smtp_from_email_decrypted or s.smtp_user))


def _smtp_probe(s: SystemSettings) -> ProbeResult:
    """Probe the configured SMTP server.

    The refusal is reported rather than audited here: this function runs in a
    worker thread with no database session, so the endpoint records it.
    """
    if not _configured_smtp(s):
        return ProbeResult("not_configured", "SMTP settings are incomplete", None)
    # _configured_smtp guarantees host/port are set; local aliases narrow the
    # Optional types for the smtplib calls below.
    smtp_host = s.smtp_host or ""
    smtp_port = int(s.smtp_port or 0)
    started = time.perf_counter()
    try:
        # The destination policy, before any connection is attempted. A "SMTP
        # host" that is really the API's own address, PostgreSQL, or the cloud
        # metadata endpoint turns this probe into a way to map the deployment
        # from a settings page.
        addresses = ensure_allowed(smtp_host, port=smtp_port)
    except OutboundBlocked as blocked:
        return ProbeResult(
            "failed",
            f"SMTP destination refused ({blocked.reason})",
            int((time.perf_counter() - started) * 1000),
            blocked.reason,
        )
    try:
        mode = (getattr(s, "smtp_security_mode", None) or "starttls").lower()
        if mode not in {"starttls", "ssl", "plain"}:
            return ProbeResult("failed", "SMTP security mode is invalid", 0)
        if mode == "plain" and s.smtp_user and s.smtp_password_decrypted:
            return ProbeResult("failed", "SMTP credentials require TLS", 0)
        from app.core.outbound import pinned_smtp_class
        if mode == "ssl":
            with pinned_smtp_class(smtplib.SMTP_SSL, addresses, implicit_tls=True)(
                smtp_host,
                smtp_port,
                timeout=core_settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS,
                context=ssl.create_default_context(),
            ) as server:
                if s.smtp_user and s.smtp_password_decrypted:
                    server.login(s.smtp_user, s.smtp_password_decrypted)
            return ProbeResult(
                "healthy", "SMTP connection is available", int((time.perf_counter() - started) * 1000)
            )

        with pinned_smtp_class(smtplib.SMTP, addresses)(
            smtp_host,
            smtp_port,
            timeout=core_settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS,
        ) as server:
            if mode == "starttls":
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            if s.smtp_user and s.smtp_password_decrypted:
                server.login(s.smtp_user, s.smtp_password_decrypted)
        return ProbeResult(
            "healthy", "SMTP connection is available", int((time.perf_counter() - started) * 1000)
        )
    except (smtplib.SMTPAuthenticationError, smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        return ProbeResult(
            "failed",
            f"SMTP check failed: {type(exc).__name__}",
            int((time.perf_counter() - started) * 1000),
        )


def _telegram_configured(s: SystemSettings) -> bool:
    chats = list(s.telegram_chat_ids or [])
    return bool(s.telegram_bot_token_decrypted and chats)


async def _telegram_probe(s: SystemSettings) -> ProbeResult:
    if not _telegram_configured(s):
        return ProbeResult("not_configured", "Telegram settings are incomplete", None)
    started = time.perf_counter()
    try:
        # Validated again at use, not only where it was written: the stored value
        # is interpolated into the request URL, and a row restored from a backup
        # or written before the schema grew this check never passed it.
        token = validate_telegram_token(s.telegram_bot_token_decrypted)
    except ValueError as exc:
        return ProbeResult(
            "failed",
            f"Telegram credentials are unusable: {exc}",
            int((time.perf_counter() - started) * 1000),
            "invalid_telegram_token",
        )
    try:
        async with httpx.AsyncClient(timeout=core_settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS) as client:
            response = await client.get(f"https://{TELEGRAM_API_HOST}/bot{token}/getMe")
        latency = int((time.perf_counter() - started) * 1000)
        if response.status_code == 200:
            return ProbeResult("healthy", "Telegram API is reachable", latency)
        if response.status_code in (401, 403):
            return ProbeResult("failed", "Telegram credentials were rejected", latency)
        return ProbeResult("degraded", f"Telegram API returned HTTP {response.status_code}", latency)
    except (httpx.HTTPError, OSError) as exc:
        return ProbeResult(
            "failed",
            f"Telegram check failed: {type(exc).__name__}",
            int((time.perf_counter() - started) * 1000),
        )


async def _bounded_smtp_probe(s: SystemSettings, timeout: float) -> ProbeResult:
    """Run synchronous SMTP work with a hard queue and caller wait budget."""
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(_SMTP_PROBE_SLOTS.acquire(), timeout=timeout)
    except asyncio.TimeoutError:
        return ProbeResult(
            "unknown",
            "SMTP health check is busy; retry shortly",
            int(timeout * 1000),
            probe_state="saturated",
        )

    try:
        worker = _SMTP_PROBE_EXECUTOR.submit(_smtp_probe, s)
    except Exception:
        _SMTP_PROBE_SLOTS.release()
        raise

    worker.add_done_callback(lambda _future: loop.call_soon_threadsafe(_SMTP_PROBE_SLOTS.release))
    wrapped = asyncio.wrap_future(worker)
    done, _pending = await asyncio.wait({wrapped}, timeout=timeout)
    if not done:
        # Keep the slot occupied until the blocking socket work really finishes.
        # The bounded executor plus semaphore prevents timed-out calls from
        # generating an unbounded backlog of worker threads or queued probes.
        return ProbeResult(
            "failed", "SMTP health check timed out", int(timeout * 1000), probe_state="timeout"
        )
    try:
        return wrapped.result()
    except Exception as exc:
        return ProbeResult("failed", f"SMTP check failed: {type(exc).__name__}", int(timeout * 1000))


class AlertQueueItem(BaseModel):
    """One delivery in the operator's queue, newest last.

    `batch_id` is nullable although the client types it as a string: the column is
    nullable, the route copies it as-is, and a delivery created outside a batch sends
    `null`. Declaring it `str` would turn one such row into a 500 for the whole
    listing. `status` stays a string for the same reason a queue must not refuse to
    render: the state machine is the service's, and an unrecognised value is something
    an operator needs to see rather than a reason to hide the page.
    """

    id: str
    batch_id: str | None
    job_id: str | None
    channel: str
    status: str
    attempts: int
    acknowledged_parts: int
    #: How many parts the delivery was split into; `acknowledged_parts` says how many
    #: the provider accepted.
    parts: int
    last_error: str | None
    next_attempt_at: datetime | None


class AlertQueueSummary(BaseModel):
    """The queue's counters and its most recent rows.

    `counts` is keyed by the statuses the table actually holds — a map of what exists,
    not a model of every state the machine allows — so a new status appears here
    without a code change.
    """

    counts: dict[str, int]
    items: list[AlertQueueItem]


@router.get("/queue", response_model=AlertQueueSummary)
async def alert_queue_status(db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    """The queue's counters and its fifty newest deliveries, for an administrator."""
    from sqlalchemy import func, select
    from app.models.alert_delivery import AlertDelivery
    counts = (await db.execute(select(AlertDelivery.status, func.count(AlertDelivery.id)).group_by(AlertDelivery.status))).all()
    recent = (await db.execute(select(AlertDelivery).order_by(AlertDelivery.created_at.desc()).limit(50))).scalars().all()
    return AlertQueueSummary(
        counts={status: int(count) for status, count in counts},
        items=[
            AlertQueueItem(
                id=str(row.id),
                batch_id=row.batch_id,
                job_id=str(row.job_id) if row.job_id else None,
                channel=row.channel,
                status=row.status,
                attempts=row.attempts,
                acknowledged_parts=row.acknowledged_parts,
                parts=len(row.parts or []),
                last_error=row.last_error,
                next_attempt_at=row.next_attempt_at,
            )
            for row in recent
        ],
    )


@router.get("/recipients")
async def alert_recipient_holds(
    db: AsyncSession = Depends(get_db), user=Depends(require_admin)
):
    """Recipients the queue is holding back, and why each one is held.

    A delivery whose outcome is unknown — a worker died mid-send, or an SMTP
    thread timed out after the provider may already have accepted the message —
    holds its recipient for `ALERT_RECIPIENT_HOLD_SECONDS`, because retrying
    immediately could duplicate the notification. That hold used to have no end
    and no way out: the recipient stayed silent and the only remedy was SQL. This
    listing is what makes the hold visible, and `release` is what makes it
    something an operator can end early.
    """
    from app.services.alert_delivery_service import AlertDeliveryService

    return {"items": await AlertDeliveryService(db).held_recipients()}


@router.post("/recipients/{key}/release")
async def release_alert_recipient(
    request: Request,
    key: str,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_admin),
):
    """End a recipient's hold, and record who decided that.

    Requeuing an ambiguous delivery is the operator asserting they have
    reconciled it — usually by confirming with the recipient whether the message
    arrived. The other possible outcome of that assertion is a duplicate
    notification, which is why the decision is audited rather than merely
    applied.
    """
    from app.services.alert_delivery_service import AlertDeliveryService

    result = await AlertDeliveryService(db).release_recipient(key=key)
    if not result["found"]:
        raise NotFoundException("Unknown alert recipient")
    if not result["released"]:
        if result["reason"] == "not_held":
            raise NotFoundException("This recipient is not currently held")
        raise ConflictException(
            "A delivery worker is sending to this recipient right now; the lease "
            "ends within the delivery timeout"
        )
    await AuditLogger.emit_background(
        db,
        action="alerts.recipient.released",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={
            "recipient_key": key,
            "reason": result["reason"],
            "requeued_deliveries": result["requeued_deliveries"],
        },
    )
    return result


def _empty_delivery() -> dict:
    """The delivery aggregate of a channel with no queue rows.

    Always present with the same shape, so a card can print "queue empty"
    instead of guessing from a missing key, and the response keeps one shape
    for every channel and role.
    """
    return {
        "counts": {
            "pending": 0,
            "delivering": 0,
            "sent": 0,
            "failed": 0,
            "cancelled": 0,
            "ambiguous": 0,
        },
        "oldest_unresolved_at": None,
        "oldest_unresolved_age_seconds": None,
        "retrying": 0,
        "stuck": 0,
        "degraded_reason": None,
    }


def _health_with_delivery(health: str, delivery: dict) -> str:
    """A queue that cannot resolve itself degrades the channel.

    Only a probe that is otherwise ``healthy``/``degraded`` is overridden: a
    ``failed`` probe is already the more severe answer, and a disabled channel
    has no delivery obligation to degrade.
    """
    if delivery.get("degraded_reason") and health in {"healthy", "degraded"}:
        return "degraded"
    return health


@dataclass(frozen=True)
class ChannelState:
    """One channel's answer, including why its probe could not be made."""

    enabled: bool
    configured: bool
    health: str
    message: str
    latency_ms: int | None
    probe_state: str
    checked_at: str | None
    from_cache: bool
    blocked_reason: str | None = None


def _smtp_fingerprint(s: SystemSettings) -> str:
    """The SMTP settings an answer depends on, hashed.

    A changed host, port, mode, login or sender is a different question, so it
    must not be answered from the previous probe's cache entry.
    """
    return alert_health_cache.fingerprint(
        "email",
        s.smtp_host,
        s.smtp_port,
        getattr(s, "smtp_security_mode", None),
        s.smtp_user,
        s.smtp_password_decrypted,
        s.smtp_from_email_decrypted,
    )


def _telegram_fingerprint(s: SystemSettings) -> str:
    return alert_health_cache.fingerprint(
        "telegram", s.telegram_bot_token_decrypted, tuple(s.telegram_chat_ids or [])
    )


async def _email_state(
    s: SystemSettings, *, ttl_seconds: int, probe_timeout: float
) -> ChannelState:
    enabled = bool(s.email_alerts_enabled)
    configured = _configured_smtp(s)
    if not enabled:
        # Never dial a switched-off channel: the SMTP probe could block for its
        # whole budget, and the answer would be "disabled" either way.
        return ChannelState(
            enabled=False,
            configured=configured,
            health="disabled",
            message="Email alerts are disabled",
            latency_ms=None,
            probe_state="skipped",
            checked_at=None,
            from_cache=False,
        )
    outcome = await alert_health_cache.probe_with_cache(
        channel="email",
        fingerprint=_smtp_fingerprint(s),
        ttl_seconds=ttl_seconds,
        wait_budget_seconds=probe_timeout,
        probe=lambda: _bounded_smtp_probe(s, probe_timeout),
    )
    return ChannelState(
        enabled=True,
        configured=configured,
        health=outcome.health,
        message=outcome.message,
        latency_ms=outcome.latency_ms,
        probe_state=outcome.probe_state,
        checked_at=outcome.checked_at,
        from_cache=outcome.from_cache,
        blocked_reason=outcome.blocked_reason,
    )


async def _telegram_state(s: SystemSettings, *, ttl_seconds: int) -> ChannelState:
    enabled = bool(s.telegram_alerts_enabled)
    configured = _telegram_configured(s)
    if not enabled:
        # Same reason as email: no probe for a channel nobody switched on.
        return ChannelState(
            enabled=False,
            configured=configured,
            health="disabled",
            message="Telegram alerts are disabled",
            latency_ms=None,
            probe_state="skipped",
            checked_at=None,
            from_cache=False,
        )
    # Telegram has no admission pool, so the probe's own HTTP timeout is the
    # whole budget; the caller still gets the SMTP-shaped budget for the wait
    # after a concurrent probe, which can only be longer than this one.
    wait_budget = (
        float(core_settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS)
        + float(core_settings.OUTBOUND_DNS_TIMEOUT_SECONDS)
    )
    outcome = await alert_health_cache.probe_with_cache(
        channel="telegram",
        fingerprint=_telegram_fingerprint(s),
        ttl_seconds=ttl_seconds,
        wait_budget_seconds=wait_budget,
        probe=lambda: _telegram_probe(s),
    )
    return ChannelState(
        enabled=True,
        configured=configured,
        health=outcome.health,
        message=outcome.message,
        latency_ms=outcome.latency_ms,
        probe_state=outcome.probe_state,
        checked_at=outcome.checked_at,
        from_cache=outcome.from_cache,
        blocked_reason=outcome.blocked_reason,
    )


class AlertDeliveryCounts(BaseModel):
    """The queue's rows by status, one counter per state a delivery can be in."""

    pending: int
    delivering: int
    sent: int
    failed: int
    cancelled: int
    ambiguous: int


class AlertDeliverySummary(BaseModel):
    """One channel's delivery queue, beside its probe.

    A probe answers "can this installation reach the provider?"; this answers "are
    the messages leaving?". Both are published because a channel whose handshake
    succeeds can still hold a queue, and `degraded_reason` is how the payload says
    so without prose.
    """

    counts: AlertDeliveryCounts
    #: ISO text: the aggregate converts the timestamp itself, so the offset the
    #: database hands back does not reach the browser.
    oldest_unresolved_at: str | None
    oldest_unresolved_age_seconds: int | None
    retrying: int
    stuck: int
    degraded_reason: str | None


class AlertChannelHealth(BaseModel):
    """One alert channel's probe and queue, in the shape both readers get.

    `checked_at` is text because the probe and its cache write it as text, and
    `from_cache` is what tells a reader that a recent `checked_at` describes an
    earlier handshake rather than this request.
    """

    channel: str
    label: str
    enabled: bool
    configured: bool
    health: HealthState
    message: str
    latency_ms: int | None
    probe_state: Literal["ok", "saturated", "timeout", "skipped"]
    checked_at: str | None
    from_cache: bool
    delivery: AlertDeliverySummary


class AlertDeliveryQueue(BaseModel):
    """Holds and retry windows are keyed by a digest of channel+target, so the
    count is stated once for the installation rather than guessed per channel."""

    waiting_recipients: int


class AlertChannelsHealthResponse(BaseModel):
    """The alert-health envelope, shared by `/alerts/health` and the dashboard."""

    items: list[AlertChannelHealth]
    delivery_queue: AlertDeliveryQueue
    generated_at: datetime


async def channel_health_payload(
    db: AsyncSession,
) -> tuple[list[dict], dict, dict[str, str]]:
    """Probe both channels once and return what every reader needs.

    Shared by ``GET /alerts/health`` and the dashboard overview (DHP-10): the two
    must answer with the same probes, cache and delivery rules, and a page that
    asked the endpoint over HTTP would pay a second request and write a second
    audit row for the same observation.

    Returns ``(items, delivery_queue, blocked)``. Nothing here writes an audit
    row: a reading is not an event, so the caller decides what the trail records
    — the endpoint keeps its ``alerts.health.view`` entry, the overview records
    one ``dashboard.view`` for the whole page.
    """
    from app.services.alert_delivery_service import AlertDeliveryService
    from app.services.alert_service import AlertService

    s = await AlertService(db).detach_settings(await SettingsService(db).get_singleton())
    delivery_by_channel, waiting_recipients = await AlertDeliveryService(
        db
    ).channel_delivery_summary(stuck_after_seconds=int(core_settings.ALERT_RECIPIENT_HOLD_SECONDS))
    # The delivery read is over, so the transaction ends here, before any network
    # work (D9). `detach_settings` had already committed the settings snapshot;
    # this commit releases the connection the aggregate query used. An SMTP probe
    # may hold its worker for the whole budget, and a pooled connection must not
    # be held with it, or a slow mail server would look like database pressure.
    # The caller's audit rows open a new transaction.
    await db.commit()
    probe_timeout = (
        float(core_settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS)
        + float(core_settings.OUTBOUND_DNS_TIMEOUT_SECONDS)
    )
    ttl_seconds = int(core_settings.ALERT_HEALTH_CACHE_SECONDS)
    email, telegram = await asyncio.gather(
        _email_state(s, ttl_seconds=ttl_seconds, probe_timeout=probe_timeout),
        _telegram_state(s, ttl_seconds=ttl_seconds),
    )
    email_delivery = delivery_by_channel.get("email", _empty_delivery())
    telegram_delivery = delivery_by_channel.get("telegram", _empty_delivery())
    items = [
        {
            "channel": "email",
            "label": "Email / SMTP",
            "enabled": email.enabled,
            "configured": email.configured,
            "health": _health_with_delivery(email.health, email_delivery),
            "message": email.message,
            "latency_ms": email.latency_ms,
            "probe_state": email.probe_state,
            "checked_at": email.checked_at,
            "from_cache": email.from_cache,
            "delivery": email_delivery,
        },
        {
            "channel": "telegram",
            "label": "Telegram",
            "enabled": telegram.enabled,
            "configured": telegram.configured,
            "health": _health_with_delivery(telegram.health, telegram_delivery),
            "message": telegram.message,
            "latency_ms": telegram.latency_ms,
            "probe_state": telegram.probe_state,
            "checked_at": telegram.checked_at,
            "from_cache": telegram.from_cache,
            "delivery": telegram_delivery,
        },
    ]
    # A refused destination is a security event, not a configuration typo: it
    # means an operator-supplied host resolved into loopback, the cloud metadata
    # range, or one of this deployment's own networks.
    blocked = {
        channel: reason
        for channel, reason in (
            ("email", email.blocked_reason),
            ("telegram", telegram.blocked_reason),
        )
        if reason
    }
    # A hold or a retry window is per recipient key, and the key is a digest of
    # channel+target, which is deliberately not reversible. So this count is
    # stated once for the installation rather than split across channels by
    # guesswork.
    return items, {"waiting_recipients": waiting_recipients}, blocked


@router.get("/health")
async def alert_channels_health(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_active_account),
):
    items, delivery_queue, blocked = await channel_health_payload(db)
    await AuditLogger.emit_background(
        db,
        action="alerts.health.view",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"channels": {item["channel"]: item["health"] for item in items}},
    )
    if blocked:
        await AuditLogger.emit_background(
            db,
            action="outbound.blocked",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={"operation": "alert_channel_probe", "channels": blocked},
        )
    return {"items": items, "delivery_queue": delivery_queue, "generated_at": _now()}
