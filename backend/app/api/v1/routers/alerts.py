"""Operational health checks for configured alert channels."""

import asyncio
import concurrent.futures
import smtplib
import ssl
import time
from datetime import datetime, timezone
from typing import NamedTuple

import httpx
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_admin, require_viewer_plus
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


async def _skip_probe() -> ProbeResult:
    """Result for a channel an operator switched off.

    A disabled channel is not dialled at all. Probing it anyway is not merely
    wasted work: the SMTP probe blocks for up to
    ``ALERT_HEALTH_CHECK_TIMEOUT_SECONDS`` against an unreachable server, and the
    endpoint reports "disabled" regardless — so a switched-off channel could
    make the health response hang for the full timeout and say nothing useful at
    the end of it.
    """
    return ProbeResult("disabled", "", None)


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
        return ProbeResult("degraded", "SMTP health check is busy; retry shortly", int(timeout * 1000))

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
        return ProbeResult("failed", "SMTP health check timed out", int(timeout * 1000))
    try:
        return wrapped.result()
    except Exception as exc:
        return ProbeResult("failed", f"SMTP check failed: {type(exc).__name__}", int(timeout * 1000))


@router.get("/queue")
async def alert_queue_status(db: AsyncSession = Depends(get_db), user=Depends(require_admin)):
    from sqlalchemy import func, select
    from app.models.alert_delivery import AlertDelivery
    counts = (await db.execute(select(AlertDelivery.status, func.count(AlertDelivery.id)).group_by(AlertDelivery.status))).all()
    recent = (await db.execute(select(AlertDelivery).order_by(AlertDelivery.created_at.desc()).limit(50))).scalars().all()
    return {"counts": {status: count for status, count in counts}, "items": [{"id": str(row.id), "batch_id": row.batch_id, "job_id": str(row.job_id) if row.job_id else None, "channel": row.channel, "status": row.status, "attempts": row.attempts, "acknowledged_parts": row.acknowledged_parts, "parts": len(row.parts or []), "last_error": row.last_error, "next_attempt_at": row.next_attempt_at} for row in recent]}


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


@router.get("/health")
async def alert_channels_health(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    from app.services.alert_service import AlertService
    s = await AlertService(db).detach_settings(await SettingsService(db).get_singleton())
    probe_timeout = (
        float(core_settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS)
        + float(core_settings.OUTBOUND_DNS_TIMEOUT_SECONDS)
    )
    smtp_result, telegram_result = await asyncio.gather(
        _bounded_smtp_probe(s, probe_timeout)
        if s.email_alerts_enabled
        else _skip_probe(),
        _telegram_probe(s) if s.telegram_alerts_enabled else _skip_probe(),
    )
    items = [
        {
            "channel": "email",
            "label": "Email / SMTP",
            "enabled": bool(s.email_alerts_enabled),
            "configured": _configured_smtp(s),
            "health": "disabled" if not s.email_alerts_enabled else smtp_result.health,
            "message": "Email alerts are disabled" if not s.email_alerts_enabled else smtp_result.message,
            "latency_ms": smtp_result.latency_ms,
            "last_checked_at": _now() if s.email_alerts_enabled else None,
        },
        {
            "channel": "telegram",
            "label": "Telegram",
            "enabled": bool(s.telegram_alerts_enabled),
            "configured": _telegram_configured(s),
            "health": "disabled" if not s.telegram_alerts_enabled else telegram_result.health,
            "message": "Telegram alerts are disabled" if not s.telegram_alerts_enabled else telegram_result.message,
            "latency_ms": telegram_result.latency_ms,
            "last_checked_at": _now() if s.telegram_alerts_enabled else None,
        },
    ]
    await AuditLogger.emit_background(
        db,
        action="alerts.health.view",
        ip_address=extract_ip(request),
        user_id=user.id,
        details={"channels": {item["channel"]: item["health"] for item in items}},
    )
    # A refused destination is a security event, not a configuration typo: it
    # means an operator-supplied host resolved into loopback, the cloud metadata
    # range, or one of this deployment's own networks.
    blocked = {
        channel: reason
        for channel, reason in (
            ("email", smtp_result.blocked_reason),
            ("telegram", telegram_result.blocked_reason),
        )
        if reason
    }
    if blocked:
        await AuditLogger.emit_background(
            db,
            action="outbound.blocked",
            ip_address=extract_ip(request),
            user_id=user.id,
            details={"operation": "alert_channel_probe", "channels": blocked},
        )
    return {"items": items, "generated_at": _now()}
