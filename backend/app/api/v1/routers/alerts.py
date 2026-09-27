"""Operational health checks for configured alert channels."""

import asyncio
import smtplib
import ssl
import time
from datetime import datetime, timezone
from typing import NamedTuple

import httpx
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import extract_ip, get_db, require_viewer_plus
from app.core.audit import AuditLogger
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
        ensure_allowed(smtp_host, port=smtp_port)
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
        if mode == "ssl":
            with smtplib.SMTP_SSL(
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

        with smtplib.SMTP(
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


@router.get("/health")
async def alert_channels_health(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_viewer_plus),
):
    s = await SettingsService(db).get_singleton()
    async def bounded_smtp_probe() -> ProbeResult:
        if not s.email_alerts_enabled:
            return await _skip_probe()
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(_smtp_probe, s),
                timeout=(
                    core_settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS
                    + float(core_settings.OUTBOUND_DNS_TIMEOUT_SECONDS)
                ),
            )
        except asyncio.TimeoutError:
            return ProbeResult(
                "failed",
                "SMTP health check timed out",
                int((core_settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS + float(core_settings.OUTBOUND_DNS_TIMEOUT_SECONDS)) * 1000),
            )

    smtp_result, telegram_result = await asyncio.gather(
        bounded_smtp_probe(),
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
            "last_checked_at": _now(),
        },
        {
            "channel": "telegram",
            "label": "Telegram",
            "enabled": bool(s.telegram_alerts_enabled),
            "configured": _telegram_configured(s),
            "health": "disabled" if not s.telegram_alerts_enabled else telegram_result.health,
            "message": "Telegram alerts are disabled" if not s.telegram_alerts_enabled else telegram_result.message,
            "latency_ms": telegram_result.latency_ms,
            "last_checked_at": _now(),
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
