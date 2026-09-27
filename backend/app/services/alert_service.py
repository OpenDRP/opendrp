import asyncio
import html
import json
import smtplib
import ssl
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Literal
from urllib.parse import quote, urlparse

import httpx
import structlog
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.ext.asyncio import AsyncSession
from tenacity import RetryCallState, retry, retry_if_exception_type, stop_after_attempt

from app.core.safe_errors import sanitize_external_error

from app import __version__
from app.core.audit import AuditLogger
from app.core.config import settings
from app.core.outbound import (
    TELEGRAM_API_HOST,
    OutboundBlocked,
    ensure_allowed,
    validate_telegram_token,
)
from app.services.settings_service import SettingsService

log = structlog.get_logger()


class AlertDeliveryTransientError(RuntimeError):
    """A provider/network failure that is safe to retry."""

    def __init__(self, message: str, *, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


def _alert_retry_wait(state: RetryCallState) -> float:
    """Honor provider Retry-After without losing the local exponential backoff."""
    exception = state.outcome.exception() if state.outcome else None
    retry_after = getattr(exception, "retry_after", None)
    if retry_after is not None:
        return min(max(float(retry_after), 0.0), 300.0)
    # Keep a bounded fallback for network failures that carry no provider hint.
    attempt = max(state.attempt_number - 1, 0)
    return min(max(settings.ALERT_DELIVERY_RETRY_BASE_SECONDS * (2**attempt), 1.0), 30.0)


class AlertDeliveryPermanentError(RuntimeError):
    """A configuration or provider rejection that must not be retried."""


#: Longest single value a delivered message prints before it is clipped. A
#: connector controls these strings, and one 4 KB "domain" must not be able to
#: push every other finding out of its own alert.
_MAX_FIELD_CHARS = 160
#: The same bound for values in the breakdown, which prints several per line.
_BREAKDOWN_CHARS = 80
#: How many distinct values a breakdown line counts before it counts the rest,
#: so a job that matched 400 assets does not print 400 of them.
_MAX_BREAKDOWN_VALUES = 4
#: Room kept for the "… +N more findings" line. It is what explains a truncated
#: list, so it is charged to the budget the list was built against.
_OMISSION_NOTE_RESERVE = 64
#: Hosts whose "link" would point at the reader's own machine rather than at
#: this installation.
# B104 is about binding a listener, not rejecting a URL host supplied as input.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})  # nosec B104
#: The finding list a delivered message links to, per threat type. A module
#: declared at runtime has its own page, named by its registry id.
_FINDING_PATHS = {"phishing": "/phishing", "breach": "/breaches"}
_BADGE_CLASSES = {"phishing": "badge-phishing", "breach": "badge-breach"}


def _clip(value: object, limit: int = _MAX_FIELD_CHARS) -> str:
    """One printable value: single line, bounded, and never a raw `None`."""
    text = " ".join(str("N/A" if value is None else value).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _escaped(value: object, limit: int = _MAX_FIELD_CHARS) -> str:
    """`_clip`, escaped for Telegram's HTML parse mode.

    Clipping happens before escaping on purpose: escaping first would let a slice
    cut `&amp;` in half, which Telegram reads as an unknown entity and rejects.
    """
    return html.escape(_clip(value, limit))


def _counted(values: list[str]) -> str:
    """`a × 3, b × 1`: most frequent first, the tail counted rather than listed."""
    ordered = sorted(Counter(values).items(), key=lambda item: (-item[1], item[0]))
    shown = [f"{value} × {count}" for value, count in ordered[:_MAX_BREAKDOWN_VALUES]]
    if len(ordered) > len(shown):
        shown.append(f"+{len(ordered) - len(shown)} more")
    return ", ".join(shown)


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _finding_path(threat_type: str) -> str:
    """The page a delivered message links to for this threat type."""
    if threat_type in _FINDING_PATHS:
        return _FINDING_PATHS[threat_type]
    if threat_type.startswith("module:"):
        module_id = threat_type.removeprefix("module:").strip()
        if module_id:
            return f"/modules/{quote(module_id, safe='')}"
    return "/dashboard"


@dataclass(frozen=True)
class _Notification:
    """One queued alert batch, in the neutral shape each channel renders.

    The module decides the content — which values identify a finding, and which
    of them are worth counting — while the channel decides the layout. That split
    is what lets a source onboarded as data reach an inbox or a chat without a
    line of per-source rendering code.
    """

    label: str
    subject: str
    job_id: str
    total: int
    included: int
    rows: list[dict[str, str]]
    groups: list[tuple[str, str]]
    link: str | None

    @property
    def columns(self) -> list[str]:
        """Every fact name the findings use, in the order they named them.

        A module declares its own fields, so two findings of one batch can carry
        different keys; the table shows the union rather than the first row's.
        """
        names: list[str] = []
        for row in self.rows:
            for name in row:
                if name not in names:
                    names.append(name)
        return names

    def table(self) -> list[list[str]]:
        """Rows aligned to `columns`, with a missing field shown as missing."""
        return [[row.get(name, "—") for name in self.columns] for row in self.rows]


def _telegram_finding_line(index: int, row: dict[str, str]) -> str:
    values = list(row.values())
    primary = _escaped(values[0]) if values else "N/A"
    details = [_escaped(value) for value in values[1:4]]
    tail = " · ".join(details)
    if len(values) > 4:
        tail += f" · +{len(values) - 4} more fields"
    return f"{index}. <code>{primary}</code>" + (f" — {tail}" if tail else "")


def _telegram_text(notification: _Notification) -> str:
    """Render the summary Telegram receives, inside Telegram's own limits.

    Telegram answers a message it cannot parse (unbalanced or sliced markup) or
    one it considers too long with `400`, which the delivery queue records as a
    permanent failure — an alert lost to a length check rather than to an outage.
    So this never slices markup it built: the finding list is dropped line by
    line against a budget that already reserved the footer and the note saying
    how many findings were left out.
    """
    lines = [f"🚨 <b>OpenDRP {html.escape(notification.label.upper())}</b>"]
    counted = f"<b>{_plural(notification.total, 'new finding')}</b>"
    if notification.included < notification.total:
        counted += f" · showing {notification.included}"
    lines.append(counted)
    if notification.groups:
        lines.append("")
        lines.extend(
            f"<b>{html.escape(name)}:</b> {html.escape(summary)}"
            for name, summary in notification.groups
        )
    if notification.rows:
        lines.append("")
        lines.append("<b>Findings</b>")
    footer = [f"Job <code>{html.escape(notification.job_id)}</code>"]
    if notification.link:
        footer.append(
            f'🔗 <a href="{html.escape(notification.link, quote=True)}">Open in OpenDRP</a>'
        )
    footer_text = "\n".join(footer)
    budget = (
        settings.ALERT_MAX_TELEGRAM_MESSAGE_LENGTH
        - _OMISSION_NOTE_RESERVE
        - len(footer_text)
        - 1
    )
    text = "\n".join(lines)
    kept = 0
    for index, row in enumerate(notification.rows, start=1):
        line = _telegram_finding_line(index, row)
        if len(text) + 1 + len(line) > budget:
            break
        text = f"{text}\n{line}"
        kept += 1
    if kept < len(notification.rows):
        missing = len(notification.rows) - kept
        text += f"\n… +{_plural(missing, 'more finding')} in OpenDRP"
    return f"{text}\n\n{footer_text}"


def _plain_text(notification: _Notification) -> str:
    """The `text/plain` alternative: the same facts, readable without HTML."""
    lines = [notification.subject, ""]
    lines.append(f"Job: {notification.job_id}")
    counted = f"Findings: {notification.total}"
    if notification.included < notification.total:
        counted += f" (showing the first {notification.included})"
    lines.append(counted)
    lines.extend(f"{name}: {summary}" for name, summary in notification.groups)
    if notification.rows:
        lines.append("")
        for index, row in enumerate(notification.rows, start=1):
            facts = "  ".join(f"{name}={_clip(value)}" for name, value in row.items())
            lines.append(f"{index:>3}. {facts}")
    if notification.link:
        lines.extend(["", f"Open in OpenDRP: {notification.link}"])
    return "\n".join(lines)


class AlertService:
    def __init__(self, db: AsyncSession):
        self.db = db

    jinja_env: Environment = Environment(
        loader=FileSystemLoader("app/templates"),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )

    def _render_template(self, name: str, **ctx) -> str:
        tpl = self.jinja_env.get_template(name)
        # No default platform address: an alert rendered without one must not ask
        # the reader's browser to open `localhost`, which is their own machine.
        ctx.setdefault("dashboard_url", None)
        return tpl.render(**ctx)

    async def _get_settings(self):
        return await SettingsService(self.db).get_singleton()

    async def _audit_alert(self, *, action: str, channel: str, details: dict) -> None:
        try:
            await AuditLogger.emit_background(
                self.db,
                action=action,
                ip_address="internal:alert-service",
                user_id=None,
                details={"channel": channel, **details},
            )
        except Exception:
            pass

    @retry(
        retry=retry_if_exception_type(AlertDeliveryTransientError),
        stop=stop_after_attempt(settings.ALERT_DELIVERY_MAX_ATTEMPTS),
        wait=_alert_retry_wait,
        reraise=True,
    )
    async def _send_email_smtp(
        self,
        *,
        to: str,
        subject: str,
        html_body: str,
        plain_body: str | None = None,
    ) -> bool:
        s = await self._get_settings()
        if not s.smtp_host:
            return False
        # The destination policy, before the connection. Alert delivery runs in
        # the worker, which sits on the same network as PostgreSQL and Redis and
        # can reach a cloud host's metadata endpoint — so "the SMTP host from the
        # settings page" must not be an operator-chosen route into either.
        try:
            ensure_allowed(s.smtp_host, port=int(s.smtp_port or 0))
        except OutboundBlocked as blocked:
            log.warning(
                "outbound_blocked",
                operation="alert_email",
                **blocked.as_audit_details(),
            )
            await self._audit_alert(
                action="outbound.blocked",
                channel="email",
                details={"operation": "alert_email", **blocked.as_audit_details()},
            )
            return False
        from_addr = s.smtp_from_email_decrypted or s.smtp_user or "opendrp@localhost"
        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to
        msg["Subject"] = subject
        # Was `settings.__version__` behind a hasattr check: Settings has no such
        # attribute, so every alert ever sent announced itself as OpenDRP/1.0.0
        # while the platform was 0.1.0. The version lives in app/__init__.py.
        msg["X-Mailer"] = f"OpenDRP/{__version__}"
        msg.set_content(plain_body or "OpenDRP alert notification.")
        msg.add_alternative(html_body, subtype="html")

        def _send_sync():
            configured_mode = getattr(s, "smtp_security_mode", None)
            mode = (configured_mode or ("ssl" if s.smtp_port == 465 else "starttls")).lower()
            if mode not in {"starttls", "ssl", "plain"}:
                raise AlertDeliveryPermanentError("smtp security mode is invalid")
            if mode == "ssl":
                connection = smtplib.SMTP_SSL(
                    s.smtp_host,
                    s.smtp_port,
                    context=ssl.create_default_context(),
                    timeout=settings.ALERT_DELIVERY_TIMEOUT_SECONDS,
                )
            else:
                connection = smtplib.SMTP(
                    s.smtp_host,
                    s.smtp_port,
                    timeout=settings.ALERT_DELIVERY_TIMEOUT_SECONDS,
                )
            with connection as server:
                if mode == "starttls":
                    server.ehlo()
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                if s.smtp_user and s.smtp_password_decrypted:
                    server.login(s.smtp_user, s.smtp_password_decrypted)
                server.send_message(msg)

        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, _send_sync),
                timeout=settings.ALERT_DELIVERY_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError as exc:
            raise AlertDeliveryTransientError("smtp delivery timed out") from exc
        except smtplib.SMTPAuthenticationError as exc:
            raise AlertDeliveryPermanentError("smtp authentication failed") from exc
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as exc:
            raise AlertDeliveryPermanentError("smtp recipient or sender rejected") from exc
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            raise AlertDeliveryTransientError(
                f"smtp {type(exc).__name__}"
            ) from exc
        log.info("alert_email_sent", to=to, subject=subject)
        await self._audit_alert(
            action="alert.dispatch.success",
            channel="email",
            details={"to": to, "subject": subject[:120]},
        )
        return True

    @retry(
        retry=retry_if_exception_type(AlertDeliveryTransientError),
        stop=stop_after_attempt(settings.ALERT_DELIVERY_MAX_ATTEMPTS),
        wait=_alert_retry_wait,
        reraise=True,
    )
    async def _send_telegram(self, text: str, parse_mode: str = "HTML", chat_id: str | None = None) -> bool:
        """Send to exactly one chat, named by the caller.

        The recipient is a parameter and never a fallback to a setting: the
        callers fan out over ``_resolve_telegram_chats()``, so resolving the
        destination here a second time would let a chat ID that resolution
        deliberately skipped (channel disabled, entry deduplicated) receive an
        alert anyway.
        """
        s = await self._get_settings()
        token = s.telegram_bot_token_decrypted
        chat = chat_id
        if not token or not chat:
            return False
        # The token is interpolated into the URL path, so it is validated here as
        # well as where it was written: `123:@evil.example/x` is shaped like a
        # token and would send every alert to an operator-chosen host.
        try:
            token = validate_telegram_token(token)
        except ValueError as exc:
            log.warning("outbound_blocked", operation="alert_telegram", reason=str(exc)[:120])
            await self._audit_alert(
                action="outbound.blocked",
                channel="telegram",
                details={"operation": "alert_telegram", "reason": "invalid_telegram_token"},
            )
            return False
        url = f"https://{TELEGRAM_API_HOST}/bot{token}/sendMessage"
        payload = {
            "chat_id": chat,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }
        async with httpx.AsyncClient(timeout=settings.ALERT_DELIVERY_TIMEOUT_SECONDS) as client:
            try:
                r = await asyncio.wait_for(
                    client.post(url, json=payload),
                    timeout=settings.ALERT_DELIVERY_TIMEOUT_SECONDS,
                )
            except (asyncio.TimeoutError, httpx.TimeoutException, httpx.NetworkError) as exc:
                raise AlertDeliveryTransientError("telegram delivery temporarily unavailable") from exc
            if r.status_code != 200:
                status = int(r.status_code)
                if status == 429 or status >= 500 or status in {408}:
                    retry_after = r.headers.get("Retry-After") if hasattr(r, "headers") else None
                    retry_delay = None
                    if retry_after:
                        try:
                            retry_delay = float(retry_after)
                        except (TypeError, ValueError):
                            retry_delay = None
                    suffix = f" retry_after={retry_after}" if retry_after else ""
                    raise AlertDeliveryTransientError(f"TG {status}{suffix}", retry_after=retry_delay)
                raise AlertDeliveryPermanentError(
                    f"telegram HTTP {status}: {self._telegram_provider_error(r)[0]}"
                )
        log.info("alert_telegram_sent", chat_id=chat)
        await self._audit_alert(
            action="alert.dispatch.success",
            channel="telegram",
            details={"chat_id": str(chat), "text_len": len(text)},
        )
        return True

    @staticmethod
    def _telegram_provider_error(response) -> tuple[str, str]:
        """Map a Telegram error to a stable, safe operator-facing result."""
        status = int(getattr(response, "status_code", 0) or 0)
        description = ""
        raw_text = str(getattr(response, "text", "") or "")
        try:
            payload = json.loads(raw_text)
            description = str(payload.get("description", ""))
        except (TypeError, ValueError):
            description = ""
        lower = description.lower()
        if status == 401:
            return "invalid_token", "Telegram rejected the bot token."
        if status == 429:
            return "rate_limited", "Telegram rate-limited this check. Try again later."
        if status == 403 and "blocked" in lower:
            return "bot_blocked", "The user has blocked this bot."
        if status == 403 and ("administrator" in lower or "rights" in lower):
            return "insufficient_rights", "The bot does not have sufficient rights in this chat."
        if status in (400, 403) and ("not found" in lower or "chat not found" in lower):
            return "chat_not_found", "Telegram cannot find this chat or the bot cannot access it."
        if status >= 500 or status == 0:
            return "provider_unavailable", "Telegram is temporarily unavailable. Try again later."
        return "telegram_error", "Telegram rejected this chat check. Verify the chat ID and bot membership."

    @staticmethod
    def _telegram_chat_result(chat: str, response) -> dict:
        if getattr(response, "status_code", 0) == 200:
            try:
                payload = json.loads(str(getattr(response, "text", "") or "{}"))
            except (TypeError, ValueError):
                payload = {}
            result = payload.get("result") if isinstance(payload, dict) else {}
            result = result if isinstance(result, dict) else {}
            return {
                "chat_id": chat,
                "ok": True,
                "chat_type": result.get("type"),
                "username": result.get("username"),
                "title": result.get("title"),
            }
        code, message = AlertService._telegram_provider_error(response)
        return {"chat_id": chat, "ok": False, "error_code": code, "error": message}

    async def validate_telegram_chats(self, s, chat_id: str | None = None) -> dict:
        """Validate configured chats with getChat without exposing the bot token."""
        from app.core.exceptions import BadRequestException

        token = s.telegram_bot_token_decrypted
        if not token:
            raise BadRequestException("telegram_bot_token is not configured")
        try:
            token = validate_telegram_token(token)
        except ValueError as exc:
            raise BadRequestException(f"telegram_bot_token is unusable: {exc}") from exc
        chats = [chat_id] if chat_id else self._resolve_telegram_chats(s, include_disabled=True)
        if not chats:
            raise BadRequestException("No Telegram chat IDs configured")

        results: list[dict] = []
        async with httpx.AsyncClient(timeout=settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS) as client:
            for chat in chats:
                try:
                    response = await client.get(
                        f"https://{TELEGRAM_API_HOST}/bot{token}/getChat",
                        params={"chat_id": chat},
                    )
                    results.append(self._telegram_chat_result(chat, response))
                except (httpx.HTTPError, OSError):
                    results.append({
                        "chat_id": chat,
                        "ok": False,
                        "error_code": "provider_unavailable",
                        "error": "Telegram is temporarily unavailable. Try again later.",
                    })
        valid = sum(1 for result in results if result["ok"])
        await self._audit_alert(
            action="settings.telegram.validate",
            channel="telegram-validation",
            details={"total": len(results), "valid": valid, "invalid": len(results) - valid},
        )
        return {"valid": valid, "total": len(results), "results": results}

    async def send_test_telegram(self, s, chat_id: str | None = None) -> dict:
        """Validate chats first, then send only to chats Telegram can access."""
        validation = await self.validate_telegram_chats(s, chat_id)
        token = validate_telegram_token(s.telegram_bot_token_decrypted)
        text = (
            "✅ <b>OpenDRP test message</b>\n\n"
            "Your Telegram alert channel is configured correctly.\n"
            f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )
        results: list[dict] = []
        async with httpx.AsyncClient(timeout=settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS) as client:
            for validation_result in validation["results"]:
                if not validation_result["ok"]:
                    results.append(validation_result)
                    continue
                chat = validation_result["chat_id"]
                try:
                    response = await client.post(
                        f"https://{TELEGRAM_API_HOST}/bot{token}/sendMessage",
                        json={
                            "chat_id": chat,
                            "text": text,
                            "parse_mode": "HTML",
                            "disable_web_page_preview": True,
                        },
                    )
                    if response.status_code == 200:
                        results.append({"chat_id": chat, "ok": True})
                    else:
                        code, message = self._telegram_provider_error(response)
                        results.append({"chat_id": chat, "ok": False, "error_code": code, "error": message})
                except (httpx.HTTPError, OSError):
                    results.append({
                        "chat_id": chat,
                        "ok": False,
                        "error_code": "provider_unavailable",
                        "error": "Telegram is temporarily unavailable. Try again later.",
                    })
        ok_count = sum(1 for result in results if result["ok"])
        await self._audit_alert(
            action="alert.test_sent" if ok_count else "alert.dispatch.failed",
            channel="telegram-test",
            details={"sent": ok_count, "total": len(results), "validation_failed": validation["total"] - validation["valid"]},
        )
        return {
            "sent": ok_count,
            "total": len(results),
            "validated": validation["valid"],
            "validation_failed": validation["total"] - validation["valid"],
            "results": results,
        }

    async def _resolve_email_recipients(self, s) -> list[str]:
        """Deduped email recipient list: selected platform users + custom address.

        Empty when the email channel is disabled.
        """
        if not getattr(s, "email_alerts_enabled", False):
            return []
        recipients: list[str] = []
        user_ids = getattr(s, "alert_email_user_ids", None) or []
        if user_ids:
            from sqlalchemy import select
            from app.models.user import User

            try:
                ids = [uid for uid in user_ids if str(uid).strip()]
                if ids:
                    result = await self.db.execute(
                        select(User.email).where(
                            User.id.in_([__import__("uuid").UUID(u) for u in ids]),
                            User.is_active.is_(True),
                        )
                    )
                    recipients.extend(r[0] for r in result.all())
            except Exception as e:
                log.warning("alert_email_user_lookup_failed", err=str(e)[:200])
        custom = s.alert_recipient_email_decrypted
        if custom:
            recipients.append(custom)
        # Dedupe preserving order, lowercase-normalized for emails.
        seen: set[str] = set()
        out: list[str] = []
        for r in recipients:
            key = r.strip().lower()
            if key and key not in seen:
                seen.add(key)
                out.append(r.strip())
        return out

    def _resolve_telegram_chats(self, s, *, include_disabled: bool = False) -> list[str]:
        """Deduped Telegram chat list; empty when the channel is disabled.

        ``include_disabled`` is used by the test-send path, which validates the
        configured chats even while the channel is still switched off.
        """
        if not include_disabled and not getattr(s, "telegram_alerts_enabled", False):
            return []
        chats = list(getattr(s, "telegram_chat_ids", None) or [])
        seen: set[str] = set()
        out: list[str] = []
        for c in chats:
            c = str(c).strip()
            if c and c not in seen:
                seen.add(c)
                out.append(c)
        return out

    def _platform_link(self, threat_type: str) -> str | None:
        """Where a delivered message links back to, when the platform knows.

        `CORS_ORIGINS` is the one place an installation records the origin its
        users open the UI under, and the only origin their browser sends. A
        loopback entry is skipped rather than preferred: an alert is read on a
        phone or in a mail client, and a link to `localhost` sends the reader to
        their own computer. No usable origin means no link, never a guessed one.
        """
        for origin in getattr(settings, "CORS_ORIGINS", None) or []:
            candidate = str(origin).strip().rstrip("/")
            parsed = urlparse(candidate)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            if (parsed.hostname or "").lower() in _LOOPBACK_HOSTS:
                continue
            return f"{candidate}{_finding_path(threat_type)}"
        return None

    def _facts(
        self, threat_type: str, item: dict
    ) -> tuple[dict[str, str], dict[str, str]]:
        """What a message says about one finding, and what the summary counts.

        The module decides both, not the alert path: the two built-in modules
        name their neutral fields, and a module declared at runtime contributes
        the fields it declared — which is what lets a source onboarded as data
        arrive in an operator's inbox without a line of rendering code. The
        second half holds only what a count is useful for; a module that names
        nothing there is simply not broken down.
        """
        if threat_type == "phishing":
            return (
                {
                    "Domain": item.get("phishing_domain") or "N/A",
                    "Matched asset": item.get("matched_asset") or "N/A",
                    "Source": item.get("detection_source") or "N/A",
                },
                {
                    "Source": item.get("detection_source") or "N/A",
                    "Matched asset": item.get("matched_asset") or "N/A",
                },
            )
        if threat_type == "breach":
            return (
                {
                    "Breach": item.get("breach_name") or "N/A",
                    "Account": item.get("matched_email")
                    or item.get("matched_domain")
                    or "N/A",
                    "Domain": item.get("domain") or "N/A",
                },
                {
                    "Breach": item.get("breach_name") or "N/A",
                    "Domain": item.get("domain") or "N/A",
                },
            )
        declared = item.get("fields")
        facts: dict[str, str] = {"Finding": item.get("title") or "N/A"}
        if isinstance(declared, dict):
            facts.update({str(key): value for key, value in declared.items()})
        return facts, {}

    def _build_notification(
        self,
        *,
        threat_type: str,
        label: str,
        subject: str,
        findings: list[dict],
        bounded: list[dict],
        job_id,
        link: str | None,
    ) -> _Notification:
        """Turn one queued batch into the neutral shape every channel renders."""
        rows: list[dict[str, str]] = []
        counted: dict[str, list[str]] = {}
        for item in bounded:
            row, groups = self._facts(threat_type, item)
            rows.append(row)
            for group_label, value in groups.items():
                counted.setdefault(group_label, []).append(_clip(value, _BREAKDOWN_CHARS))
        return _Notification(
            label=label,
            subject=subject,
            job_id=str(job_id) if job_id else "unrecorded",
            total=len(findings),
            included=len(bounded),
            rows=rows,
            groups=[(name, _counted(values)) for name, values in counted.items()],
            link=link,
        )

    async def send_aggregated_alert_notification(
        self,
        *,
        threat_type: str,
        findings: list[dict],
        job_id=None,
        channel: Literal["email", "telegram"],
        target: str | None = None,
    ) -> dict:
        """Deliver one bounded summary to exactly one channel.

        The queue owns retry state and queues per channel, so a call names the
        channel it is delivering: a successful email and a failed Telegram
        delivery are two rows with two lifecycles, never one. This method raises
        only when every destination of that channel failed, allowing the queue to
        retry without duplicating a delivery that already succeeded. Provider
        error text is sanitized before logging.
        """
        s = await self._get_settings()
        email_recipients = (
            [target]
            if channel == "email" and target
            else await self._resolve_email_recipients(s)
            if channel == "email"
            else []
        )
        telegram_chats = (
            [target]
            if channel == "telegram" and target
            else self._resolve_telegram_chats(s)
            if channel == "telegram"
            else []
        )
        bounded = findings[: settings.ALERT_MAX_FINDINGS_PER_MESSAGE]
        total = len(findings)
        label = (
            "Phishing"
            if threat_type == "phishing"
            else "Credential breach"
            if threat_type == "breach"
            else threat_type.removeprefix("module:")
        )
        subject = f"[OpenDRP Alert] {label}: {_plural(total, 'new finding')}"
        notification = self._build_notification(
            threat_type=threat_type,
            label=label,
            subject=subject,
            findings=findings,
            bounded=bounded,
            job_id=job_id,
            link=self._platform_link(threat_type),
        )
        email_html = self._render_template(
            "emails/finding_summary.html",
            module_label=notification.label,
            title=notification.subject,
            badge_class=_BADGE_CLASSES.get(threat_type, ""),
            dashboard_url=notification.link,
            job_id=notification.job_id,
            total=notification.total,
            included=notification.included,
            groups=notification.groups,
            columns=notification.columns,
            rows=notification.table(),
        )
        plain = _plain_text(notification)
        sent = 0
        failures: list[Exception] = []
        for recipient in email_recipients:
            try:
                delivered = await self._send_email_smtp(
                    to=recipient,
                    subject=subject,
                    html_body=email_html,
                    plain_body=plain,
                )
                if delivered:
                    sent += 1
                else:
                    failures.append(RuntimeError("email provider did not accept the message"))
            except Exception as exc:
                failures.append(exc)
        telegram_text = _telegram_text(notification)
        for chat in telegram_chats:
            try:
                delivered = await self._send_telegram(telegram_text, chat_id=chat)
                if delivered:
                    sent += 1
                else:
                    failures.append(RuntimeError("Telegram provider did not accept the message"))
            except Exception as exc:
                failures.append(exc)
        configured = len(email_recipients) + len(telegram_chats)
        # Queue rows are channel-specific. Require every recipient of this
        # channel to succeed; otherwise the whole channel row is retried while
        # already successful channels remain independently marked as sent.
        if configured and sent < configured:
            error = sanitize_external_error(failures[-1] if failures else "no destination accepted the alert")
            await self._audit_alert(
                action="alert.dispatch.failed",
                channel=channel,
                details={"threat_type": threat_type, "job_id": str(job_id) if job_id else None, "count": total, "error": error},
            )
            raise RuntimeError(error)
        await self._audit_alert(
            action="alert.dispatch.success",
            channel=channel,
            details={"threat_type": threat_type, "job_id": str(job_id) if job_id else None, "count": total, "sent": sent, "failed": len(failures)},
        )
        return {"sent": sent, "failed": len(failures), "total": configured, "findings": total}

    async def send_operator_message(
        self, *, subject: str, html_body: str, plain_body: str | None = None
    ) -> dict:
        """Send an operational message about the platform itself.

        Distinct from a finding alert: no threat template, no per-finding
        deduplication, just the operator's already-configured channels — the
        people who would have to act on "the audit chain does not verify".
        Delivery results are returned rather than raised so that a caller whose
        job is to *record* the failure is not stopped by a channel being down.
        """
        s = await self._get_settings()
        recipients = (
            await self._resolve_email_recipients(s) if s.email_alerts_enabled else []
        )
        chats = self._resolve_telegram_chats(s) if s.telegram_alerts_enabled else []
        email_sent = False
        telegram_sent = False
        errors: list[str] = []

        for to in recipients:
            try:
                sent = await self._send_email_smtp(
                    to=to, subject=subject, html_body=html_body, plain_body=plain_body
                )
                email_sent = sent or email_sent
            except Exception as exc:
                errors.append(f"email:{type(exc).__name__}")

        text = f"⚠️ <b>{html.escape(subject)}</b>\n\n{html.escape(plain_body or subject)}"
        for chat in chats:
            try:
                sent = await self._send_telegram(text, chat_id=chat)
                telegram_sent = sent or telegram_sent
            except Exception as exc:
                errors.append(f"telegram:{type(exc).__name__}")

        return {
            "email_sent": email_sent,
            "telegram_sent": telegram_sent,
            "email_recipients": len(recipients),
            "telegram_chats": len(chats),
            "errors": errors[:5],
        }
