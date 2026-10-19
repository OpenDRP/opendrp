import asyncio
import html
import json
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Literal
from urllib.parse import urlparse

import httpx
import structlog
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.ext.asyncio import AsyncSession
from types import SimpleNamespace

from app.services.alert_content import fact_text, safe_snapshot, telegram_parts
from app.services.alert_facts import message_facts, stored_message_facts
from app.services.alert_transport import (
    AlertDeliveryAmbiguousError as AlertDeliveryAmbiguousError,
    AlertDeliveryCancelledError as AlertDeliveryCancelledError,
    AlertDeliveryPermanentError as AlertDeliveryPermanentError,
    AlertDeliveryTransientError as AlertDeliveryTransientError,
    _SMTP_SLOTS as _SMTP_SLOTS,
    alert_retry_wait,
    bounded_smtp as bounded_smtp,
)
from app.services.alert_message import (
    BADGE_CLASSES,
    BREAKDOWN_CHARS,
    LOOPBACK_HOSTS,
    Notification,
    breach_subject_class,
    clip,
    counted,
    declared_column,
    digest_heading as digest_heading,
    finding_path,
    highest_severity,
    plain_text,
    plural,
)
from app.services.alert_routing import (
    PhishingRoute as PhishingRoute,
    phishing_alert_route as phishing_alert_route,
)

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

#: Historical private names: the message layer used to live in this module, and a
#: caller (or a test) that reached for one of these should not have to learn a
#: second import path in the same release. Remove with the next major version.
_Notification = Notification
_plain_text = plain_text
_highest_severity = highest_severity
_breach_subject_class = breach_subject_class
_alert_retry_wait = alert_retry_wait


class AlertService:
    def __init__(self, db: AsyncSession, *, user_id=None, ip_address="internal:alert-service"):
        self.db = db
        self.user_id = user_id
        self.ip_address = ip_address

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
        snapshot = getattr(self, "_settings_snapshot", None)
        if snapshot is not None:
            return snapshot
        return await SettingsService(self.db).get_singleton()

    async def detach_settings(self, row=None):
        row = row or await self._get_settings()
        names = ("smtp_host", "smtp_port", "smtp_security_mode", "smtp_user", "smtp_password_decrypted", "smtp_from_email_decrypted", "telegram_bot_token_decrypted", "alert_recipient_email_decrypted", "email_alerts_enabled", "telegram_alerts_enabled", "alert_email_user_ids", "telegram_chat_ids")
        self._settings_snapshot = SimpleNamespace(**{name: getattr(row, name, None) for name in names})
        await self.db.commit()
        return self._settings_snapshot

    async def _audit_alert(self, *, action: str, channel: str, details: dict) -> None:
        try:
            await AuditLogger.emit_background(
                self.db,
                action=action,
                ip_address=self.ip_address,
                user_id=self.user_id,
                details={"channel": channel, **details},
            )
        except Exception:
            pass

    async def send_email(
        self,
        *,
        to: str,
        subject: str,
        html_body: str,
        plain_body: str | None = None,
    ) -> bool:
        """Send one message through the alert transport, as a non-alert.

        Opening this door rather than a second SMTP path keeps TLS rules, the
        timeout, credential handling and the outbound destination policy in one
        place (RWI-15). ``audit=False`` is what makes the rows that accompany it
        honest: the account-change notice records ``user.notification.*``, and a
        ``alert.dispatch.success`` row for a password-reset mail would describe it
        as a finding alert.
        """
        return await self._send_email_smtp(
            to=to,
            subject=subject,
            html_body=html_body,
            plain_body=plain_body,
            audit=False,
        )

    async def _send_email_smtp(
        self,
        *,
        to: str,
        subject: str,
        html_body: str,
        plain_body: str | None = None,
        audit: bool = True,
    ) -> bool:
        s = await self._get_settings()
        if getattr(self, "_settings_snapshot", None) is None:
            s = await self.detach_settings(s)
        if not s.smtp_host:
            return False
        # The destination policy, before the connection. Alert delivery runs in
        # the worker, which sits on the same network as PostgreSQL and Redis and
        # can reach a cloud host's metadata endpoint — so "the SMTP host from the
        # settings page" must not be an operator-chosen route into either.
        try:
            addresses = await asyncio.to_thread(ensure_allowed, s.smtp_host, port=int(s.smtp_port or 0))
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
            raise AlertDeliveryPermanentError("SMTP destination refused") from blocked
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
            if mode == "plain" and s.smtp_user and s.smtp_password_decrypted:
                raise AlertDeliveryPermanentError("SMTP credentials require TLS")
            from app.core.outbound import pinned_smtp_class
            if mode == "ssl":
                connection = pinned_smtp_class(smtplib.SMTP_SSL, addresses, implicit_tls=True)(
                    s.smtp_host,
                    s.smtp_port,
                    context=ssl.create_default_context(),
                    timeout=settings.ALERT_DELIVERY_TIMEOUT_SECONDS,
                )
            else:
                connection = pinned_smtp_class(smtplib.SMTP, addresses)(
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

        try:
            await bounded_smtp(_send_sync)
        except smtplib.SMTPAuthenticationError as exc:
            raise AlertDeliveryPermanentError("smtp authentication failed") from exc
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as exc:
            raise AlertDeliveryPermanentError("smtp recipient or sender rejected") from exc
        except smtplib.SMTPResponseException as exc:
            error = AlertDeliveryPermanentError if exc.smtp_code >= 500 else AlertDeliveryTransientError
            raise error(f"SMTP {exc.smtp_code}") from exc
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            raise AlertDeliveryAmbiguousError(
                f"smtp {type(exc).__name__}"
            ) from exc
        log.info("alert_email_sent", to=to, subject=subject)
        if audit:
            await self._audit_alert(
                action="alert.dispatch.success",
                channel="email",
                details={"to": to, "subject": subject[:120]},
            )
        return True

    async def _send_telegram(self, text: str, parse_mode: str = "HTML", chat_id: str | None = None) -> bool:
        """Send to exactly one chat, named by the caller.

        The recipient is a parameter and never a fallback to a setting: the
        callers fan out over ``_resolve_telegram_chats()``, so resolving the
        destination here a second time would let a chat ID that resolution
        deliberately skipped (channel disabled, entry deduplicated) receive an
        alert anyway.
        """
        s = await self._get_settings()
        if getattr(self, "_settings_snapshot", None) is None:
            s = await self.detach_settings(s)
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
            except (httpx.ConnectTimeout, httpx.ConnectError) as exc:
                raise AlertDeliveryTransientError("telegram connection unavailable") from exc
            except (asyncio.TimeoutError, httpx.TimeoutException, httpx.NetworkError) as exc:
                raise AlertDeliveryAmbiguousError("Telegram response lost; provider acceptance unknown") from exc
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
                    try:
                        retry_delay = max(float(r.json().get("parameters", {}).get("retry_after", 0)), retry_delay or 0) or None
                    except (TypeError, ValueError, AttributeError):
                        pass
                    suffix = f" retry_after={retry_delay}" if retry_delay else ""
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

        await self.detach_settings(s)
        results: list[dict] = []
        deadline = asyncio.get_running_loop().time() + settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS
        async with httpx.AsyncClient(timeout=settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS) as client:
            for chat in chats:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    results.append({"chat_id": chat, "ok": False, "error_code": "deadline_exceeded", "error": "Overall validation deadline exceeded"})
                    continue
                try:
                    response = await asyncio.wait_for(client.get(
                        f"https://{TELEGRAM_API_HOST}/bot{token}/getChat",
                        params={"chat_id": chat},
                    ), remaining)
                    results.append(self._telegram_chat_result(chat, response))
                except (httpx.HTTPError, OSError, asyncio.TimeoutError):
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
        deadline = asyncio.get_running_loop().time() + settings.ALERT_HEALTH_CHECK_TIMEOUT_SECONDS
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
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    results.append({"chat_id": chat, "ok": False, "error_code": "deadline_exceeded", "error": "Overall test deadline exceeded"})
                    continue
                try:
                    response = await asyncio.wait_for(client.post(
                        f"https://{TELEGRAM_API_HOST}/bot{token}/sendMessage",
                        json={
                            "chat_id": chat,
                            "text": text,
                            "parse_mode": "HTML",
                            "disable_web_page_preview": True,
                        },
                    ), remaining)
                    if response.status_code == 200:
                        results.append({"chat_id": chat, "ok": True})
                    else:
                        code, message = self._telegram_provider_error(response)
                        results.append({"chat_id": chat, "ok": False, "error_code": code, "error": message})
                except (httpx.HTTPError, OSError, asyncio.TimeoutError):
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
            if (parsed.hostname or "").lower() in LOOPBACK_HOSTS:
                continue
            return f"{candidate}{finding_path(threat_type)}"
        return None

    async def _stored_message_facts(
        self, threat_type: str, findings: list[dict]
    ) -> dict[str, dict]:
        """The module's own row behind each event of one batch.

        The SQL and the per-module field mapping live in
        :mod:`app.services.alert_facts`; this method is the service's entry point
        so a caller keeps one dependency.
        """
        return await stored_message_facts(self.db, threat_type, findings)

    def _facts(
        self, threat_type: str, item: dict, stored: dict | None = None
    ) -> tuple[dict[str, str], dict[str, str]]:
        """What a message says about one finding, and what the summary counts."""
        return message_facts(threat_type, item, stored)

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
        total_count: int | None = None,
        stored_facts: dict[str, dict] | None = None,
    ) -> Notification:
        """Turn one queued batch into the neutral shape every channel renders."""
        rows: list[dict[str, str]] = []
        grouped: dict[str, list[str]] = {}
        known = stored_facts or {}
        for item in bounded:
            safe_item = safe_snapshot(item)
            row, groups = self._facts(
                threat_type, safe_item, known.get(str(item.get("finding_id") or ""))
            )
            if item.get("finding_id") and threat_type in {"phishing", "breach"}:
                origin_link = self._platform_link(threat_type)
                if origin_link:
                    from uuid import UUID
                    row["Finding link"] = f"{origin_link}?finding_id={UUID(str(item['finding_id']))}"
            for name, value in safe_item.items():
                if not declared_column(threat_type, name):
                    continue
                row[name] = fact_text(value)
            rows.append({name: fact_text(value) for name, value in row.items()})
            for group_label, value in groups.items():
                grouped.setdefault(group_label, []).append(clip(value, BREAKDOWN_CHARS))
        return Notification(
            label=label,
            subject=subject,
            job_id=str(job_id) if job_id else "unrecorded",
            total=total_count if total_count is not None else len(findings),
            included=len(bounded),
            rows=rows,
            groups=[(name, counted(values)) for name, values in grouped.items()],
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
        allowed_email = await self._resolve_email_recipients(s) if channel == "email" else []
        allowed_chats = self._resolve_telegram_chats(s) if channel == "telegram" else []
        if target and not (target.lower() in {value.lower() for value in allowed_email} if channel == "email" else target in allowed_chats):
            raise AlertDeliveryCancelledError("Destination disabled or removed")
        if not target and not (allowed_email or allowed_chats):
            raise AlertDeliveryCancelledError("No enabled destination")
        s = await self.detach_settings(s)
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
        bounded = findings
        total = len(findings)
        label = (
            "Phishing"
            if threat_type == "phishing"
            else            "Credential breach"
            if threat_type == "breach"
            else "DNS Security"
            if threat_type in {"dns", "dns_security"}
            else threat_type.removeprefix("module:")
        )
        subject = f"[OpenDRP Alert] {label}: {plural(total, 'new finding')}"
        severity = highest_severity(findings)
        if severity is not None:
            subject = f"{subject} ({severity})"
        if threat_type == "breach":
            change = _breach_subject_class(findings)
            if change is not None:
                subject = f"{subject} ({change})"
        notification = self._build_notification(
            threat_type=threat_type,
            label=label,
            subject=subject,
            findings=findings,
            bounded=bounded,
            job_id=job_id,
            link=self._platform_link(threat_type),
            stored_facts=await self._stored_message_facts(threat_type, findings),
        )
        email_html = self._render_template(
            "emails/finding_summary.html",
            module_label=notification.label,
            title=notification.subject,
            badge_class=BADGE_CLASSES.get(threat_type, ""),
            dashboard_url=notification.link,
            job_id=notification.job_id,
            total=notification.total,
            included=notification.included,
            groups=notification.groups,
            columns=notification.columns,
            rows=notification.table(),
        )
        plain = plain_text(notification)
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
        for chat in telegram_chats:
            try:
                for telegram_text in telegram_parts(notification, settings.ALERT_MAX_TELEGRAM_MESSAGE_LENGTH):
                    delivered = await self._send_telegram(telegram_text, chat_id=chat)
                    if not delivered:
                        raise AlertDeliveryPermanentError("Telegram provider did not accept the message")
                sent += 1
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
            raise failures[-1] if failures else AlertDeliveryTransientError(error)
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
