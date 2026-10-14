import asyncio
import re
import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm.exc import StaleDataError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings as core_settings
from app.core.crypto import mask_value
from app.core.exceptions import BadRequestException, ConflictException
from app.core.outbound import OutboundBlocked, ensure_allowed
from app.core.safe_errors import sanitize_external_error
from app.models.settings import SystemSettings
from app.schemas.settings import SystemSettingsUpdate


# Only alert-channel secrets are owned by the core. Provider credentials belong
# to connector containers and must never be read from system_settings.
_ENCRYPTED_FIELDS = {
    "smtp_password": "smtp_password_decrypted",
    "telegram_bot_token": "telegram_bot_token_decrypted",
    "smtp_from_email": "smtp_from_email_decrypted",
    "alert_recipient_email": "alert_recipient_email_decrypted",
}


def is_unchanged_masked_value(
    submitted: Any, current_plain: Optional[str]
) -> bool:
    """Return whether a submitted value is the exact UI mask of a secret."""
    if not isinstance(submitted, str) or not submitted or not current_plain:
        return False
    try:
        return submitted == mask_value(current_plain, keep_first=2, keep_last=2)
    except Exception:
        return False


#: A run of mask characters at least this long is the settings placeholder. The
#: UI masks a secret as ``ab****yz`` (``mask_value`` keeps the first and the last
#: two characters), so every mask of a secret longer than six characters contains
#: a run at least this long, and a mask of a very short secret is nothing but mask
#: characters.
_MASK_RUN_RE = re.compile(r"[*\u2022]{3,}")


def looks_like_a_mask(value: str) -> bool:
    """Whether a submitted secret is the UI placeholder rather than a secret.

    Deliberately narrower than "contains an asterisk". A password may contain
    one — refusing it tells the operator that their complete value is not
    complete, and leaves them no way to set the password at all. What must never
    be stored is the placeholder itself.

    The residual, stated rather than hidden: a mask of a five- or six-character
    secret has a run of one or two, so it is not recognised here. That value can
    only arrive as a mask belonging to a *different* value (its own is caught by
    the unchanged-mask check above), which is a stale client rather than a
    supported flow.
    """
    return bool(_MASK_RUN_RE.search(value))


class SettingsService:
    async def _audit_blocked(self, blocked, *, operation: str) -> None:
        """Record a destination the policy refused.

        Best-effort on purpose: the caller is already raising a refusal the
        operator will see, and an audit write that fails must not replace that
        message with a database error.
        """
        from app.core.audit import AuditLogger

        try:
            await AuditLogger.emit_background(
                self.db,
                action="outbound.blocked",
                ip_address="internal:settings-service",
                user_id=None,
                details={"operation": operation, **blocked.as_audit_details()},
            )
        except Exception:
            pass

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_singleton(self) -> SystemSettings:
        row = (await self.db.execute(select(SystemSettings).where(SystemSettings.singleton_key == 1))).scalar_one_or_none()
        if row is None:
            if self.db.get_bind().dialect.name == "sqlite":
                statement = sqlite_insert(SystemSettings).values(singleton_key=1).on_conflict_do_nothing(index_elements=[SystemSettings.singleton_key])
                await self.db.execute(statement)
            else:
                pg_statement = pg_insert(SystemSettings).values(singleton_key=1).on_conflict_do_nothing(index_elements=[SystemSettings.singleton_key])
                await self.db.execute(pg_statement)
            await self.db.commit()
            row = (await self.db.execute(select(SystemSettings).where(SystemSettings.singleton_key == 1))).scalar_one()
        return row

    async def update_settings(
        self, settings: SystemSettings, data: SystemSettingsUpdate,
        *, commit: bool = True,
    ) -> SystemSettings:
        update_data = data.model_dump(exclude_unset=True)
        expected = update_data.pop("expected_version", None)
        if expected is not None and expected != settings.version:
            raise ConflictException("Settings changed concurrently; reload before saving")
        user_ids = update_data.get("alert_email_user_ids")
        if user_ids:
            from uuid import UUID
            from app.models.user import User
            active = set((await self.db.execute(select(User.id).where(User.id.in_([UUID(value) for value in user_ids]), User.is_active.is_(True)))).scalars())
            if active != {UUID(value) for value in user_ids}:
                raise BadRequestException("Recipients must reference existing active users")
        if "schedules" in update_data and update_data["schedules"] is not None:
            from app.models import Module
            module_ids = set((await self.db.execute(select(Module.id))).scalars().all())
            unknown = sorted(set(update_data["schedules"]) - module_ids)
            if unknown:
                raise BadRequestException(f"Schedules reference unknown modules: {unknown}")
        for field, value in update_data.items():
            if field in _ENCRYPTED_FIELDS:
                current_plain = getattr(settings, _ENCRYPTED_FIELDS[field], None)
                if is_unchanged_masked_value(value, current_plain):
                    continue
                if isinstance(value, str) and looks_like_a_mask(value):
                    raise BadRequestException(
                        f"{field} is masked; replace it with the complete value to change it"
                    )
                setattr(settings, _ENCRYPTED_FIELDS[field], value)
            elif field == "smtp_port" and value is None:
                # smtp_port is NOT NULL; an empty form value means keep the
                # current setting rather than issuing an invalid NULL update.
                continue
            else:
                setattr(settings, field, value)
        if settings.smtp_security_mode == "plain" and settings.smtp_user and settings.smtp_password:
            raise BadRequestException("SMTP credentials require STARTTLS or implicit TLS")
        try:
            await self.db.flush()
            if commit:
                await self.db.commit()
                await self.db.refresh(settings)
        except StaleDataError as exc:
            await self.db.rollback()
            raise ConflictException("Settings changed concurrently; reload before saving") from exc
        return settings

    async def send_test_email(
        self, settings: SystemSettings, to: Optional[str] = None
    ) -> dict:
        recipient = to or settings.alert_recipient_email_decrypted
        if not recipient:
            raise BadRequestException("No alert_recipient_email configured")
        if not settings.smtp_host or not settings.smtp_port:
            raise BadRequestException("SMTP settings not configured")

        subject = "[OpenDRP] Test alert email from OpenDRP Platform"
        body_html = (
            "<html><body>"
            "<h2>OpenDRP Test Email ✅</h2>"
            "<p>SMTP configuration is working correctly.<br/>"
            f"Time sent: {datetime.now(timezone.utc).isoformat()} UTC</p>"
            "<p>If you received this, your Alert Module integration succeeded.</p>"
            "</body></html>"
        )
        smtp_from = (
            settings.smtp_from_email_decrypted
            or settings.smtp_user
            or "opendrp@localhost"
        )
        smtp_user = settings.smtp_user
        smtp_password = settings.smtp_password_decrypted or None
        host, port = settings.smtp_host, settings.smtp_port
        mode = settings.smtp_security_mode or "starttls"
        if mode == "plain" and smtp_user and smtp_password:
            raise BadRequestException("SMTP credentials require TLS")
        await self.db.commit()  # Snapshot above; no DB transaction during I/O.

        # A test send is a real connection to an operator-supplied host, so it
        # goes through the destination policy like every other one. The refusal is
        # raised as a bad request rather than a 500: it is a deliberate refusal,
        # and the message names the reason so the operator can act on it (fix the
        # host, or add it to OUTBOUND_ALLOWED_HOSTS).
        try:
            addresses = await asyncio.to_thread(ensure_allowed, host, port=int(port or 0))
        except OutboundBlocked as blocked:
            await self._audit_blocked(blocked, operation="settings_test_email")
            raise BadRequestException(
                "Refusing to connect to the configured SMTP host: "
                f"{blocked.reason}. Add it to OUTBOUND_ALLOWED_HOSTS if this is "
                "intended."
            ) from blocked

        def _deliver() -> None:
            message = EmailMessage()
            message["From"] = smtp_from
            message["To"] = recipient
            message["Subject"] = subject
            message.set_content("Test successful.")
            message.add_alternative(body_html, subtype="html")
            from app.core.outbound import pinned_smtp_class
            transport_mode = mode.lower()
            if transport_mode not in {"starttls", "ssl", "plain"}:
                raise ValueError("unsupported SMTP security mode")
            if transport_mode == "ssl":
                context = ssl.create_default_context()
                with pinned_smtp_class(smtplib.SMTP_SSL, addresses, implicit_tls=True)(
                    host,
                    port,
                    context=context,
                    timeout=core_settings.ALERT_DELIVERY_TIMEOUT_SECONDS,
                ) as server:
                    if smtp_user and smtp_password:
                        server.login(smtp_user, smtp_password)
                    server.send_message(message)
                return

            with pinned_smtp_class(smtplib.SMTP, addresses)(
                host,
                port,
                timeout=core_settings.ALERT_DELIVERY_TIMEOUT_SECONDS,
            ) as server:
                if transport_mode == "starttls":
                    server.ehlo()
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)
                server.send_message(message)

        try:
            # SMTP is blocking I/O; do not block the FastAPI event loop. The
            # executor socket timeout bounds individual operations, while this
            # wall-clock timeout bounds the complete test, including DNS and
            # authentication handshakes.
            from app.services.alert_service import bounded_smtp
            await bounded_smtp(_deliver)
        except asyncio.TimeoutError as exc:
            raise BadRequestException("Failed to send email: SMTP delivery timed out") from exc
        except Exception as exc:
            raise BadRequestException(
                "Failed to send email: " + sanitize_external_error(exc, limit=300)
            ) from exc
        return {"status": "sent", "to": recipient}
