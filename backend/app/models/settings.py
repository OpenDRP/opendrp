from typing import Optional

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import Mapped, mapped_column

from app.core.crypto import decrypt_value, encrypt_value
from app.core.database import Base, TimestampMixin, UUIDMixin


class SystemSettings(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "system_settings"

    # Provider credentials belong to connector containers and are intentionally
    # not part of the core settings model.
    smtp_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    smtp_password: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    smtp_from_email: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    smtp_port: Mapped[int] = mapped_column(Integer, default=587, nullable=False)
    # Transport mode is explicit instead of inferring TLS from the port. This
    # supports internal relays and providers that use implicit TLS on a custom
    # port without silently sending credentials over the wrong transport.
    smtp_security_mode: Mapped[str] = mapped_column(String(16), default="starttls", nullable=False)

    alert_recipient_email: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    telegram_bot_token: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # --- Alert channels (Part 2) ---
    email_alerts_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    telegram_alerts_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # JSON list of user UUIDs receiving email alerts.
    alert_email_user_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # JSON list of Telegram chat IDs (strings). This is the only Telegram
    # destination the platform has: an earlier single-chat column was removed in
    # v0.1.0, so there is no second place a chat ID can come from and no
    # fallback that could deliver to a chat an operator has since deleted.
    telegram_chat_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # --- Scan schedules (Part 3) ---
    # JSON: {"days": [0-6 (0=Sun)], "hour": 0-23, "minute": 0-59} in UTC.
    schedule_phishing: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    schedule_breaches: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # NOTE: the ``X_decrypted`` hybrid_property + setter pairs below reuse the
    # property name for the setter decorator by design (SQLAlchemy's standard
    # hybrid pattern). mypy flags the setter as ``no-redef``; the per-file
    # override in pyproject.toml disables only that code for this module.
    @hybrid_property
    def smtp_password_decrypted(self) -> Optional[str]:
        return decrypt_value(self.smtp_password)

    @smtp_password_decrypted.setter  # type: ignore[no-redef]
    def smtp_password_decrypted(self, value: Optional[str]) -> None:
        self.smtp_password = encrypt_value(value)

    @hybrid_property
    def telegram_bot_token_decrypted(self) -> Optional[str]:
        return decrypt_value(self.telegram_bot_token)

    @telegram_bot_token_decrypted.setter  # type: ignore[no-redef]
    def telegram_bot_token_decrypted(self, value: Optional[str]) -> None:
        self.telegram_bot_token = encrypt_value(value)

    @hybrid_property
    def smtp_from_email_decrypted(self) -> Optional[str]:
        return decrypt_value(self.smtp_from_email)

    @smtp_from_email_decrypted.setter  # type: ignore[no-redef]
    def smtp_from_email_decrypted(self, value: Optional[str]) -> None:
        self.smtp_from_email = encrypt_value(value)

    @hybrid_property
    def alert_recipient_email_decrypted(self) -> Optional[str]:
        return decrypt_value(self.alert_recipient_email)

    @alert_recipient_email_decrypted.setter  # type: ignore[no-redef]
    def alert_recipient_email_decrypted(self, value: Optional[str]) -> None:
        self.alert_recipient_email = encrypt_value(value)
