from typing import Optional

from sqlalchemy import Boolean, CheckConstraint, Integer, SmallInteger, String

from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import Mapped, mapped_column

from app.core.crypto import decrypt_value, encrypt_value
from app.core.database import Base, TimestampMixin, UUIDMixin


class SystemSettings(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "system_settings"
    __table_args__ = (CheckConstraint("singleton_key = 1", name="ck_system_settings_singleton"),)

    singleton_key: Mapped[int] = mapped_column(Integer, default=1, server_default="1", unique=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1", nullable=False)
    __mapper_args__ = {"version_id_col": version}

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

    # --- Alert budget (Part 3) ---
    # The operator's half of the alert policy (see app/services/alert_policy.py).
    # Every column is nullable on purpose: NULL means "this installation has not
    # decided this one", and the environment's value (ALERT_CONFIDENCE_DIRECT and
    # friends) answers it. That is what lets a save raise one threshold without
    # resetting the other five, and what keeps an installation that never opens
    # the Settings page on the deployment's own defaults.
    # The four numbers are ``smallint`` like the confidence they are compared
    # with; the largest of them is a retry window in hours (8760 at most), which a
    # 16-bit integer holds with room to spare.
    alert_confidence_direct: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    alert_confidence_digest: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    alert_phishing_digest_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    alert_phishing_digest_hour_utc: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    alert_no_channel_retry_hours: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    alert_candidate_change_notifications: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    #: The breach module's half of the budget: what the channel does with an
    #: incident the source itself labels spam or fabricated, and how many new
    #: incidents one scan may report before the rest wait for the digest. Nullable
    #: for the same reason as the six above - NULL is "not decided here", and the
    #: environment answers.
    alert_breach_noise_policy: Mapped[str | None] = mapped_column(String(32), nullable=True)
    alert_breach_digest_threshold: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)

    # --- Scan schedules (Part 3) ---
    # JSON: {"days": [0-6 (0=Sun)], "hour": 0-23, "minute": 0-59} in UTC.
    schedule_phishing: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    schedule_breaches: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    schedule_dns_security: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    schedule_exposure: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Generic module-id -> UTC schedule map for modules declared at runtime.
    schedules: Mapped[dict | None] = mapped_column(JSON, nullable=True)

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
