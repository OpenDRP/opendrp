from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class AlertDeliveryStatus:
    pending = "pending"
    delivering = "delivering"
    sent = "sent"
    failed = "failed"


class AlertDelivery(Base, UUIDMixin, TimestampMixin):
    """Durable notification event, separated from finding persistence.

    One row represents one newly discovered finding for one delivery channel.
    Rows sharing a job, threat type, and channel are claimed together by the
    delivery worker and sent as one aggregated notification. Keeping events
    individually makes retries and crash recovery lossless without requiring a
    large mutable JSON blob; a Telegram outage cannot mark email as delivered.
    """

    __tablename__ = "alert_deliveries"

    job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    threat_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # Delivery state is per channel. One finding may need an email retry while
    # its Telegram delivery is already complete; a single event-level status
    # cannot represent that without losing the failed channel.
    channel: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )
    # Concrete email address or Telegram chat ID. Keeping this at the queue-row
    # level prevents a retry for one recipient from duplicating delivery to
    # recipients that already succeeded.
    target: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=AlertDeliveryStatus.pending, index=True)
    attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
