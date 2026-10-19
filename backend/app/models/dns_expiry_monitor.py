from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class DNSExpiryMonitor(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "dns_expiry_monitors"
    __table_args__ = (
        UniqueConstraint("asset_id", "kind", name="uq_dns_expiry_monitor_asset_kind"),
        Index("ix_dns_expiry_monitor_due", "state", "expires_at"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    subject: Mapped[str] = mapped_column(String(253), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    successful_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    certificate_id: Mapped[str | None] = mapped_column(String(128))
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    observation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("dns_security_observations.id", ondelete="SET NULL"))
    cycle: Mapped[str | None] = mapped_column(String(64))
    alerted_thresholds: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # When the "this control has not been checked for too long" warning was queued.
    # Silence and a quiet domain look identical from here (F-16), so the sweep says so
    # once per staleness episode and a successful check clears the marker.
    stale_alerted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
