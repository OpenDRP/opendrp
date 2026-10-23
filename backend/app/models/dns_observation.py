from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class DNSObservation(Base, UUIDMixin, TimestampMixin):
    """One source's evolving observation, not an immutable generic finding.

    ``observation_key`` identifies a stable fact within a source (a DNS RRset
    member, certificate, or registration record). Re-observing it advances
    ``last_seen_at`` and refreshes mutable metadata while retaining its original
    first-seen timestamp. Certificate observations intentionally remain distinct
    so Certificate Transparency history is not mistaken for current DNS state.
    """

    __tablename__ = "dns_security_observations"
    __table_args__ = (
        UniqueConstraint("source", "observation_key", name="uq_dns_observation_source_key"),
        Index("ix_dns_observation_subject_type", "subject", "observation_type"),
        Index("ix_dns_observation_expires", "expires_at"),
        Index("ix_dns_observation_source_seen", "source", "last_seen_at"),
    )

    observation_key: Mapped[str] = mapped_column(String(64), nullable=False)
    observation_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    record_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    value: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="current")
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
