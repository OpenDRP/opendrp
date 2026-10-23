from __future__ import annotations

import uuid
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Index, JSON, String
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base, TimestampMixin, UUIDMixin


class IngestionEvent(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "ingestion_events"
    __table_args__ = (
        # The dispatcher's query — unprocessed rows of a kind whose next attempt
        # is due — is the whole table every fifteen seconds, so the composite is
        # the difference between an index scan and a sequential one. Declared
        # here as in the baseline: the test schema is built from these models.
        Index("ix_ingestion_events_due", "kind", "processed_at", "next_attempt_at"),
    )

    event_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    module: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(nullable=False)
    job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("jobs.id", ondelete="SET NULL"))
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(String(128))
