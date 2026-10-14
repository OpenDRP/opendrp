from __future__ import annotations

from typing import TYPE_CHECKING
from datetime import datetime
import uuid

from sqlalchemy import JSON, UUID, ForeignKey, String, Boolean, DateTime, Integer, Text, func
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base, TimestampMixin, UUIDMixin
if TYPE_CHECKING:
    from app.models.user import User


class Report(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "reports"

    report_name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending", nullable=False)
    # Snapshot of the report input bound at generation time. This lets the UI
    # explain a historical truncation even after REPORT_MAX_ROWS changes.
    is_truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    truncation_metadata: Mapped[dict | None] = mapped_column(MutableDict.as_mutable(JSON()), nullable=True)
    generation_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_by_user: Mapped["User | None"] = relationship(
        "User", back_populates="reports"
    )


class ReportArtifactCleanup(Base):
    """Durable retry intent for deleting a report PDF after its row is gone."""

    __tablename__ = "report_artifact_cleanup"

    artifact_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)


class ReportAuditOutbox(Base):
    """Durable report outcome events awaiting signed audit-chain delivery."""

    __tablename__ = "report_audit_outbox"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    report_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    details: Mapped[dict] = mapped_column(MutableDict.as_mutable(JSON()), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class ReportQueueControl(Base):
    """Singleton write-lock row serializing global report queue admission."""

    __tablename__ = "report_queue_control"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    touched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
