from __future__ import annotations

from typing import TYPE_CHECKING
import uuid

from sqlalchemy import JSON, UUID, ForeignKey, String, Boolean
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
    truncation_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_by_user: Mapped["User | None"] = relationship(
        "User", back_populates="reports"
    )
