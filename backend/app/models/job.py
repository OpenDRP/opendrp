from __future__ import annotations

from typing import TYPE_CHECKING
import re
import uuid
from datetime import datetime
from enum import Enum as PyEnum
from typing import Any

from sqlalchemy import UUID, DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.core.database import Base, TimestampMixin, UUIDMixin
if TYPE_CHECKING:
    from app.models.user import User


class JobStatus(str, PyEnum):
    pending = "pending"
    running = "running"
    success = "success"
    partial = "partial"
    error = "error"
    cancelled = "cancelled"
    skipped = "skipped"


class JobType(str, PyEnum):
    """Job types the core creates itself.

    Connector-declared scan types (the manifest protocol) are deliberately not
    enumerated here: a connector owns its job type, so the core accepts any
    value matching :data:`CONNECTOR_JOB_TYPE_RE` and keeps this enum for the jobs
    it enqueues on its own behalf. A type a connector declares is registry data,
    not core vocabulary — see ``app/services/connector_manifest.py``.
    """

    report_generate = "report.generate"
    system = "system"


#: Namespaced job type a connector may declare, e.g. ``phishing.dnstwist``.
#: This is the same grammar the connector manifest protocol validates against
#: (``app/services/connector_manifest.py``).
CONNECTOR_JOB_TYPE_RE = re.compile(r"^[a-z][a-z0-9_-]*(?:\.[a-z0-9_-]+)+$")

_JOB_TYPES = {m.value for m in JobType}
_JOB_STATUSES = {m.value for m in JobStatus}


class Job(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "jobs"

    job_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32),
        default=JobStatus.pending.value,
        nullable=False,
        index=True,
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    task_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    params: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    result_summary: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Connector-owned jobs use a lease so a lost connector cannot leave work
    # permanently running. Core-owned Celery jobs leave these fields NULL.
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(default=0, nullable=False)
    claimed_by_connector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    lease_token: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_by_user: Mapped["User | None"] = relationship(
        "User", lazy="selectin"
    )

    @validates("job_type")
    def _validate_job_type(self, key: str, value: Any) -> str:  # type: ignore[type-arg]
        v = getattr(value, "value", value)
        if v is None:
            raise ValueError("job_type is required")
        vs = str(v)
        if vs in _JOB_TYPES or CONNECTOR_JOB_TYPE_RE.match(vs):
            return vs
        raise ValueError(f"job_type invalid: {vs}")

    @validates("status")
    def _validate_status(self, key: str, value: Any) -> str:  # type: ignore[type-arg]
        v = getattr(value, "value", value)
        if v is None:
            return JobStatus.pending.value
        vs = str(v)
        if vs not in _JOB_STATUSES:
            raise ValueError(f"status invalid: {vs}")
        return vs
