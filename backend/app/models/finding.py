import uuid

from sqlalchemy import JSON, UUID, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class Finding(Base, UUIDMixin, TimestampMixin):
    """A finding stored for a registry-declared module.

    Modules the core has no dedicated table for persist here: the row carries the
    platform-wide facts (which module and connector produced it, when, its
    deduplication key) and the *whole* validated payload as JSON, shaped by the
    module's own declared fields. That is what removes the last closed set: the
    core needs no table, no schema class and no migration per data source.

    Deduplication is declared too: ``dedup_key`` is built from the module's
    ``dedup_fields`` and is unique per module, so re-submitting the same finding
    is rejected exactly like the native tables' unique constraints do.
    """

    __tablename__ = "drp_findings"
    __table_args__ = (
        UniqueConstraint("module", "dedup_key", name="uq_findings_module_dedup"),
        Index("ix_drp_findings_module_created", "module", "created_at"),
    )

    #: Registry module id this finding belongs to (e.g. "phishing").
    module: Mapped[str] = mapped_column(
        String(32), ForeignKey("drp_modules.id", ondelete="RESTRICT"), nullable=False
    )
    #: The module's finding kind, denormalized so a query never has to join.
    finding_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Connector that reported it (taken from its credential, not from a claim).
    connector_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    #: Scan job that produced it. Deliberately not a foreign key: job history is
    #: prunable, while a finding must outlive the scan that found it.
    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    #: Declared-field values joined into one comparison key (unique per module).
    dedup_key: Mapped[str] = mapped_column(String(512), nullable=False)
    #: Human-readable headline for lists and alerts (the module's title field).
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    #: Asset the finding was matched against, when the module declares one.
    matched_asset: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="active", nullable=False, index=True)
    #: The validated payload: declared fields plus the source's own attributes.
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
