from datetime import datetime
import uuid

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, UUID, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class SourceObservation(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "source_observations"
    __table_args__ = (
        UniqueConstraint("module", "source", "observation_key", name="uq_source_observation"),
        Index("ix_source_observations_module_seen", "module", "last_seen_at"),
    )
    module: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    observation_key: Mapped[str] = mapped_column(String(64), nullable=False)
    subject: Mapped[str] = mapped_column(String(253), nullable=False)
    #: Indexed: the Exposure inventory and the asset → findings view read the
    #: module's observations by asset (WI-15).
    matched_asset: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    candidate_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("drp_phishing_domains.id", ondelete="CASCADE"), nullable=True)
    connector_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("drp_connectors.id", ondelete="SET NULL"))
    source_account_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("source_accounts.id", ondelete="SET NULL"))
    provenance: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="observed")
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
