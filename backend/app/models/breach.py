from datetime import date

from sqlalchemy import Date, Index, Integer, JSON, String, Text, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class Breach(Base, UUIDMixin, TimestampMixin):
    """A breach finding matched to a monitored asset.

    The columns are the fields *every* breach source can supply: which incident,
    which of our assets it hit, when it happened, how much data was involved,
    and which classes of data were exposed. Anything a particular source knows
    beyond that — verification flags, exposed-secret samples, the source's own
    catalog timestamps — travels in :attr:`attributes`, so supporting a new
    breach source never requires a core schema change.

    Named for what it stores rather than for the first source that filled it: the
    connector protocol accepts breaches from any provider, so nothing about this
    module names one — not the table, not the API group the UI calls, not the
    finding shape.
    """

    __tablename__ = "drp_breaches"
    __table_args__ = (
        UniqueConstraint("breach_name", "matched_email", name="uq_breach_email"),
        # Domain scans may return several affected aliases for one domain and
        # breach. Only domain-only findings use the domain fallback key.
        Index(
            "uq_breach_domain_only",
            "breach_name",
            "matched_domain",
            unique=True,
            postgresql_where=text("matched_domain IS NOT NULL AND matched_email IS NULL"),
            sqlite_where=text("matched_domain IS NOT NULL AND matched_email IS NULL"),
        ),
    )

    breach_name: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    breach_date: Mapped[date] = mapped_column(Date, nullable=False)
    pwn_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    data_classes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    matched_email: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    matched_domain: Mapped[str | None] = mapped_column(
        String(255), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(
        String(50), default="active", nullable=False, index=True
    )
    #: Provider-specific payload (scalars or lists of strings), sanitized at the
    #: protocol boundary and re-sanitized on ingestion.
    attributes: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
