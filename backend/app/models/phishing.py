from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class PhishingDomain(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "drp_phishing_domains"

    phishing_domain: Mapped[str] = mapped_column(
        String(512), unique=True, nullable=False, index=True
    )
    matched_asset: Mapped[str] = mapped_column(String(512), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    web_ports: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detection_source: Mapped[str] = mapped_column(String(100), nullable=False)
    original_domain: Mapped[str | None] = mapped_column(String(512), nullable=True)
    whois_registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    whois_abuse_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain_created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: Investigation state of the finding: ``active``, ``investigating`` or
    #: ``resolved``. The platform has no takedown workflow.
    status: Mapped[str] = mapped_column(
        String(50), default="active", nullable=False, index=True
    )
