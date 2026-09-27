from enum import Enum as PyEnum

from sqlalchemy import Boolean, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, TimestampMixin, UUIDMixin


class AssetType(str, PyEnum):
    domain = "domain"
    ip_address = "ip_address"
    email_account = "email_account"
    keyword_domain = "keyword_domain"
    keyword_title = "keyword_title"


class Asset(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "assets"

    asset_type: Mapped[str] = mapped_column(
        Enum(AssetType, name="asset_type", create_constraint=True),
        nullable=False,
        index=True,
    )
    asset_value: Mapped[str] = mapped_column(String(512), nullable=False)
    # Canonical value used by matching and the composite uniqueness index. The
    # display value remains in asset_value for operator-facing responses.
    normalized_value: Mapped[str | None] = mapped_column(String(512), nullable=True)
    criticality: Mapped[str] = mapped_column(String(50), default="medium", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
