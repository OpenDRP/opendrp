from enum import Enum as PyEnum

from sqlalchemy import Boolean, Enum, Index, String, text
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
    __table_args__ = (
        # The list is ordered by `created_at` with `id` as the tie-breaker, and
        # paged: without this index every page sorts the whole table (WI-15/
        # AST-18). PostgreSQL scans the btree backwards, so one ascending index
        # serves both directions.
        Index("ix_assets_created_at_id", "created_at", "id"),
        # The duplicate rule itself. Declared here as well as in migration 0001 so the
        # ORM metadata that tests and drift checks build from enforces the same rule:
        # without it an insert race between two writers was never a constraint error
        # outside PostgreSQL.
        Index(
            "uq_assets_type_normalized_value",
            "asset_type",
            "normalized_value",
            unique=True,
            postgresql_where=text("(normalized_value IS NOT NULL)"),
            sqlite_where=text("(normalized_value IS NOT NULL)"),
        ),
    )

    asset_type: Mapped[str] = mapped_column(
        Enum(AssetType, name="asset_type", create_constraint=True),
        nullable=False,
        index=True,
    )
    asset_value: Mapped[str] = mapped_column(String(512), nullable=False)
    # Canonical value used by matching and the composite uniqueness index.
    #
    # ``asset_value`` is written canonical too (see ``AssetService.create_asset``
    # and ``update_asset``): the exact text an operator typed is *not* retained,
    # so a domain entered as ``Example.COM.`` is stored and displayed as
    # ``example.com``. Keeping the canonical form in both columns is what makes
    # every matching path agree — there is no second, un-normalized value for a
    # lookup to miss.
    normalized_value: Mapped[str | None] = mapped_column(String(512), nullable=True)
    criticality: Mapped[str] = mapped_column(String(50), default="medium", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
