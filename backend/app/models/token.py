import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, String, UUID, Boolean, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base, UUIDMixin


class RefreshTokenFamily(Base, UUIDMixin):
    __tablename__ = "drp_refresh_families"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        unique=True,
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    last_jti: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
    )
    last_issued_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_reason: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=func.now(),
        nullable=False,
    )
