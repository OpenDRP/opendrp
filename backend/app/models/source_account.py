from sqlalchemy import JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base, TimestampMixin, UUIDMixin


class SourceAccount(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "source_accounts"
    __table_args__ = (UniqueConstraint("source_id", "name", name="uq_source_account"),)
    source_id: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_ref: Mapped[str | None] = mapped_column(String(128))
    # Fernet ciphertext of the provider API key (see app.core.crypto). Never
    # returned by the API; `api_key_hint` is the only value shown back.
    api_key_encrypted: Mapped[str | None] = mapped_column(Text)
    api_key_hint: Mapped[str | None] = mapped_column(String(16))
    policy: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    access_state: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
