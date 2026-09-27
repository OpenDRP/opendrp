import ipaddress
import re
import uuid
from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    TypeAdapter,
    field_validator,
)

from app.schemas.common import PaginatedResponse
from app.schemas.email import EmailAddress
from app.schemas.user import AssetType

AssetCriticality = Literal["low", "medium", "high", "critical"]
_AssetTypeLiteralValues = {"domain", "ip_address", "email_account", "keyword_domain", "keyword_title"}

_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

_IP_ADAPTER: TypeAdapter = TypeAdapter(IPvAnyAddress)
_EMAIL_ADAPTER: TypeAdapter = TypeAdapter(EmailAddress)


def normalize_asset_value(asset_type: str, value: str) -> str:
    """Return the canonical value used for matching, indexing and deduplication."""
    raw = value.strip()
    if asset_type == "domain":
        return raw.rstrip(".").lower().encode("idna").decode("ascii")
    if asset_type == "email_account":
        local, separator, domain = raw.partition("@")
        return f"{local}@{domain.lower()}" if separator else raw.lower()
    if asset_type == "ip_address":
        return str(ipaddress.ip_address(raw))
    return raw


def validate_and_normalize_asset_value(asset_type: str, value: str) -> str:
    """Validate an asset value for its type and return its canonical form."""
    try:
        normalized = normalize_asset_value(asset_type, value)
    except (ValueError, UnicodeError) as exc:
        if asset_type == "ip_address":
            raise ValueError("Invalid IP address format") from exc
        if asset_type == "domain":
            raise ValueError("Invalid domain format") from exc
        raise ValueError("Invalid asset value") from exc
    if asset_type == "domain" and not _HOSTNAME_RE.match(normalized):
        raise ValueError("Invalid domain format")
    if asset_type == "ip_address":
        try:
            _IP_ADAPTER.validate_python(normalized)
        except Exception as exc:
            raise ValueError("Invalid IP address format") from exc
    if asset_type == "email_account":
        try:
            _EMAIL_ADAPTER.validate_python(normalized)
        except Exception as exc:
            raise ValueError("Invalid email format") from exc
    if asset_type in ("keyword_domain", "keyword_title") and not normalized:
        raise ValueError("Keyword cannot be empty")
    return normalized


class AssetBase(BaseModel):
    asset_type: AssetType
    asset_value: str = Field(..., max_length=512)
    criticality: AssetCriticality = "medium"
    is_active: bool = True

    model_config = ConfigDict(from_attributes=True, use_enum_values=True)

    @field_validator("asset_type", mode="before")
    @classmethod
    def _coerce_asset_type(cls, v):
        if v is None:
            return v
        if hasattr(v, "value"):
            s = v.value
        else:
            s = str(v)
        if s in _AssetTypeLiteralValues:
            return s
        return v

    @field_validator("criticality", mode="before")
    @classmethod
    def _coerce_criticality(cls, v):
        if v is None:
            return v
        if hasattr(v, "value"):
            return v.value
        return str(v)


class AssetCreate(AssetBase):
    @field_validator("asset_value")
    @classmethod
    def validate_asset_value(cls, v: str, info) -> str:
        asset_type = info.data.get("asset_type")
        if not asset_type:
            return v
        validate_and_normalize_asset_value(asset_type, v)
        return v


class AssetUpdate(BaseModel):
    asset_type: AssetType | None = None
    asset_value: str | None = Field(None, max_length=512)
    criticality: AssetCriticality | None = None
    is_active: bool | None = None

    @field_validator("asset_value")
    @classmethod
    def validate_asset_value(cls, v: str | None, info) -> str | None:
        if v is None:
            return v
        asset_type = info.data.get("asset_type")
        if not asset_type:
            return v
        validate_and_normalize_asset_value(asset_type, v)
        return v


class AssetResponse(AssetBase):
    id: uuid.UUID
    normalized_value: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AssetListResponse(PaginatedResponse[AssetResponse]):
    items: list[AssetResponse]
