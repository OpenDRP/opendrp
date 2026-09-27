"""Strict wire schemas for connector-to-core findings.

Connector payloads are untrusted input even when the connector itself is a
first-party container. These schemas keep validation at the protocol boundary:
HTTP submissions must pass through these models before anything is persisted,
and a payload the manifest did not declare is refused rather than reshaped.
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    field_validator,
)

from app.schemas.email import EmailAddress


_CONTROL_CHARS_RE = re.compile(r"[\x00\r\n]")

#: Attribute keys travel into a JSON payload the UI renders generically, so the
#: grammar is enforced instead of trusting a connector's naming.
_ATTRIBUTE_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_ATTRIBUTES = 32
MAX_ATTRIBUTE_LIST_ITEMS = 100
MAX_ATTRIBUTE_STR_LEN = 2000
MAX_ATTRIBUTES_JSON_LEN = 20_000

def sanitize_attributes(raw: Any, *, strict: bool = True) -> dict[str, Any]:
    """Validate and clean a provider-specific attribute payload.

    A breach source may know things the core has no column for (verification
    flags, exposed-secret samples, catalog timestamps). Those travel here so a
    source never has to be squeezed into another vendor's field set.

    ``strict`` raises ``ValueError`` on a bad key or value (wire validation);
    non-strict drops the offending entry (defensive re-sanitization at the
    ingestion boundary, where a partially usable finding beats a rejected one).
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        if strict:
            raise ValueError("attributes must be an object")
        return {}
    def _clean_scalar(text: str, key: str) -> str | None:
        if _CONTROL_CHARS_RE.search(text):
            if strict:
                raise ValueError(f"{key}: control characters are not allowed")
            text = _CONTROL_CHARS_RE.sub("", text)
        cleaned_text = text.strip()
        return cleaned_text or None

    cleaned: dict[str, Any] = {}
    for raw_key, raw_value in raw.items():
        key = str(raw_key)
        if not _ATTRIBUTE_KEY_RE.match(key):
            if strict:
                raise ValueError(f"attribute key '{key}' is not a lowercase identifier")
            continue
        if len(cleaned) >= MAX_ATTRIBUTES:
            if strict:
                raise ValueError(f"attributes cannot contain more than {MAX_ATTRIBUTES} keys")
            break
        if isinstance(raw_value, list):
            items: list[str] = []
            for item in raw_value[:MAX_ATTRIBUTE_LIST_ITEMS]:
                if isinstance(item, (dict, list)) or item is None:
                    continue
                text = _clean_scalar(str(item), key)
                if text is not None:
                    items.append(text[:255])
            cleaned[key] = items
            continue
        if isinstance(raw_value, bool) or isinstance(raw_value, (int, float)):
            cleaned[key] = raw_value
            continue
        if raw_value is None:
            continue
        if not isinstance(raw_value, str):
            if strict:
                raise ValueError(f"attribute '{key}' must be a scalar or a list of strings")
            # A direct service caller (not an HTTP payload) may hand over a
            # date, UUID or Decimal; those serialize fine as their string form.
            # Anything else (a nested object, an arbitrary instance) is dropped
            # rather than coerced into a repr string.
            if not isinstance(raw_value, (datetime, date, uuid.UUID, Decimal)):
                continue
            raw_value = str(raw_value)
        text = _clean_scalar(raw_value, key)
        if text is None:
            continue
        if len(text) > MAX_ATTRIBUTE_STR_LEN:
            if strict:
                raise ValueError(f"attribute '{key}' is too long")
            text = text[:MAX_ATTRIBUTE_STR_LEN]
        cleaned[key] = text
    return cleaned
_HOSTNAME_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def _clean_text(value: str | None, *, field_name: str) -> str | None:
    if value is None:
        return None
    if _CONTROL_CHARS_RE.search(value):
        raise ValueError(f"{field_name}: control characters are not allowed")
    cleaned = value.strip()
    return cleaned or None


def _validate_host_or_ip(value: str | None, *, field_name: str) -> str | None:
    cleaned = _clean_text(value, field_name=field_name)
    if cleaned is None:
        return None
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        if _HOSTNAME_RE.fullmatch(cleaned):
            return cleaned.lower()
    raise ValueError(f"{field_name}: invalid hostname or IP address")


class ConnectorFindingBase(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PhishingFinding(ConnectorFindingBase):
    phishing_domain: str = Field(min_length=1, max_length=512)
    matched_asset: str = Field(min_length=1, max_length=512)
    ip_address: str | None = Field(default=None, max_length=255)
    web_ports: str | None = Field(default=None, max_length=255)
    # Generic fallback keeps the protocol usable for connectors that do not
    # publish a source label; ingestion defaults it to the authenticated name.
    detection_source: str | None = Field(default=None, max_length=100)
    original_domain: str | None = Field(default=None, max_length=512)

    @field_validator("phishing_domain")
    @classmethod
    def validate_phishing_domain(cls, value: str) -> str:
        cleaned = _validate_host_or_ip(value, field_name="phishing_domain")
        if cleaned is None:
            raise ValueError("phishing_domain must not be empty")
        return cleaned

    @field_validator("matched_asset", "detection_source", "original_domain", "web_ports")
    @classmethod
    def validate_text(cls, value: str | None, info) -> str | None:
        return _clean_text(value, field_name=info.field_name)

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        cleaned = _clean_text(value, field_name="ip_address")
        if cleaned is None:
            return None
        try:
            ipaddress.ip_address(cleaned)
        except ValueError as exc:
            raise ValueError("ip_address: invalid IP address") from exc
        return cleaned


class BreachFinding(ConnectorFindingBase):
    """Provider-neutral breach finding.

    The core stores what every breach source can supply — the incident name,
    the matched asset, when it happened, how many accounts it covers — and keeps
    anything beyond that in ``attributes``. No column here belongs to one
    vendor, so a source whose payload looks nothing like another vendor's still
    submits findings without a core schema change.
    """

    breach_name: str = Field(min_length=1, max_length=255)
    title: str = Field(default="", max_length=512)
    domain: str = Field(default="", max_length=255)
    breach_date: date | None = None
    pwn_count: StrictInt = Field(default=0, ge=0, le=1_000_000_000_000)
    description: str | None = Field(default=None, max_length=100_000)
    data_classes: list[Annotated[str, Field(min_length=1, max_length=255)]] = Field(
        default_factory=list, max_length=100
    )
    matched_email: EmailAddress | None = None
    matched_domain: str | None = Field(default=None, max_length=255)
    #: Provider-specific payload (scalars or lists of strings).
    attributes: dict[str, Annotated[bool | int | float | str | list[str], Field()]] = Field(
        default_factory=dict
    )

    @field_validator("attributes")
    @classmethod
    def validate_attributes(cls, value: dict) -> dict:
        cleaned = sanitize_attributes(value, strict=True)
        if len(json.dumps(cleaned, default=str)) > MAX_ATTRIBUTES_JSON_LEN:
            raise ValueError("attributes payload is too large")
        return cleaned

    @field_validator("breach_name")
    @classmethod
    def validate_breach_name(cls, value: str) -> str:
        cleaned = _clean_text(value, field_name="breach_name")
        if cleaned is None:
            raise ValueError("breach_name must not be empty")
        return cleaned

    @field_validator("title")
    @classmethod
    def validate_title(cls, value: str) -> str:
        return _clean_text(value, field_name="title") or ""

    @field_validator("domain")
    @classmethod
    def validate_breach_domain(cls, value: str) -> str:
        if not value:
            return ""
        return _validate_host_or_ip(value, field_name="domain") or ""

    @field_validator("description")
    @classmethod
    def validate_optional_text(cls, value: str | None, info) -> str | None:
        return _clean_text(value, field_name=info.field_name)

    @field_validator("matched_domain")
    @classmethod
    def validate_domain(cls, value: str | None) -> str | None:
        return _validate_host_or_ip(value, field_name="matched_domain")

    @field_validator("data_classes")
    @classmethod
    def validate_data_classes(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw_item in value:
            item = _clean_text(raw_item, field_name="data_classes")
            if item is not None and item not in cleaned:
                cleaned.append(item)
        return cleaned


ConnectorFinding = PhishingFinding | BreachFinding
MAX_FINDINGS_PER_BATCH = 500

__all__ = [
    "MAX_ATTRIBUTES",
    "MAX_FINDINGS_PER_BATCH",
    "BreachFinding",
    "ConnectorFinding",
    "PhishingFinding",
    "sanitize_attributes",
]
