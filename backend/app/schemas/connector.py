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
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    field_validator,
)

from app.schemas.email import EmailAddress


_CONTROL_CHARS_RE = re.compile(r"[\x00\r\n]")

#: The active TLS probe stores one control row per port, and the storage identity
#: is (source, subject, record type): without the port in the record type, 443 and
#: 8443 would overwrite each other. `TLS` alone is the default port.
_TLS_RECORD_TYPE = re.compile(r"TLS(?::(?:[1-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?")

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
#: The subject grammar for DNS observations. It is a hostname plus the RFC 8552
#: underscore service labels that address records which are *not* hostnames: the DMARC
#: policy (`_dmarc.example.com`), DKIM selectors (`_domainkey`), ACME challenges and
#: `_sip._tcp` service names. Those records exist only under such a name, so refusing
#: the underscore would leave the platform unable to represent what a domain actually
#: publishes - and an observation subject is matched by exact string equality against
#: assets, never resolved or fetched, so the label cannot reach a URL or a probe.
_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DNS_SERVICE_LABEL = r"_[a-z0-9-]{1,63}"
#: At least two labels are required, exactly as before: a single label is not a
#: name the platform can attribute to an asset.
DNS_NAME_RE = re.compile(
    rf"^(?:{_DNS_SERVICE_LABEL}\.)*{_DNS_LABEL}(?:\.{_DNS_LABEL})+$"
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
    observed_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value):
        return sanitize_attributes(value, strict=True)

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


class DNSObservationPayload(ConnectorFindingBase):
    """Small normalized record submitted by a DNS Security source connector."""

    observation_type: str = Field(min_length=1, max_length=32)
    subject: str = Field(min_length=1, max_length=253)
    record_type: str | None = Field(default=None, max_length=16)
    value: str | None = Field(default=None, max_length=1000)
    expires_at: datetime | None = None
    status: str = Field(default="current", max_length=16)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observation_type")
    @classmethod
    def _valid_observation_type(cls, value: str) -> str:
        allowed = {"dns_record", "rdap", "certificate", "certificate_check", "vt_subdomain", "vt_resolution", "vt_domain", "hostname", "passive_dns",
                   # The active probe's two shapes: the mutable control row that says
                   # what a host serves now, and the certificate evidence it read.
                   "tls_probe", "tls_certificate",
                   # Where an index says a certificate we serve is *being served* - the
                   # reverse of discovery - together with the host facts (organisation,
                   # ASN, JARM, title) the scoring rules read.
                   "certificate_response",
                   # One address as a provider's own index saw it: what it serves now and
                   # the stack behind it.
                   "host_lookup"}
        cleaned = value.strip().lower()
        if cleaned not in allowed:
            raise ValueError("unsupported DNS observation type")
        return cleaned

    @field_validator("subject")
    @classmethod
    def _valid_subject(cls, value: str) -> str:
        cleaned = _clean_text(value, field_name="subject")
        if cleaned is None:
            raise ValueError("subject must not be empty")
        try:
            ipaddress.ip_address(cleaned)
            return cleaned
        except ValueError:
            pass
        try:
            normalized = cleaned.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("subject has invalid IDNA encoding") from exc
        if len(normalized) > 253 or not DNS_NAME_RE.fullmatch(normalized):
            raise ValueError("subject must be a valid DNS name or IP address")
        return normalized

    @field_validator("value")
    @classmethod
    def _valid_value(cls, value: str | None) -> str | None:
        return _clean_text(value, field_name="value")

    @field_validator("expires_at")
    @classmethod
    def _normalize_expiry_timezone(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value

    @field_validator("record_type")
    @classmethod
    def _valid_record_type(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip().upper()
        if cleaned not in {"A", "AAAA", "CNAME", "NS", "MX", "CAA", "SOA", "RDAP", "TXT"} and not _TLS_RECORD_TYPE.fullmatch(cleaned):
            raise ValueError("unsupported DNS record type")
        return cleaned

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in {"current", "historical", "expired", "unknown"}:
            raise ValueError("unsupported DNS observation status")
        return cleaned

    @field_validator("metadata")
    @classmethod
    def _valid_metadata(cls, value: dict) -> dict:
        cleaned = sanitize_attributes(value, strict=True)
        if len(json.dumps(cleaned, separators=(",", ":"))) > 10_000:
            raise ValueError("metadata payload is too large")
        return cleaned


class ExposureFinding(ConnectorFindingBase):
    subject: str = Field(min_length=1, max_length=253)
    matched_asset: str = Field(min_length=1, max_length=512)
    hostname: str | None = Field(default=None, max_length=253)
    port: StrictInt = Field(ge=1, le=65535)
    transport: str = Field(default="tcp", pattern="^(tcp|udp)$")
    protocol: str = Field(default="unknown", max_length=32)
    observed_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("subject", "hostname")
    @classmethod
    def valid_subject(cls, value):
        if value is None:
            return value
        from app.services.dns_security_service import normalize_subject
        return normalize_subject(value)

    @field_validator("matched_asset", "protocol")
    @classmethod
    def valid_text(cls, value):
        return _clean_text(value, field_name="exposure")

    @field_validator("metadata")
    @classmethod
    def valid_metadata(cls, value):
        return sanitize_attributes(value, strict=True)


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
    #: Which class of exposure this finding is: an account compromised (the default, and
    #: what every source reported before the field existed), the account appearing in a
    #: paste, or a site found in a stealer log. Declared by the source and closed here,
    #: because a class nothing recognizes would be stored under a heading nobody chose
    #: (WI-21). The dedup keys do not move for it: a paste or a stealer log also carries
    #: its own identifier inside ``breach_name``.
    exposure_kind: Literal["breach", "paste", "stealer_log"] | None = None
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


class BreachCatalogueEntry(BaseModel):
    """One incident from a breach source's own catalogue (F-09, WI-13).

    The same neutral facts a finding carries and no match: an entry describes an
    incident the source knows about, whether or not any address of ours is in it. That
    is the whole point of the catalogue — an incident at a domain being watched is
    worth knowing about *before* somebody has added an address to it.

    ``attributes`` carries what a source knows beyond the neutral fields, with the same
    validation a finding's attributes get, and deliberately nothing else: a catalogue is
    a description of incidents, not a second place to store exposed credentials (the
    exposed-secret sample belongs to the finding of the address it was recovered from).
    """

    model_config = ConfigDict(extra="forbid")

    breach_name: str = Field(min_length=1, max_length=255)
    title: str = Field(default="", max_length=512)
    domain: str = Field(default="", max_length=255)
    breach_date: date | None = None
    #: The source's own catalogue timestamps. They are what makes the platform's diff
    #: meaningful: an incident whose ``added_date`` is old but which this installation
    #: has never stored is still new *here*, and the column says which is which.
    added_date: datetime | None = None
    modified_date: datetime | None = None
    pwn_count: StrictInt = Field(default=0, ge=0, le=1_000_000_000_000)
    data_classes: list[Annotated[str, Field(min_length=1, max_length=255)]] = Field(
        default_factory=list, max_length=100
    )
    attributes: dict[str, Annotated[bool | int | float | str | list[str], Field()]] = Field(
        default_factory=dict
    )

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
    def validate_vendor_domain(cls, value: str) -> str:
        if not value:
            return ""
        return _validate_host_or_ip(value, field_name="domain") or ""

    @field_validator("attributes")
    @classmethod
    def validate_attributes(cls, value: dict) -> dict:
        cleaned = sanitize_attributes(value, strict=True)
        if len(json.dumps(cleaned, default=str)) > MAX_ATTRIBUTES_JSON_LEN:
            raise ValueError("attributes payload is too large")
        return cleaned

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
#: One catalogue submission's bound. A source's whole catalogue is a handful of
#: requests' worth of rows at most, and a batch larger than this is a caller that
#: assembled its payload wrongly rather than a catalogue that grew.
MAX_CATALOGUE_ENTRIES_PER_BATCH = 500

__all__ = [
    "MAX_ATTRIBUTES",
    "MAX_CATALOGUE_ENTRIES_PER_BATCH",
    "MAX_FINDINGS_PER_BATCH",
    "BreachCatalogueEntry",
    "BreachFinding",
    "ConnectorFinding",
    "PhishingFinding",
    "sanitize_attributes",
]
