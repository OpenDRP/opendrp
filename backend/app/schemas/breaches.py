import uuid
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.common import PaginatedResponse
from app.schemas.email import EmailAddress

# The vendor's REST payload schema used to live here, when the core called the
# upstream API itself. Scanning lives in connector containers, so validating a
# specific vendor's response shape is the connector's job and the core keeps
# only the provider-neutral result (see BreachResponse).


class BreachResponse(BaseModel):
    """A breach finding.

    Fields are the ones every breach source can supply; whatever the reporting
    source knows beyond that is returned in ``attributes`` and rendered
    generically by the UI, so a new source needs no API change.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    breach_name: str
    title: str
    domain: str
    breach_date: date
    pwn_count: int
    description: str | None
    data_classes: list[str]
    matched_email: str | None
    matched_domain: str | None
    status: str
    #: Provider-specific payload (e.g. verification flags, catalog timestamps).
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    matched_asset: str | None = None
    matched_asset_type: str | None = None


class BreachListResponse(PaginatedResponse):
    items: list[BreachResponse]


class BreachScanEmailRequest(BaseModel):
    email: EmailAddress = Field(
        ..., max_length=255, description="Email address to scan for breaches"
    )


class BreachScanDomainRequest(BaseModel):
    domain: str = Field(
        ..., min_length=3, max_length=255, description="Domain name to scan for breaches"
    )

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        import re

        s = v.strip().lower()
        pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
        )
        if not pattern.match(s):
            raise ValueError("domain: invalid FQDN format")
        return s
