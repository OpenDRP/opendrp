import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import PaginatedResponse

ThreatStatus = Literal["active", "investigating", "resolved"]
DetectionSource = Literal["dnstwist", "shodan_ssl", "shodan_title", "shodan_favicon"]


class PhishingThreatBase(BaseModel):
    phishing_domain: str = Field(..., max_length=512)
    matched_asset: str = Field(..., max_length=512)
    ip_address: str | None = Field(None, max_length=255)
    web_ports: str | None = Field(None, max_length=255)
    detection_source: DetectionSource = "dnstwist"
    original_domain: str | None = Field(None, max_length=512)
    whois_registrar: str | None = Field(None, max_length=255)
    whois_abuse_email: str | None = Field(None, max_length=255)
    domain_created_at: datetime | None = None
    #: Investigation state: ``active``, ``investigating`` or ``resolved``.
    status: ThreatStatus = "active"


class PhishingThreatResponse(PhishingThreatBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class PhishingThreatUpdate(BaseModel):
    status: ThreatStatus | None = None
    matched_asset: str | None = None


class PhishingListResponse(PaginatedResponse):
    items: list[PhishingThreatResponse]
