"""Wire schemas for the module registry and generically stored findings.

A module is data, so its *definition* is user input and gets the same treatment
as every other untrusted payload: strict fields, bounded sizes, no unknown keys.
The declaration is validated again in ``module_registry`` (grammar, field types,
dedup coherence), because the service is also reachable without HTTP.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

#: Triage states a finding may be moved to. The same three the built-in
#: phishing module uses, so triaging a declared module's findings works the way
#: an analyst already expects; anything else is rejected rather than stored.
FindingStatus = Literal["active", "investigating", "resolved"]


class ModuleCreateRequest(BaseModel):
    """Declare a new module backed by generic finding storage."""

    model_config = ConfigDict(extra="forbid")

    #: Module id used by connectors in ``CONNECTOR_TYPE`` and by the API.
    id: str = Field(min_length=1, max_length=32)
    label: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    #: Finding fields the module declares: ``{name: {type, label, required}}``.
    fields: dict[str, dict] = Field(min_length=1, max_length=32)
    #: Field names that identify a finding (dedup key), in order.
    dedup_fields: list[str] = Field(min_length=1, max_length=3)
    #: Declared field shown as the finding's headline (defaults to the first
    #: dedup field).
    title_field: str | None = Field(default=None, max_length=64)
    #: Asset-inventory sections the module works with.
    asset_types: list[str] | None = Field(default=None, max_length=16)


class ModuleUpdateRequest(BaseModel):
    """Rename, redescribe or toggle a module. Fields are immutable."""

    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None


class ModuleOut(BaseModel):
    id: str
    label: str
    description: str | None = None
    finding_kind: str
    asset_types: list[str] = []
    fields: dict[str, dict] = {}
    dedup_fields: list[str] = []
    title_field: str | None = None
    #: "table" for a built-in write adapter, "generic" for generic storage.
    storage: str
    enabled: bool
    builtin: bool


class ModuleListResponse(BaseModel):
    modules: list[ModuleOut]
    generated_at: datetime


class FindingUpdateRequest(BaseModel):
    """Move a finding through triage.

    Only the status is editable: the payload is what the source reported, and
    rewriting it after the fact would make the audit trail describe something
    the source never said.
    """

    model_config = ConfigDict(extra="forbid")

    status: FindingStatus


class FindingOut(BaseModel):
    """One generically stored finding.

    ``payload`` carries exactly the fields the module declared (plus the
    platform-provided asset match and the source's own attributes), so a client
    renders it from the module's ``fields`` without knowing the module.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    module: str
    finding_kind: str
    connector_name: str
    job_id: uuid.UUID | None = None
    title: str
    matched_asset: str | None = None
    status: str
    payload: dict
    created_at: datetime
