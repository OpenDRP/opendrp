import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.common import PaginatedResponse

ReportStatus = Literal["pending", "generating", "completed", "failed"]


class ReportBase(BaseModel):
    report_name: str
    status: ReportStatus


class ReportCreate(BaseModel):
    report_name: str | None = Field(default=None, max_length=255)

    @field_validator("report_name")
    @classmethod
    def normalize_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = " ".join(value.split()).strip()
        return cleaned or None


class ReportResponse(ReportBase):
    id: uuid.UUID
    created_by: uuid.UUID | None = None
    created_by_email: str | None = None
    file_path: str
    # ``False`` means the row says ``completed`` but the artifact is gone from
    # the report store (deleted out-of-band, or a rotated store volume). The UI
    # uses it to stop offering a download that can only 404.
    file_available: bool | None = None
    is_truncated: bool = False
    truncation_metadata: dict | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ReportListResponse(PaginatedResponse):
    items: list[ReportResponse]
