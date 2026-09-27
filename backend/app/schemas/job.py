import uuid
from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


JobStatus = Literal["pending", "running", "success", "partial", "error", "cancelled", "skipped"]
#: Job types are open by design: a connector declares its own (see
#: ``app/services/connector_manifest.py``), so the wire schema must not pin a
#: fixed literal set — an unknown type is data, not a validation error.
JobType = str


class JobResponse(BaseModel):
    id: uuid.UUID
    job_type: JobType
    status: JobStatus
    task_id: Optional[str] = None
    title: Optional[str] = None
    error_message: Optional[str] = None
    params: Optional[Any] = None
    result_summary: Optional[Any] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    lease_expires_at: Optional[datetime] = None
    last_heartbeat_at: Optional[datetime] = None
    attempt_count: int = 0
    claimed_by_connector: Optional[str] = None
    created_by: Optional[uuid.UUID] = None
    created_by_email: Optional[str] = None

    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


class ListJobsRequest(BaseModel):
    page: int = Field(1, ge=1)
    size: int = Field(20, ge=1, le=200)
    job_type: Optional[JobType] = None
    status: Optional[JobStatus] = None
    created_by: Optional[uuid.UUID] = None
    search: Optional[str] = None
