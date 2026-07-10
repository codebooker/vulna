"""Report request/read schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ReportFormat, ReportStatus, ReportType

# All artifact types produced when a request omits an explicit list.
ALL_REPORT_TYPES: list[ReportType] = list(ReportType)


class ReportCreate(BaseModel):
    """Request to generate one or more report artifacts for a scan job."""

    scan_job_id: uuid.UUID
    report_types: list[ReportType] = Field(default_factory=lambda: list(ALL_REPORT_TYPES))


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID | None
    scan_job_id: uuid.UUID | None
    report_type: ReportType
    format: ReportFormat
    status: ReportStatus
    template_version: str
    sha256: str | None
    size_bytes: int
    generated_by: uuid.UUID | None
    generated_at: datetime | None
    expires_at: datetime | None
    error: str | None
    parameters_json: dict[str, Any]
    created_at: datetime
