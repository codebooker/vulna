"""Scan-job schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import JobMode, JobStatus


class JobCreate(BaseModel):
    """Operator request to create (and sign) a scan job for a probe."""

    probe_id: uuid.UUID
    targets: list[str] = Field(min_length=1)
    mode: JobMode = JobMode.VULNERABILITY_ASSESSMENT
    not_before: datetime | None = None
    expires_at: datetime | None = None


class JobRead(BaseModel):
    """A scan job as returned by the API (excludes the raw signed envelope)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    probe_id: uuid.UUID
    mode: JobMode
    status: JobStatus
    requested_targets_json: list[str]
    policy_version: int
    not_before: datetime
    expires_at: datetime
    created_by: uuid.UUID | None
    offered_at: datetime | None
    accepted_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    cancel_requested_at: datetime | None
    error_code: str | None
    error_message: str | None
    summary_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class JobStatusUpdate(BaseModel):
    """Status report from a probe about a job it was offered."""

    status: JobStatus
    error_code: str | None = Field(default=None, max_length=64)
    error_message: str | None = Field(default=None, max_length=2048)
    summary: dict[str, Any] | None = None


class ResultIngestSummary(BaseModel):
    """Summary returned after ingesting a scanner result upload."""

    hosts_seen: int
    assets_created: int
    assets_updated: int
    services_upserted: int
