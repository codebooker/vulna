"""Schemas for scheduled scans."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScanScheduleCreate(BaseModel):
    network_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    interval_minutes: int = Field(ge=5, description="Minimum 5 minutes between runs")
    preset_key: str = Field(default="standard", min_length=1, max_length=128)
    enabled: bool = True
    # Optional first run; defaults to now + interval.
    first_run_at: datetime | None = None


class ScanScheduleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    interval_minutes: int | None = Field(default=None, ge=5)
    preset_key: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None
    next_run_at: datetime | None = None


class ScanScheduleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    network_id: uuid.UUID
    name: str
    mode: str
    interval_minutes: int
    preset_key: str
    preset_version: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_job_id: uuid.UUID | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime
