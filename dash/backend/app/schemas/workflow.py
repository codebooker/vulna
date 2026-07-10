"""Full-spectrum workflow schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import JobMode, WorkflowRunStatus, WorkflowStageStatus


class WorkflowRunCreate(BaseModel):
    site_id: uuid.UUID
    include_web: bool = False
    include_intrusive: bool = False


class WorkflowAdvance(BaseModel):
    """Complete or fail the current stage."""

    outcome: WorkflowStageStatus = WorkflowStageStatus.COMPLETED
    detail: str | None = None


class WorkflowApproval(BaseModel):
    approve: bool


class WorkflowRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    scan_job_id: uuid.UUID | None
    mode: JobMode
    status: WorkflowRunStatus
    include_web: bool
    include_intrusive: bool
    intrusive_approved: bool
    stages_json: list[dict[str, Any]]
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
