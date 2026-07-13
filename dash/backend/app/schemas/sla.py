"""SLA policy, deadline, exception, metric, and guidance API schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    RemediationClassification,
    SlaCalculationSource,
    SlaExceptionStatus,
    SlaHistoryEvent,
)


class SlaPolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    priority: int = Field(ge=1, le=10000)
    enabled: bool = True
    match: dict[str, Any] = Field(default_factory=dict)
    due_days: dict[str, int] = Field(default_factory=dict)
    pause_on_risk_acceptance: bool = False


class SlaPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    priority: int | None = Field(default=None, ge=1, le=10000)
    enabled: bool | None = None
    match: dict[str, Any] | None = None
    due_days: dict[str, int] | None = None
    pause_on_risk_acceptance: bool | None = None


class SlaPolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str | None
    priority: int
    enabled: bool
    match_json: dict[str, Any]
    due_days_json: dict[str, int]
    pause_on_risk_acceptance: bool
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class SlaCalculationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    finding_id: uuid.UUID
    policy_id: uuid.UUID | None
    previous_calculation_id: uuid.UUID | None
    source: SlaCalculationSource
    started_at: datetime
    due_at: datetime
    calculation_json: dict[str, Any]
    created_by_user_id: uuid.UUID | None
    created_at: datetime


class SlaExceptionCreate(BaseModel):
    requested_due_at: datetime
    reason: str = Field(min_length=10, max_length=4000)


class SlaExceptionDecision(BaseModel):
    approve: bool
    review_notes: str | None = Field(default=None, max_length=4000)


class SlaExceptionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    finding_id: uuid.UUID
    requested_due_at: datetime
    reason: str
    status: SlaExceptionStatus
    requested_by_user_id: uuid.UUID | None
    reviewed_by_user_id: uuid.UUID | None
    reviewed_at: datetime | None
    review_notes: str | None
    resulting_calculation_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class SlaHistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    finding_id: uuid.UUID
    event: SlaHistoryEvent
    actor_user_id: uuid.UUID | None
    metadata_json: dict[str, Any]
    created_at: datetime


class GuidanceStep(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    instruction: str = Field(min_length=1, max_length=4000)


class RemediationGuidanceCreate(BaseModel):
    classification: RemediationClassification
    summary: str = Field(min_length=1, max_length=1024)
    steps: list[GuidanceStep] = Field(min_length=1, max_length=50)
    validation_steps: list[GuidanceStep] = Field(min_length=1, max_length=50)
    references: list[str] = Field(default_factory=list, max_length=25)
    source: str = Field(min_length=1, max_length=255)


class RemediationGuidanceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    finding_id: uuid.UUID
    classification: RemediationClassification
    summary: str
    steps_json: list[dict[str, Any]]
    validation_steps_json: list[dict[str, Any]]
    references_json: list[str]
    source: str
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class SlaMetricsRead(BaseModel):
    total_with_sla: int
    open: int
    overdue: int
    due_within_7_days: int
    completed: int
    completed_on_time: int
    on_time_percentage: float | None
    by_severity: dict[str, int]
    generated_at: datetime
