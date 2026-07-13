"""Guided first-run (onboarding) schemas (Phase 19)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class OnboardingStateRead(BaseModel):
    """Resumable wizard state."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    current_step: str
    completed_steps: list[str] = Field(validation_alias="completed_steps_json")
    site_id: uuid.UUID | None
    scope_id: uuid.UUID | None
    first_job_id: uuid.UUID | None
    demo_used: bool
    dismissed: bool
    completed_at: datetime | None


class CompleteStepRequest(BaseModel):
    step: str
    site_id: uuid.UUID | None = None
    scope_id: uuid.UUID | None = None
    first_job_id: uuid.UUID | None = None
    demo_used: bool | None = None


class RecoveryCodesResponse(BaseModel):
    """Plaintext recovery codes — shown exactly once."""

    codes: list[str]
    generated_at: datetime


class NetworkCandidatesResponse(BaseModel):
    candidates: list[str]
    source: str
    note: str


class ScopePreviewRequest(BaseModel):
    cidr: str
    allow_public: bool = False


class ScopePreviewResponse(BaseModel):
    cidr: str
    host_estimate: int
    is_private: bool
    warnings: list[str]
    requires_confirmation: bool


class ScanPreset(BaseModel):
    key: str
    name: str
    mode: str
    description: str
    checks: list[str]
    intrusive: bool
    active_web: bool
    uses_credentials: bool
    resource_class: str
    duration_class: str


class ScanPresetsResponse(BaseModel):
    presets: list[ScanPreset]


class ScanSummaryRequest(BaseModel):
    preset: str = "standard"
    targets: list[str]
    demo: bool = False


class ScanSummaryResponse(BaseModel):
    preset: str
    preset_name: str
    targets: list[str]
    host_estimate: int
    checks: list[str]
    intrusive: bool
    active_web: bool
    uses_credentials: bool
    resource_class: str
    duration_class: str
    demo: bool
    data_retention: str


class DemoTargetResponse(BaseModel):
    cidr: str
    note: str


class ProfilePlanQuestion(BaseModel):
    key: str
    label: str
    kind: Literal["boolean", "number", "text", "select"]
    options: list[str] = Field(default_factory=list)
    required: bool = False


class ProfileRecommendation(BaseModel):
    capability: str
    status: Literal["available", "planned"]
    reason: str
    route: str | None = None


class ProfilePlanRead(BaseModel):
    experience_profile: str
    questions: list[ProfilePlanQuestion]
    answers: dict[str, Any]
    recommendations: list[ProfileRecommendation]
    updated_at: datetime | None = None


class ProfilePlanUpdate(BaseModel):
    answers: dict[str, Any] = Field(default_factory=dict)
