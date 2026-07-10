"""Finding read/update schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import FindingStatus, FindingType, Severity, ValidationStatus


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    asset_id: uuid.UUID | None
    service_id: uuid.UUID | None
    scan_job_id: uuid.UUID | None
    scanner_name: str
    scanner_finding_id: str | None
    finding_type: FindingType
    title: str
    description: str | None
    severity: Severity
    cvss_score: float | None
    cvss_vector: str | None
    cve_ids_json: list[str]
    cwe_ids_json: list[str]
    confidence: int
    known_exploited: bool
    epss_score: float | None
    epss_percentile: float | None
    validation_status: ValidationStatus
    evidence_json: dict[str, Any]
    remediation: str | None
    references_json: list[str]
    status: FindingStatus
    owner_user_id: uuid.UUID | None
    due_at: datetime | None
    risk_acceptance_id: uuid.UUID | None
    false_positive_reason: str | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    last_verified_at: datetime | None
    resolved_at: datetime | None
    reopened_count: int
    created_at: datetime
    updated_at: datetime


class FindingUpdate(BaseModel):
    """Workflow/remediation update for a finding."""

    status: FindingStatus | None = None
    validation_status: ValidationStatus | None = None
    owner_user_id: uuid.UUID | None = None
    due_at: datetime | None = None
    false_positive_reason: str | None = None


class FindingNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


class FindingNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    author_user_id: uuid.UUID | None
    body: str
    created_at: datetime
