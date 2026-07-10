"""Finding read/update schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

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
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    resolved_at: datetime | None
    reopened_count: int
    created_at: datetime
    updated_at: datetime


class FindingUpdate(BaseModel):
    """Workflow update for a finding (Operator/Administrator)."""

    status: FindingStatus | None = None
    validation_status: ValidationStatus | None = None
