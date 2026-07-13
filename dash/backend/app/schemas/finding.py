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
    current_sla_calculation_id: uuid.UUID | None = None
    sla_started_at: datetime | None = None
    sla_paused_at: datetime | None = None
    sla_completed_at: datetime | None = None
    risk_acceptance_id: uuid.UUID | None
    false_positive_reason: str | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    last_verified_at: datetime | None
    resolved_at: datetime | None
    reopened_count: int
    created_at: datetime
    updated_at: datetime

    # Phase 41 cache of the latest immutable score snapshot.
    current_score_snapshot_id: uuid.UUID | None = None
    risk_score: float | None = None
    risk_profile_version: int | None = None
    risk_scored_at: datetime | None = None

    # Everyday-UX fields (Phase 22), computed at serialization time.
    priority: str = ""
    priority_rationale: str = ""
    confidence_label: str = ""

    @classmethod
    def from_model(cls, finding: Any) -> FindingRead:
        """Build a read model with the priority bucket, confidence label, and a
        display-safe (sanitized) copy of the evidence."""
        from app.services.evidence import sanitize_evidence
        from app.services.priority import classify, confidence_label
        from app.services.risk import priority_from_score

        read = cls.model_validate(finding)
        if finding.risk_score is not None:
            priority, rationale = priority_from_score(finding.risk_score)
        else:
            # Upgrade compatibility for an object not yet backfilled/scored.
            priority, rationale = classify(
                severity=finding.severity,
                confidence=finding.confidence,
                known_exploited=finding.known_exploited,
                epss_score=finding.epss_score,
                validation_status=finding.validation_status,
            )
        read.priority = priority
        read.priority_rationale = rationale
        read.confidence_label = confidence_label(finding.confidence)
        read.evidence_json = sanitize_evidence(finding.evidence_json)
        return read


class FindingUpdate(BaseModel):
    """Workflow/remediation update for a finding."""

    status: FindingStatus | None = None
    validation_status: ValidationStatus | None = None
    owner_user_id: uuid.UUID | None = None
    due_at: datetime | None = None
    false_positive_reason: str | None = None


class BulkFindingAction(BaseModel):
    """Apply one workflow action to several findings at once."""

    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)
    action: str = Field(description="assign | false_positive | start_remediation | triage")
    owner_user_id: uuid.UUID | None = None
    false_positive_reason: str | None = Field(default=None, max_length=2000)


class BulkFindingResult(BaseModel):
    updated: list[uuid.UUID]
    skipped: int


class FindingNoteCreate(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


class FindingNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    author_user_id: uuid.UUID | None
    body: str
    created_at: datetime
