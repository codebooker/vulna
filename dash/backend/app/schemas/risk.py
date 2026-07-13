"""Public schemas for explainable risk and remediation planning."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import (
    FindingDecisionStatus,
    FindingDecisionType,
    FindingStatus,
    RemediationKeyType,
    RemediationSuggestionStatus,
    RemediationUnitStatus,
)


class RiskProfileCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    weights: dict[str, float]
    make_default: bool = True


class RiskProfileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    version: int
    description: str | None
    weights_json: dict[str, float]
    is_default: bool
    created_by_user_id: uuid.UUID | None
    created_at: datetime


class FindingScoreRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    risk_profile_id: uuid.UUID
    profile_version: int
    score: float
    priority: str = ""
    weighted_sum: float
    positive_maximum: float
    source_values_json: dict[str, Any]
    factors_json: list[dict[str, Any]]
    input_hash: str
    created_at: datetime

    @classmethod
    def from_model(cls, snapshot: Any) -> FindingScoreRead:
        from app.services.risk import priority_from_score

        result = cls.model_validate(snapshot)
        result.priority = priority_from_score(snapshot.score)[0]
        return result


class RemediationUnitCreate(BaseModel):
    site_id: uuid.UUID
    key_type: RemediationKeyType = RemediationKeyType.MANUAL
    exact_key: str = Field(min_length=1, max_length=512)
    title: str = Field(min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=8000)
    owner_user_id: uuid.UUID | None = None
    finding_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)


class RemediationUnitUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=8000)
    status: RemediationUnitStatus | None = None
    owner_user_id: uuid.UUID | None = None


class RemediationUnitRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    key_type: RemediationKeyType
    exact_key: str
    title: str
    description: str | None
    status: RemediationUnitStatus
    owner_user_id: uuid.UUID | None
    automatically_created: bool
    finding_count: int = 0
    projected_risk_reduction: float = 0
    created_at: datetime
    updated_at: datetime


class RemediationMembershipRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    remediation_unit_id: uuid.UUID
    finding_id: uuid.UUID
    match_basis_json: dict[str, Any]
    added_by_user_id: uuid.UUID | None
    created_at: datetime


class AutoGroupRequest(BaseModel):
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)


class AutoGroupResult(BaseModel):
    units_created: int
    memberships_created: int


class FuzzySuggestionRequest(BaseModel):
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)
    threshold: float = Field(default=0.5, ge=0.1, le=1.0)


class FuzzySuggestionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    site_id: uuid.UUID
    remediation_unit_id: uuid.UUID
    finding_id: uuid.UUID
    similarity: float
    explanation_json: dict[str, Any]
    status: RemediationSuggestionStatus
    reviewed_by_user_id: uuid.UUID | None
    reviewed_at: datetime | None
    created_at: datetime


class SuggestionReview(BaseModel):
    accept: bool


class FindingDecisionCreate(BaseModel):
    decision_type: FindingDecisionType
    reason: str = Field(min_length=1, max_length=8000)
    evidence: list[dict[str, Any]] = Field(min_length=1, max_length=100)
    expires_at: datetime
    duplicate_of_finding_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def validate_duplicate(self) -> FindingDecisionCreate:
        if (self.decision_type == FindingDecisionType.DUPLICATE) != (
            self.duplicate_of_finding_id is not None
        ):
            raise ValueError("duplicate decisions require duplicate_of_finding_id")
        if any(not item.get("type") or not item.get("reference") for item in self.evidence):
            raise ValueError("each evidence item requires type and reference")
        if len(json.dumps(self.evidence, sort_keys=True, default=str)) > 65_536:
            raise ValueError("decision evidence is too large")
        return self


class FindingDecisionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    finding_id: uuid.UUID
    decision_type: FindingDecisionType
    status: FindingDecisionStatus
    reason: str
    evidence_json: list[dict[str, Any]]
    expires_at: datetime
    duplicate_of_finding_id: uuid.UUID | None
    previous_status: FindingStatus
    created_by_user_id: uuid.UUID | None
    revoked_by_user_id: uuid.UUID | None
    revoked_at: datetime | None
    created_at: datetime
