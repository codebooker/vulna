"""Risk-acceptance schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import RiskAcceptanceStatus


class RiskAcceptanceCreate(BaseModel):
    """Request to accept a finding's risk for a bounded period."""

    reason: str = Field(min_length=1, max_length=4000)
    compensating_controls: str | None = Field(default=None, max_length=4000)
    starts_at: datetime | None = None
    expires_at: datetime  # required — acceptances expire by default


class RiskAcceptanceDecision(BaseModel):
    """Approve or reject a pending risk acceptance (approver/administrator)."""

    approve: bool
    review_notes: str | None = Field(default=None, max_length=4000)


class ExpiryResult(BaseModel):
    """Outcome of a risk-acceptance expiry sweep."""

    expired: int


class RiskAcceptanceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    finding_id: uuid.UUID
    requested_by: uuid.UUID | None
    approved_by: uuid.UUID | None
    reason: str
    compensating_controls: str | None
    starts_at: datetime | None
    expires_at: datetime
    status: RiskAcceptanceStatus
    review_notes: str | None
    created_at: datetime
    updated_at: datetime
