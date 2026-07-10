"""Organization schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class OrganizationRead(BaseModel):
    """Organization as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    default_timezone: str
    settings_json: dict[str, Any]
    retention_policy_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class OrganizationUpdate(BaseModel):
    """Partial update for an organization (administrator only)."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    default_timezone: str | None = Field(default=None, max_length=64)
    settings_json: dict[str, Any] | None = None
    retention_policy_json: dict[str, Any] | None = None
