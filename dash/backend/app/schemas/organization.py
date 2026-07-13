"""Organization schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ExperienceProfile


class OrganizationRead(BaseModel):
    """Organization as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    default_timezone: str
    settings_json: dict[str, Any]
    retention_policy_json: dict[str, Any]
    experience_profile: ExperienceProfile
    feature_overrides_json: dict[str, bool]
    created_at: datetime
    updated_at: datetime


class OrganizationUpdate(BaseModel):
    """Partial update for an organization (administrator only)."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    default_timezone: str | None = Field(default=None, max_length=64)
    settings_json: dict[str, Any] | None = None
    retention_policy_json: dict[str, Any] | None = None


class ExperienceChange(BaseModel):
    """A proposed or applied presentation-profile selection."""

    experience_profile: ExperienceProfile
    feature_overrides: dict[str, bool] = Field(default_factory=dict)


class CapabilityStatus(BaseModel):
    key: str
    name: str
    status: Literal["available", "planned"]
    production_ready: bool = False


class ExperienceRead(ExperienceChange):
    route_visibility: dict[str, bool]
    core_routes: list[str]
    advanced_routes: list[str]
    capabilities: list[CapabilityStatus]
    note: str


class ExperiencePreview(ExperienceRead):
    changed_routes: list[str]
