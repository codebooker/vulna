"""Site schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SiteRead(BaseModel):
    """Site as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    code: str
    description: str | None
    address: str | None
    timezone: str
    business_owner: str | None
    technical_owner: str | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime


class SiteCreate(BaseModel):
    """Payload to create a site (administrator only)."""

    name: str = Field(min_length=1, max_length=255)
    code: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=1024)
    address: str | None = Field(default=None, max_length=1024)
    timezone: str = Field(default="UTC", max_length=64)
    business_owner: str | None = Field(default=None, max_length=255)
    technical_owner: str | None = Field(default=None, max_length=255)
    tags: list[str] = Field(default_factory=list)


class SiteUpdate(BaseModel):
    """Partial update for a site (administrator only)."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    code: str | None = Field(default=None, min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=1024)
    address: str | None = Field(default=None, max_length=1024)
    timezone: str | None = Field(default=None, max_length=64)
    business_owner: str | None = Field(default=None, max_length=255)
    technical_owner: str | None = Field(default=None, max_length=255)
    tags: list[str] | None = None
