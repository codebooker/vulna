"""Software inventory, history, and EOL API schemas."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import EolStatus, SoftwareChangeType, SoftwareInventorySource


class EolEvaluation(BaseModel):
    status: EolStatus
    eol_date: date | None = None
    source: str
    source_url: str | None = None
    overridden: bool = False


class SoftwareRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    asset_id: uuid.UUID
    source: SoftwareInventorySource
    name: str
    package_key: str
    version: str
    architecture: str
    publisher: str | None
    product_key: str | None
    install_date: date | None
    first_seen_at: datetime
    last_seen_at: datetime
    removed_at: datetime | None
    metadata: dict[str, Any]
    eol: EolEvaluation


class SoftwareHistoryRead(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    software_item_id: uuid.UUID
    scan_job_id: uuid.UUID | None
    change_type: SoftwareChangeType
    previous_version: str | None
    observed_version: str | None
    observation: dict[str, Any]
    created_at: datetime


class EolOverrideCreate(BaseModel):
    status: EolStatus
    eol_date: date | None = None
    reason: str = Field(min_length=8, max_length=2048)
    expires_at: datetime | None = None


class EolOverrideRead(BaseModel):
    id: uuid.UUID
    software_item_id: uuid.UUID
    status: EolStatus
    eol_date: date | None
    reason: str
    expires_at: datetime | None
    active: bool
    created_at: datetime
    updated_at: datetime
