"""Change-event read schema."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import ChangeEventType


class ChangeEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    asset_id: uuid.UUID | None
    scan_job_id: uuid.UUID | None
    event_type: ChangeEventType
    severity: str
    summary: str
    before_json: dict[str, Any]
    after_json: dict[str, Any]
    created_at: datetime
