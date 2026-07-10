"""Audit-event read schema."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import ActorType


class AuditEventRead(BaseModel):
    """An audit event as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID | None
    actor_type: ActorType
    actor_id: uuid.UUID | None
    action: str
    target_type: str | None
    target_id: str | None
    source_ip: str | None
    request_id: str | None
    metadata_json: dict[str, Any]
    created_at: datetime
