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
    integrity_version: int
    integrity_algorithm: str
    integrity_key_id: str
    event_signature: str
    chain_sequence: int
    previous_hash: str
    chain_hash: str
    created_at: datetime


class AuditIntegrityRead(BaseModel):
    valid: bool
    events_checked: int
    failure: str | None
    last_hash: str | None
    legacy_events: int = 0
