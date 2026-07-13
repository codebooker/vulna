"""One-way ticket connector and durable synchronization schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from app.models.enums import TicketConnectorType, TicketSyncAction, TicketSyncStatus


class TicketConnectorCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    connector_type: TicketConnectorType
    base_url: HttpUrl
    project_key: str = Field(min_length=1, max_length=512)
    config: dict[str, Any] = Field(default_factory=dict)
    secret: str = Field(min_length=1, max_length=16384)
    close_after_verification: bool = True
    timeout_seconds: int = Field(default=15, ge=1, le=60)


class TicketConnectorUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    base_url: HttpUrl | None = None
    project_key: str | None = Field(default=None, min_length=1, max_length=512)
    config: dict[str, Any] | None = None
    secret: str | None = Field(default=None, min_length=1, max_length=16384)
    enabled: bool | None = None
    close_after_verification: bool | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=60)


class TicketConnectorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    connector_type: TicketConnectorType
    base_url: str
    project_key: str
    config_json: dict[str, Any]
    has_secret: bool = True
    enabled: bool
    close_after_verification: bool
    timeout_seconds: int
    successful_test_at: datetime | None
    last_test_error: str | None
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, connector: Any) -> TicketConnectorRead:
        return cls.model_validate(connector)


class TicketConnectorTestRead(BaseModel):
    succeeded: bool
    tested_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class TicketSyncRequest(BaseModel):
    connector_id: uuid.UUID
    action: TicketSyncAction = TicketSyncAction.UPSERT
    explicit_close_reason: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def validate_close_reason(self) -> TicketSyncRequest:
        if self.action != TicketSyncAction.CLOSE and self.explicit_close_reason is not None:
            raise ValueError("explicit_close_reason is only valid for close actions")
        return self


class TicketSyncRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    connector_id: uuid.UUID
    finding_id: uuid.UUID
    status: TicketSyncStatus
    last_action: TicketSyncAction
    external_ticket_id: str | None
    external_ticket_url: str | None
    last_payload_hash: str | None
    last_error: str | None
    last_synced_at: datetime | None
    created_at: datetime
    updated_at: datetime


class TicketSyncEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    sync_id: uuid.UUID
    background_task_id: uuid.UUID | None
    action: TicketSyncAction
    status: TicketSyncStatus
    idempotency_key: str
    payload_hash: str
    response_json: dict[str, Any]
    error: str | None
    created_at: datetime
