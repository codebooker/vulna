"""Administrator-facing durable task schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import BackgroundTaskStatus


class BackgroundTaskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID | None
    task_type: str
    payload_json: dict[str, Any]
    idempotency_key: str
    status: BackgroundTaskStatus
    priority: int
    scheduled_at: datetime
    attempts: int
    max_attempts: int
    lease_owner: str | None
    lease_expires_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    cancel_requested_at: datetime | None
    cancelled_at: datetime | None
    dead_lettered_at: datetime | None
    last_error: str | None
    result_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class WorkerHeartbeatRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    worker_id: str
    kind: str
    hostname: str
    process_id: int
    status: str
    current_task_id: uuid.UUID | None
    started_at: datetime
    last_seen_at: datetime
    metadata_json: dict[str, Any]


class TaskHealthRead(BaseModel):
    counts: dict[str, int]
    workers: list[WorkerHeartbeatRead]
    stale_after_seconds: int
