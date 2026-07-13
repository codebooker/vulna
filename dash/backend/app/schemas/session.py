"""Revocable session and organization session-policy schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class SessionRead(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    authenticated_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    revoked_at: datetime | None
    revocation_reason: str | None
    device_name: str | None
    source_ip: str | None
    user_agent: str | None
    trusted_until: datetime | None
    current: bool = False
    active: bool
    privileged_until: datetime


class ReauthenticateRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class ReauthenticationResult(BaseModel):
    authenticated_at: datetime
    privileged_until: datetime


class SessionPolicyRead(BaseModel):
    idle_timeout_hours: int
    absolute_lifetime_days: int
    privileged_window_minutes: int
    max_concurrent_sessions: int
    trusted_device_days: int


class SessionPolicyUpdate(BaseModel):
    idle_timeout_hours: int | None = Field(default=None, ge=1, le=168)
    absolute_lifetime_days: int | None = Field(default=None, ge=1, le=365)
    privileged_window_minutes: int | None = Field(default=None, ge=1, le=120)
    max_concurrent_sessions: int | None = Field(default=None, ge=1, le=100)
    trusted_device_days: int | None = Field(default=None, ge=1, le=365)
