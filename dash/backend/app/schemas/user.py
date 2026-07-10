"""User schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.enums import UserRole


class UserRead(BaseModel):
    """User as returned by the API (never includes the password hash)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    email: EmailStr
    full_name: str | None
    role: UserRole
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime


class UserCreate(BaseModel):
    """Payload to create a user (administrator only)."""

    email: EmailStr
    password: str = Field(min_length=12, max_length=1024)
    full_name: str | None = Field(default=None, max_length=255)
    role: UserRole = UserRole.VIEWER
    is_active: bool = True


class UserUpdate(BaseModel):
    """Partial update for a user (administrator only)."""

    full_name: str | None = Field(default=None, max_length=255)
    role: UserRole | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=1024)
