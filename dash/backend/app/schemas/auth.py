"""Authentication request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.models.enums import PrincipalType, UserRole


class LoginRequest(BaseModel):
    """Credentials submitted to obtain an access token."""

    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)
    device_name: str | None = Field(default=None, max_length=255)
    trust_device: bool = False


class TokenResponse(BaseModel):
    """A bearer access token."""

    access_token: str
    token_type: str = "bearer"  # noqa: S105  (label, not a secret)
    expires_in: int = Field(description="Token lifetime in seconds")
    session_id: uuid.UUID | None = None
    mfa_required: bool = False
    mfa_enrollment_required: bool = False
    mfa_methods: list[str] = Field(default_factory=list)
    mfa_grace_expires_at: datetime | None = None
    authentication_source: str = "local"
    is_break_glass: bool = False


class CurrentUserResponse(BaseModel):
    """The authenticated user's own profile."""

    id: uuid.UUID
    email: EmailStr | None
    full_name: str | None
    role: UserRole
    organization_id: uuid.UUID
    is_active: bool
    mfa_status: str = "not_enrolled"
    mfa_grace_expires_at: datetime | None = None
    authentication_source: str = "local"
    is_break_glass: bool = False
    principal_type: PrincipalType = PrincipalType.USER
    permissions: list[str] = Field(default_factory=list)
