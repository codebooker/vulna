"""Authentication request/response schemas."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, EmailStr, Field

from app.models.enums import UserRole


class LoginRequest(BaseModel):
    """Credentials submitted to obtain an access token."""

    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)


class TokenResponse(BaseModel):
    """A bearer access token."""

    access_token: str
    token_type: str = "bearer"  # noqa: S105  (label, not a secret)
    expires_in: int = Field(description="Token lifetime in seconds")


class CurrentUserResponse(BaseModel):
    """The authenticated user's own profile."""

    id: uuid.UUID
    email: EmailStr
    full_name: str | None
    role: UserRole
    organization_id: uuid.UUID
    is_active: bool
