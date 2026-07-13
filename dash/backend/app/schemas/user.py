"""User administration and lifecycle schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.enums import (
    AccountStatus,
    AuthenticationSource,
    SiteAccessMode,
    UserRole,
)


class UserRead(BaseModel):
    """User metadata; never contains password/token hashes or reusable secrets."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    email: EmailStr
    full_name: str | None
    role: UserRole
    is_active: bool
    account_status: AccountStatus
    authentication_source: AuthenticationSource
    site_access_mode: SiteAccessMode
    site_ids: list[uuid.UUID] = Field(default_factory=list)
    mfa_status: Literal["not_enrolled", "planned"] = "planned"
    last_login_at: datetime | None
    invited_at: datetime | None
    activated_at: datetime | None
    suspended_at: datetime | None
    deactivated_at: datetime | None
    password_changed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class UserCreate(BaseModel):
    """Create an invitation; administrators never choose a permanent password."""

    email: EmailStr
    full_name: str | None = Field(default=None, max_length=255)
    role: UserRole = UserRole.VIEWER
    site_access_mode: SiteAccessMode = SiteAccessMode.ASSIGNED
    site_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    # Accepted only to return a clear migration error for older clients.
    password: str | None = Field(default=None, min_length=12, max_length=1024)
    # Compatibility input: false creates a deactivated passwordless record.
    is_active: bool | None = None


class UserInvitationCreated(UserRead):
    """Creation response. The URL is returned once and never persisted."""

    invitation_url: str | None
    invitation_expires_at: datetime | None


class UserUpdate(BaseModel):
    """Partial metadata update; status and password use dedicated flows."""

    full_name: str | None = Field(default=None, max_length=255)
    role: UserRole | None = None
    is_active: bool | None = None
    # Kept in the request schema so old clients receive an explicit error.
    password: str | None = Field(default=None, min_length=12, max_length=1024)


class UserStatusUpdate(BaseModel):
    status: AccountStatus
    reason: str = Field(min_length=1, max_length=1024)


class UserSiteAccessUpdate(BaseModel):
    mode: SiteAccessMode
    site_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    reason: str | None = Field(default=None, max_length=1024)


class InvitationIssued(BaseModel):
    user: UserRead
    invitation_url: str
    expires_at: datetime


class PasswordResetIssued(BaseModel):
    user_id: uuid.UUID
    reset_url: str
    expires_at: datetime


class AcceptInvitationRequest(BaseModel):
    token: str = Field(min_length=16, max_length=512)
    password: str = Field(min_length=12, max_length=1024)
    full_name: str | None = Field(default=None, max_length=255)


class CompletePasswordResetRequest(BaseModel):
    token: str = Field(min_length=16, max_length=512)
    password: str = Field(min_length=12, max_length=1024)


class LifecycleEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    actor_user_id: uuid.UUID | None
    event_type: str
    previous_status: str | None
    new_status: str | None
    reason: str | None
    metadata_json: dict[str, object]
    created_at: datetime


class LoginHistoryRead(BaseModel):
    id: uuid.UUID
    outcome: Literal["succeeded", "failed", "denied"]
    source_ip: str | None
    user_agent: str | None
    occurred_at: datetime
