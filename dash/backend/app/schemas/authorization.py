"""Public Phase 39 authorization and API-token schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import GrantScopeType, PrincipalType, ServiceAccountStatus, UserRole


class PermissionRead(BaseModel):
    key: str
    label: str
    description: str
    scopes: list[str]
    high_risk: bool


class AuthorizationRoleRead(BaseModel):
    id: uuid.UUID
    key: str
    name: str
    description: str | None
    is_system: bool
    compatibility_role: UserRole | None
    permission_keys: list[str]
    created_at: datetime
    updated_at: datetime


class AuthorizationRoleCreate(BaseModel):
    key: str = Field(pattern=r"^[a-z][a-z0-9_]{1,62}[a-z0-9]$")
    name: str = Field(min_length=2, max_length=128)
    description: str | None = Field(default=None, max_length=1024)
    permission_keys: list[str] = Field(default_factory=list, max_length=256)


class AuthorizationRoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=128)
    description: str | None = Field(default=None, max_length=1024)
    permission_keys: list[str] | None = Field(default=None, max_length=256)


class ScopedGrantCreate(BaseModel):
    principal_type: PrincipalType
    principal_id: uuid.UUID
    role_id: uuid.UUID
    scope_type: GrantScopeType
    scope_id: uuid.UUID


class ScopedGrantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    principal_type: PrincipalType
    principal_id: uuid.UUID
    role_id: uuid.UUID
    role_key: str
    role_name: str
    scope_type: GrantScopeType
    scope_id: uuid.UUID
    created_at: datetime


class ServiceAccountCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    description: str | None = Field(default=None, max_length=1024)


class ServiceAccountUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    status: ServiceAccountStatus | None = None


class ServiceAccountRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str | None
    status: ServiceAccountStatus
    primary_role: UserRole
    last_used_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    expires_in_days: int = Field(ge=1, le=365)
    ip_restrictions: list[str] = Field(default_factory=list, max_length=100)


class ApiTokenRotate(BaseModel):
    expires_in_days: int = Field(default=90, ge=1, le=365)
    ip_restrictions: list[str] | None = Field(default=None, max_length=100)


class ApiTokenRead(BaseModel):
    id: uuid.UUID
    principal_type: PrincipalType
    principal_id: uuid.UUID
    name: str
    token_prefix: str
    has_secret: bool = True
    expires_at: datetime
    revoked_at: datetime | None
    ip_restrictions: list[str]
    last_used_at: datetime | None
    last_used_ip: str | None
    created_at: datetime


class ApiTokenIssued(ApiTokenRead):
    token: str = Field(description="One-time token value; it is never returned again")
