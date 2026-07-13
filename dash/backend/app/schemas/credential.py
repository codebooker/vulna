"""One-way credential-vault and authenticated inventory API schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import (
    CredentialAssignmentTarget,
    CredentialAuthType,
    CredentialProtocol,
    CredentialTestStatus,
    CredentialUsageStatus,
)


class CredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    protocol: CredentialProtocol
    auth_type: CredentialAuthType
    username: str = Field(min_length=1, max_length=255)
    secret: str = Field(min_length=1, max_length=131_072, repr=False)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CredentialUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    username: str | None = Field(default=None, min_length=1, max_length=255)
    metadata: dict[str, Any] | None = None
    is_active: bool | None = None


class CredentialRotate(BaseModel):
    secret: str = Field(min_length=1, max_length=131_072, repr=False)


class CredentialRead(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str | None
    protocol: CredentialProtocol
    auth_type: CredentialAuthType
    username: str
    metadata: dict[str, Any]
    is_active: bool
    has_secret: bool = True
    current_version: int
    created_at: datetime
    updated_at: datetime


class CredentialAssignmentCreate(BaseModel):
    target_type: CredentialAssignmentTarget
    target_id: str = Field(min_length=1, max_length=255)


class CredentialAssignmentRead(BaseModel):
    id: uuid.UUID
    credential_id: uuid.UUID
    protocol: CredentialProtocol
    credential_name: str
    target_type: CredentialAssignmentTarget
    target_id: str
    site_id: uuid.UUID | None
    enabled: bool
    created_at: datetime


class CredentialResolveRequest(BaseModel):
    asset_id: uuid.UUID
    protocols: list[CredentialProtocol] = Field(min_length=1, max_length=2)
    network_id: uuid.UUID | None = None
    preset_key: str | None = Field(default=None, max_length=128)


class CredentialResolution(BaseModel):
    protocol: CredentialProtocol
    credential_id: uuid.UUID | None = None
    credential_name: str | None = None
    secret_version_id: uuid.UUID | None = None
    matched_level: CredentialAssignmentTarget | None = None
    conflict: bool = False
    candidates: list[uuid.UUID] = Field(default_factory=list)
    message: str


class CredentialTestRequest(BaseModel):
    asset_id: uuid.UUID
    probe_id: uuid.UUID
    network_id: uuid.UUID | None = None


class CredentialTestRead(BaseModel):
    id: uuid.UUID
    credential_id: uuid.UUID
    asset_id: uuid.UUID
    scan_job_id: uuid.UUID | None
    status: CredentialTestStatus
    message: str | None
    created_at: datetime
    finished_at: datetime | None


class CredentialUsageRead(BaseModel):
    id: uuid.UUID
    credential_id: uuid.UUID
    secret_version_id: uuid.UUID
    asset_id: uuid.UUID
    probe_id: uuid.UUID
    scan_job_id: uuid.UUID
    protocol: CredentialProtocol
    status: CredentialUsageStatus
    detail: str | None
    created_at: datetime
