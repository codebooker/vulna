"""Administrator-facing SCIM token, mapping, and log schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, model_validator

from app.models.enums import UserRole


class ScimTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class ScimTokenRead(BaseModel):
    id: uuid.UUID
    name: str
    token_prefix: str
    has_secret: bool = True
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    last_used_at: datetime | None
    last_used_ip: str | None


class ScimTokenIssued(ScimTokenRead):
    token: str


class ScimGroupMappingUpdate(BaseModel):
    role: UserRole | None = None
    grants_all_sites: bool = False
    site_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    asset_group_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def validate_site_mode(self) -> ScimGroupMappingUpdate:
        if self.grants_all_sites and self.site_ids:
            raise ValueError("site_ids must be empty when grants_all_sites is true")
        if len(set(self.site_ids)) != len(self.site_ids):
            raise ValueError("site_ids must not contain duplicates")
        if len(set(self.asset_group_ids)) != len(self.asset_group_ids):
            raise ValueError("asset_group_ids must not contain duplicates")
        return self


class ScimGroupMappingRead(BaseModel):
    id: uuid.UUID
    external_id: str | None
    display_name: str
    member_count: int
    role: UserRole | None
    grants_all_sites: bool
    site_ids: list[uuid.UUID]
    asset_group_ids: list[uuid.UUID]
    created_at: datetime
    updated_at: datetime


class ScimMappingPreview(BaseModel):
    group_id: uuid.UUID
    affected_users: int
    role: UserRole | None
    grants_all_sites: bool
    site_ids: list[uuid.UUID]
    asset_group_ids: list[uuid.UUID]
    users: list[dict[str, object]]


class ScimProvisioningLogRead(BaseModel):
    id: uuid.UUID
    operation: str
    resource_type: str | None
    resource_id: str | None
    external_id: str | None
    status_code: int
    succeeded: bool
    detail: str | None
    request_id: str | None
    source_ip: str | None
    changes: dict[str, object]
    created_at: datetime


class ScimLogPage(BaseModel):
    items: list[ScimProvisioningLogRead]
    total: int
    limit: int
    offset: int
