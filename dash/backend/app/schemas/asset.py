"""Asset and service read schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import (
    AssetCriticality,
    AssetEnvironment,
    AssetGroupType,
    AssetMembershipSource,
    AssetStatus,
    AssetTagSource,
    AssetType,
    DataClassification,
    IdentifierType,
    OwnershipSource,
    ServiceState,
    ServiceTransport,
)


class AssetIdentifierRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    identifier_type: IdentifierType
    identifier_value: str
    confidence: int
    last_seen_at: datetime | None


class ServiceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    transport: ServiceTransport
    port: int
    state: ServiceState
    service_name: str | None
    product: str | None
    version: str | None
    cpe: str | None
    first_seen_at: datetime | None
    last_seen_at: datetime | None


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    canonical_name: str
    asset_type: AssetType
    status: AssetStatus
    operating_system: str | None
    manufacturer: str | None
    identity_confidence: int
    department: str | None
    business_function: str | None
    environment: AssetEnvironment
    criticality: AssetCriticality
    data_classification: DataClassification
    internet_exposed: bool
    owner_user_id: uuid.UUID | None
    context_json: dict[str, Any]
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    tags: list[AssetTagRead] = Field(default_factory=list)
    group_ids: list[uuid.UUID] = Field(default_factory=list)
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    last_assessed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AssetDetail(AssetRead):
    """An asset with its identifiers and services."""

    identifiers: list[AssetIdentifierRead]
    services: list[ServiceRead]


class AssetContextUpdate(BaseModel):
    canonical_name: str | None = Field(default=None, min_length=1, max_length=255)
    asset_type: AssetType | None = None
    status: AssetStatus | None = None
    department: str | None = Field(default=None, max_length=255)
    business_function: str | None = Field(default=None, max_length=255)
    environment: AssetEnvironment | None = None
    criticality: AssetCriticality | None = None
    data_classification: DataClassification | None = None
    internet_exposed: bool | None = None
    owner_user_id: uuid.UUID | None = None
    context_json: dict[str, Any] | None = None

    @model_validator(mode="after")
    def required_fields_cannot_be_cleared(self) -> AssetContextUpdate:
        for field in (
            "canonical_name",
            "asset_type",
            "status",
            "environment",
            "criticality",
            "data_classification",
            "internet_exposed",
            "context_json",
        ):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be null")
        return self


class AssetTagCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)
    color: str | None = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")


class AssetTagUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1024)
    color: str | None = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")


class AssetTagRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    description: str | None
    color: str | None
    created_at: datetime
    updated_at: datetime


class AssetTagAssignmentRead(BaseModel):
    asset_id: uuid.UUID
    tag: AssetTagRead
    source: AssetTagSource
    metadata_json: dict[str, Any]
    created_at: datetime


class AssetGroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    group_type: AssetGroupType
    site_id: uuid.UUID | None = None
    rule_json: dict[str, Any] | None = None
    priority: int = Field(default=0, ge=-100_000, le=100_000)
    owner_user_id: uuid.UUID | None = None
    enabled: bool = True

    @model_validator(mode="after")
    def rule_matches_type(self) -> AssetGroupCreate:
        if self.group_type == AssetGroupType.DYNAMIC and self.rule_json is None:
            raise ValueError("Dynamic groups require rule_json")
        if self.group_type == AssetGroupType.STATIC and self.rule_json is not None:
            raise ValueError("Static groups cannot define rule_json")
        return self


class AssetGroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    site_id: uuid.UUID | None = None
    rule_json: dict[str, Any] | None = None
    priority: int | None = Field(default=None, ge=-100_000, le=100_000)
    owner_user_id: uuid.UUID | None = None
    enabled: bool | None = None

    @model_validator(mode="after")
    def required_fields_cannot_be_cleared(self) -> AssetGroupUpdate:
        for field in ("name", "priority", "enabled"):
            if field in self.model_fields_set and getattr(self, field) is None:
                raise ValueError(f"{field} cannot be null")
        return self


class AssetGroupRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID | None
    name: str
    description: str | None
    group_type: AssetGroupType
    rule_json: dict[str, Any] | None
    priority: int
    owner_user_id: uuid.UUID | None
    enabled: bool
    last_evaluated_at: datetime | None
    member_count: int = 0
    created_at: datetime
    updated_at: datetime


class AssetGroupMembershipRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    group_id: uuid.UUID
    asset_id: uuid.UUID
    source: AssetMembershipSource
    explanation_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class StaticMembershipChange(BaseModel):
    asset_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)


class GroupPreviewRequest(BaseModel):
    rule_json: dict[str, Any]
    site_id: uuid.UUID | None = None
    limit: int = Field(default=100, ge=1, le=500)


class GroupPreviewMatch(BaseModel):
    asset_id: uuid.UUID
    canonical_name: str
    explanation: dict[str, Any]


class GroupPreviewResponse(BaseModel):
    matches: list[GroupPreviewMatch]
    total: int
    truncated: bool


class AssetBulkUpdate(BaseModel):
    asset_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)
    context: AssetContextUpdate | None = None
    add_tag_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    remove_tag_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    add_static_group_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    remove_static_group_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)


class AssetBulkResult(BaseModel):
    updated_assets: int
    tags_added: int
    tags_removed: int
    memberships_added: int
    memberships_removed: int


class DepartmentOwnerUpsert(BaseModel):
    department: str = Field(min_length=1, max_length=255)
    owner_user_id: uuid.UUID


class DepartmentOwnerRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    department: str
    owner_user_id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class OwnershipResolution(BaseModel):
    asset_id: uuid.UUID
    finding_id: uuid.UUID | None
    owner_user_id: uuid.UUID | None
    source: OwnershipSource
    source_id: uuid.UUID | None
    explanation: dict[str, Any]


class OwnershipHistoryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    finding_id: uuid.UUID | None
    owner_user_id: uuid.UUID | None
    source: OwnershipSource
    source_id: uuid.UUID | None
    explanation_json: dict[str, Any]
    created_at: datetime
