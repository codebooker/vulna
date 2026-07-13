"""Passive inventory, reconciliation, analytics, and report-builder schemas."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from app.models.enums import (
    ConnectorRunStatus,
    InventoryAssetState,
    PassiveConnectorType,
    ReconciliationStatus,
    ReportTemplateRunStatus,
    ReportType,
)


class InventoryConnectorCreate(BaseModel):
    site_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)
    connector_type: PassiveConnectorType
    base_url: HttpUrl | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    secret: str | None = Field(default=None, min_length=1, max_length=32768)
    interval_minutes: int | None = Field(default=None, ge=5, le=525600)


class InventoryConnectorUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    base_url: HttpUrl | None = None
    config: dict[str, Any] | None = None
    secret: str | None = Field(default=None, min_length=1, max_length=32768)
    clear_secret: bool = False
    enabled: bool | None = None
    interval_minutes: int | None = Field(default=None, ge=5, le=525600)

    @model_validator(mode="after")
    def validate_secret_change(self) -> InventoryConnectorUpdate:
        if self.secret is not None and self.clear_secret:
            raise ValueError("secret and clear_secret cannot be used together")
        return self


class InventoryConnectorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    name: str
    connector_type: PassiveConnectorType
    base_url: str | None
    config_json: dict[str, Any]
    has_secret: bool
    has_source_data: bool
    source_filename: str | None
    source_sha256: str | None
    source_size_bytes: int | None
    source_uploaded_at: datetime | None
    enabled: bool
    interval_minutes: int | None
    next_run_at: datetime | None
    successful_test_at: datetime | None
    last_test_error: str | None
    last_run_at: datetime | None
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, connector: Any) -> InventoryConnectorRead:
        return cls.model_validate(connector)


class InventoryConnectorTestRead(BaseModel):
    succeeded: bool
    tested_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class ConnectorRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    connector_id: uuid.UUID
    background_task_id: uuid.UUID | None
    status: ConnectorRunStatus
    started_at: datetime | None
    finished_at: datetime | None
    records_read: int
    observations_created: int
    error: str | None
    has_cursor: bool
    created_at: datetime


class AssetObservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    connector_id: uuid.UUID
    run_id: uuid.UUID
    source_record_id: str
    observed_at: datetime
    identifiers_json: list[dict[str, Any]]
    attributes_json: dict[str, Any]
    payload_hash: str
    matched_asset_id: uuid.UUID | None
    created_at: datetime


class ReconciliationCandidateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    observation_id: uuid.UUID
    candidate_asset_id: uuid.UUID
    score: float
    reasons_json: list[dict[str, Any]]
    conflicts_json: list[dict[str, Any]]
    status: ReconciliationStatus
    merge_snapshot_json: dict[str, Any]
    decided_by_user_id: uuid.UUID | None
    decided_at: datetime | None
    split_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ReconciliationDecision(BaseModel):
    action: Literal["approve", "reject", "split"]


class AssetInventoryStateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    asset_id: uuid.UUID
    state: InventoryAssetState
    expected: bool
    discovered_at: datetime | None
    assessed_at: datetime | None
    last_observed_at: datetime | None
    missing_since: datetime | None
    stale_after_days: int
    created_at: datetime
    updated_at: datetime


class AssetInventoryStateUpdate(BaseModel):
    expected: bool | None = None
    stale_after_days: int | None = Field(default=None, ge=1, le=3650)


class ReportTemplateCreate(BaseModel):
    site_id: uuid.UUID | None = None
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    report_types: list[ReportType] = Field(min_length=1, max_length=20)
    sections: list[str] = Field(default_factory=list, max_length=20)
    filters: dict[str, Any] = Field(default_factory=dict)
    redaction: dict[str, Any] = Field(default_factory=dict)
    branding: dict[str, Any] = Field(default_factory=dict)
    export_password: str | None = Field(default=None, min_length=1, max_length=255)


class ReportTemplateUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    report_types: list[ReportType] | None = Field(default=None, min_length=1, max_length=20)
    sections: list[str] | None = Field(default=None, max_length=20)
    filters: dict[str, Any] | None = None
    redaction: dict[str, Any] | None = None
    branding: dict[str, Any] | None = None
    export_password: str | None = Field(default=None, min_length=1, max_length=255)
    clear_export_password: bool = False
    enabled: bool | None = None

    @model_validator(mode="after")
    def validate_password_change(self) -> ReportTemplateUpdate:
        if self.export_password is not None and self.clear_export_password:
            raise ValueError("export_password and clear_export_password cannot be used together")
        return self


class ReportTemplateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID | None
    name: str
    description: str | None
    version: int
    report_types_json: list[str]
    sections_json: list[str]
    filters_json: dict[str, Any]
    redaction_json: dict[str, Any]
    branding_json: dict[str, Any]
    has_export_password: bool
    enabled: bool
    created_by_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_model(cls, template: Any) -> ReportTemplateRead:
        return cls.model_validate(template)


class ReportTemplateScheduleCreate(BaseModel):
    interval_minutes: int = Field(ge=15, le=525600)
    next_run_at: datetime
    delivery: dict[str, Any] = Field(default_factory=lambda: {"notify": True})

    @field_validator("next_run_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("next_run_at must include a timezone")
        return value


class ReportTemplateScheduleUpdate(BaseModel):
    interval_minutes: int | None = Field(default=None, ge=15, le=525600)
    next_run_at: datetime | None = None
    delivery: dict[str, Any] | None = None
    enabled: bool | None = None

    @field_validator("next_run_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("next_run_at must include a timezone")
        return value


class ReportTemplateScheduleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID | None
    template_id: uuid.UUID
    interval_minutes: int
    next_run_at: datetime
    delivery_json: dict[str, Any]
    enabled: bool
    last_run_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ReportTemplateRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID | None
    template_id: uuid.UUID
    schedule_id: uuid.UUID | None
    background_task_id: uuid.UUID | None
    status: ReportTemplateRunStatus
    template_version: int
    parameters_json: dict[str, Any]
    report_ids_json: list[str]
    comparison_json: dict[str, Any]
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class ComparisonRequest(BaseModel):
    first_start: date
    first_end: date
    second_start: date
    second_end: date

    @model_validator(mode="after")
    def validate_ranges(self) -> ComparisonRequest:
        if self.first_start > self.first_end or self.second_start > self.second_end:
            raise ValueError("comparison period starts must not be after their ends")
        return self
