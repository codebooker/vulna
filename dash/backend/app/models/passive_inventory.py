"""Passive inventory, reconciliation, analytics, and report-builder models."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    ConnectorRunStatus,
    InventoryAssetState,
    PassiveConnectorType,
    ReconciliationStatus,
    ReportTemplateRunStatus,
)


class InventoryConnector(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Organization-owned configuration for a read-only inventory source."""

    __tablename__ = "inventory_connectors"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_inventory_connector_org_name"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    connector_type: Mapped[PassiveConnectorType] = mapped_column(
        Enum(
            PassiveConnectorType,
            native_enum=False,
            length=32,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    base_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    encrypted_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    successful_test_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_test_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    @property
    def has_secret(self) -> bool:
        return bool(self.encrypted_secret)


class ConnectorRun(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One durable execution and its bounded outcome metadata."""

    __tablename__ = "connector_runs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("inventory_connectors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    background_task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("background_tasks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[ConnectorRunStatus] = mapped_column(
        Enum(
            ConnectorRunStatus,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=ConnectorRunStatus.QUEUED,
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    records_read: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observations_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    cursor_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    @property
    def has_cursor(self) -> bool:
        return bool(self.cursor_json)


class AssetObservation(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only source record. Raw secret material is never accepted."""

    __tablename__ = "asset_observations"
    __table_args__ = (
        UniqueConstraint(
            "run_id", "source_record_id", name="uq_asset_observation_run_source_record"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("inventory_connectors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("connector_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_record_id: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    identifiers_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    attributes_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    matched_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )


class AssetSourceLink(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Current, reversible mapping from a source identity to a Vulna asset."""

    __tablename__ = "asset_source_links"
    __table_args__ = (
        UniqueConstraint(
            "connector_id", "source_record_id", name="uq_asset_source_link_connector_record"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("inventory_connectors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_record_id: Mapped[str] = mapped_column(String(512), nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    identifiers_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)


class AssetInventoryState(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Materialized lifecycle state derived from append-only events."""

    __tablename__ = "asset_inventory_states"
    __table_args__ = (UniqueConstraint("asset_id", name="uq_asset_inventory_state_asset"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    state: Mapped[InventoryAssetState] = mapped_column(
        Enum(
            InventoryAssetState,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=InventoryAssetState.DISCOVERED,
        index=True,
    )
    expected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    missing_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stale_after_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)


class InventoryLifecycleEvent(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only explanation for each lifecycle transition."""

    __tablename__ = "inventory_lifecycle_events"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    previous_state: Mapped[InventoryAssetState | None] = mapped_column(
        Enum(
            InventoryAssetState,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=True,
    )
    new_state: Mapped[InventoryAssetState] = mapped_column(
        Enum(
            InventoryAssetState,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    source_observation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("asset_observations.id", ondelete="SET NULL"), nullable=True
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class ReconciliationCandidate(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Scored and explainable candidate with an immutable merge snapshot."""

    __tablename__ = "reconciliation_candidates"
    __table_args__ = (
        UniqueConstraint(
            "observation_id", "candidate_asset_id", name="uq_reconciliation_observation_asset"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    observation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset_observations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    candidate_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    reasons_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    conflicts_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[ReconciliationStatus] = mapped_column(
        Enum(
            ReconciliationStatus,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=ReconciliationStatus.PENDING,
        index=True,
    )
    merge_snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    decided_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    split_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DailyFindingAggregate(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Daily server-side finding and inventory snapshot for trend queries."""

    __tablename__ = "daily_finding_aggregates"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "scope_key",
            "aggregate_date",
            name="uq_daily_aggregate_org_scope_date",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=True, index=True
    )
    scope_key: Mapped[str] = mapped_column(String(36), nullable=False)
    aggregate_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    finding_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_open: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_resolved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_breached: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity_json: Mapped[dict[str, int]] = mapped_column(JSON, nullable=False, default=dict)
    inventory_state_json: Mapped[dict[str, int]] = mapped_column(JSON, nullable=False, default=dict)


class AnalyticsCacheEntry(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Organization-scoped cache with explicit expiry and no authorization reuse."""

    __tablename__ = "analytics_cache_entries"
    __table_args__ = (
        UniqueConstraint("organization_id", "cache_key", name="uq_analytics_cache_scope_key"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=True, index=True
    )
    cache_key: Mapped[str] = mapped_column(String(255), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class ReportTemplate(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Reusable, versioned report definition with one-way secret response fields."""

    __tablename__ = "report_templates"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_report_template_org_name"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    report_types_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    sections_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    filters_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    redaction_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    branding_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    encrypted_export_password: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    @property
    def has_export_password(self) -> bool:
        return bool(self.encrypted_export_password)


class ReportTemplateSchedule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Worker-backed generation and delivery schedule."""

    __tablename__ = "report_template_schedules"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=True, index=True
    )
    template_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("report_templates.id", ondelete="CASCADE"), nullable=False, index=True
    )
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    delivery_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReportTemplateRun(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Immutable template version, filters, and outputs used for one execution."""

    __tablename__ = "report_template_runs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=True, index=True
    )
    template_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("report_templates.id", ondelete="CASCADE"), nullable=False, index=True
    )
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("report_template_schedules.id", ondelete="SET NULL"), nullable=True
    )
    background_task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("background_tasks.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[ReportTemplateRunStatus] = mapped_column(
        Enum(
            ReportTemplateRunStatus,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=ReportTemplateRunStatus.QUEUED,
        index=True,
    )
    template_version: Mapped[int] = mapped_column(Integer, nullable=False)
    parameters_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    report_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    comparison_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    encrypted_export_password: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
