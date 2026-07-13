"""Software inventory, immutable history, EOL intelligence, and overrides (Phase 42)."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Date, DateTime, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import EolStatus, SoftwareChangeType, SoftwareInventorySource


class SoftwareInventoryItem(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Current materialized software/package state for an asset."""

    __tablename__ = "software_inventory_items"
    __table_args__ = (
        UniqueConstraint(
            "asset_id", "source", "package_key", "architecture", name="uq_software_asset_package"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source: Mapped[SoftwareInventorySource] = mapped_column(
        Enum(
            SoftwareInventorySource,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    package_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(255), nullable=False)
    architecture: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    publisher: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    install_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class SoftwareInventoryHistory(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only software observations and changes."""

    __tablename__ = "software_inventory_history"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    software_item_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("software_inventory_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    change_type: Mapped[SoftwareChangeType] = mapped_column(
        Enum(
            SoftwareChangeType,
            native_enum=False,
            length=24,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    previous_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observed_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observation_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class EolIntelligenceRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Provider-neutral EOL record; synchronization adapters populate this table."""

    __tablename__ = "eol_intelligence_records"
    __table_args__ = (
        UniqueConstraint(
            "provider", "product_key", "version_prefix", name="uq_eol_provider_product_version"
        ),
    )

    provider: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    product_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    version_prefix: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    status: Mapped[EolStatus] = mapped_column(
        Enum(
            EolStatus,
            native_enum=False,
            length=24,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    release_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    eol_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    source_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EolOverride(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Audited organization-owned override for one software inventory item."""

    __tablename__ = "eol_overrides"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    software_item_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("software_inventory_items.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[EolStatus] = mapped_column(
        Enum(
            EolStatus,
            native_enum=False,
            length=24,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    eol_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    reason: Mapped[str] = mapped_column(String(2048), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
