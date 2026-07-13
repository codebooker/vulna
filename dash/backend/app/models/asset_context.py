"""Normalized asset context, grouping, and ownership history (Phase 40)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    AssetGroupType,
    AssetMembershipSource,
    AssetTagSource,
    OwnershipSource,
)


class AssetTag(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An organization-owned normalized tag definition."""

    __tablename__ = "asset_tags"
    __table_args__ = (
        UniqueConstraint("organization_id", "normalized_name", name="uq_asset_tag_org_name"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    color: Mapped[str | None] = mapped_column(String(16), nullable=True)


class AssetTagAssignment(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A tag assignment with source and lossless migration metadata."""

    __tablename__ = "asset_tag_assignments"
    __table_args__ = (UniqueConstraint("asset_id", "tag_id", name="uq_asset_tag_assignment"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tag_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset_tags.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source: Mapped[AssetTagSource] = mapped_column(
        Enum(
            AssetTagSource,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=AssetTagSource.MANUAL,
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    assigned_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class AssetGroup(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A static or safely evaluated dynamic group."""

    __tablename__ = "asset_groups"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_asset_group_org_name"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    group_type: Mapped[AssetGroupType] = mapped_column(
        Enum(
            AssetGroupType,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    rule_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    last_evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AssetGroupMembership(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Materialized group membership, including human-readable explanation."""

    __tablename__ = "asset_group_memberships"
    __table_args__ = (UniqueConstraint("group_id", "asset_id", name="uq_asset_group_membership"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset_groups.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source: Mapped[AssetMembershipSource] = mapped_column(
        Enum(
            AssetMembershipSource,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    explanation_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class DepartmentOwner(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Organization-level fallback owner for an asset department."""

    __tablename__ = "department_owners"
    __table_args__ = (
        UniqueConstraint("organization_id", "department_key", name="uq_department_owner"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    department: Mapped[str] = mapped_column(String(255), nullable=False)
    department_key: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )


class AssetOwnershipHistory(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only snapshots of effective asset/finding ownership."""

    __tablename__ = "asset_ownership_history"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    source: Mapped[OwnershipSource] = mapped_column(
        Enum(
            OwnershipSource,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    source_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    explanation_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
