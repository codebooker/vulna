"""Organization-scoped SCIM provisioning state (Phase 38)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import UserRole


class ScimToken(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A one-time-disclosed bearer token; only its SHA-256 digest is stored."""

    __tablename__ = "scim_tokens"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(24), nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    rotated_from_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scim_tokens.id", ondelete="SET NULL"), nullable=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ScimGroup(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A provisioned group plus its local role/site mapping targets."""

    __tablename__ = "scim_groups"
    __table_args__ = (
        UniqueConstraint("organization_id", "display_name", name="uq_scim_group_org_name"),
        UniqueConstraint("organization_id", "external_id", name="uq_scim_group_org_external"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    mapped_role: Mapped[UserRole | None] = mapped_column(
        Enum(UserRole, native_enum=False, length=32, validate_strings=True), nullable=True
    )
    grants_all_sites: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Reserved for Phase 40. It is intentionally not serialized by Phase 38 APIs.
    asset_group_targets_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )


class ScimGroupMember(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Direct SCIM group membership. Nested groups are not accepted."""

    __tablename__ = "scim_group_members"
    __table_args__ = (UniqueConstraint("group_id", "user_id", name="uq_scim_group_member"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scim_groups.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )


class ScimGroupSiteMapping(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A local site granted by membership in a SCIM group."""

    __tablename__ = "scim_group_site_mappings"
    __table_args__ = (UniqueConstraint("group_id", "site_id", name="uq_scim_group_site_mapping"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scim_groups.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )


class ScimProvisioningLog(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Sanitized immutable SCIM request/result history."""

    __tablename__ = "scim_provisioning_logs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scim_tokens.id", ondelete="SET NULL"), nullable=True, index=True
    )
    operation: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    detail: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    changes_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class ScimRateLimitWindow(UUIDPrimaryKeyMixin, Base):
    """Database-backed fixed-window request counter for a SCIM token."""

    __tablename__ = "scim_rate_limit_windows"
    __table_args__ = (
        UniqueConstraint("token_id", "window_started_at", name="uq_scim_rate_window"),
    )

    token_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scim_tokens.id", ondelete="CASCADE"), nullable=False, index=True
    )
    window_started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    request_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
