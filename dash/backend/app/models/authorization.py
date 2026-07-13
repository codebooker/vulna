"""Database roles, scoped grants, service principals, and API tokens."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
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
from app.models.enums import GrantScopeType, PrincipalType, ServiceAccountStatus, UserRole


class AuthorizationRole(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "authorization_roles"
    __table_args__ = (
        UniqueConstraint("organization_id", "key", name="uq_authorization_role_org_key"),
        UniqueConstraint("organization_id", "name", name="uq_authorization_role_org_name"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    compatibility_role: Mapped[UserRole | None] = mapped_column(
        Enum(
            UserRole,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=True,
    )


class RolePermission(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role_id", "permission_key", name="uq_role_permission"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("authorization_roles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    permission_key: Mapped[str] = mapped_column(String(128), nullable=False, index=True)


class ServiceAccount(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "service_accounts"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_service_account_org_name"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[ServiceAccountStatus] = mapped_column(
        Enum(
            ServiceAccountStatus,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=ServiceAccountStatus.ACTIVE,
    )
    primary_role: Mapped[UserRole] = mapped_column(
        Enum(
            UserRole,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=UserRole.VIEWER,
    )
    auth_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def role(self) -> UserRole:
        """Compatibility with handlers that still expose a primary role."""
        return self.primary_role

    @property
    def is_active(self) -> bool:
        return self.status == ServiceAccountStatus.ACTIVE

    @property
    def full_name(self) -> str:
        return self.name

    @property
    def is_break_glass(self) -> bool:
        return False


class ScopedGrant(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "scoped_grants"
    __table_args__ = (
        CheckConstraint(
            "(principal_type = 'user' AND user_id IS NOT NULL AND service_account_id IS NULL) "
            "OR (principal_type = 'service_account' AND user_id IS NULL "
            "AND service_account_id IS NOT NULL)",
            name="ck_scoped_grant_principal",
        ),
        UniqueConstraint(
            "user_id", "role_id", "scope_type", "scope_id", name="uq_user_role_scope_grant"
        ),
        UniqueConstraint(
            "service_account_id",
            "role_id",
            "scope_type",
            "scope_id",
            name="uq_service_role_scope_grant",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    principal_type: Mapped[PrincipalType] = mapped_column(
        Enum(
            PrincipalType,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    service_account_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("service_accounts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("authorization_roles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scope_type: Mapped[GrantScopeType] = mapped_column(
        Enum(
            GrantScopeType,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    # Organization grants store organization_id; site grants store site_id.
    scope_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class ApiToken(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    __tablename__ = "api_tokens"
    __table_args__ = (
        CheckConstraint(
            "(principal_type = 'user' AND user_id IS NOT NULL AND service_account_id IS NULL) "
            "OR (principal_type = 'service_account' AND user_id IS NULL "
            "AND service_account_id IS NOT NULL)",
            name="ck_api_token_principal",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    principal_type: Mapped[PrincipalType] = mapped_column(
        Enum(
            PrincipalType,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    service_account_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("service_accounts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(24), nullable=False)
    issued_auth_version: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotated_from_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("api_tokens.id", ondelete="SET NULL"), nullable=True
    )
    ip_restrictions_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
