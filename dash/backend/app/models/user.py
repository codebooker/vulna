"""User account model with role-based access control.

Passwords are only ever stored as Argon2 hashes (see ``app.auth.password``).
The plaintext password never touches the database or logs.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    AccountStatus,
    AuthenticationSource,
    SiteAccessMode,
    UserRole,
)


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An authenticated operator of VulnaDash."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "scim_external_id", name="uq_users_org_scim_external_id"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    # Invitations do not receive an administrator-selected password. The hash is
    # nullable until the invited user consumes their one-time token.
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, native_enum=False, length=32, validate_strings=True),
        nullable=False,
        default=UserRole.VIEWER,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    account_status: Mapped[AccountStatus] = mapped_column(
        Enum(
            AccountStatus,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=AccountStatus.ACTIVE,
    )
    authentication_source: Mapped[AuthenticationSource] = mapped_column(
        Enum(
            AuthenticationSource,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=AuthenticationSource.LOCAL,
    )
    site_access_mode: Mapped[SiteAccessMode] = mapped_column(
        Enum(
            SiteAccessMode,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=SiteAccessMode.ALL,
    )
    auth_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    authorization_migrated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    invited_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    mfa_grace_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_break_glass: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    scim_external_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # One-time account recovery codes: only Argon2 hashes are stored (like the
    # password), each removed as it is consumed. Plaintext is shown to the user
    # exactly once at generation time and never persisted or logged.
    recovery_codes_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recovery_codes_generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    @validates("is_active")
    def _sync_compatibility_active(self, _key: str, value: bool) -> bool:
        """Keep direct legacy writes safe while status becomes authoritative."""
        if hasattr(self, "account_status"):
            self.account_status = AccountStatus.ACTIVE if value else AccountStatus.DEACTIVATED
        return value

    def set_account_status(self, value: AccountStatus, *, now: datetime) -> None:
        """Apply lifecycle state and its derived compatibility/timestamp fields."""
        self.is_active = value == AccountStatus.ACTIVE
        # The compatibility validator maps false to deactivated; restore the
        # richer authoritative state (for example suspended or invited) last.
        self.account_status = value
        if value == AccountStatus.INVITED:
            self.invited_at = now
        elif value == AccountStatus.ACTIVE:
            self.activated_at = self.activated_at or now
        elif value == AccountStatus.SUSPENDED:
            self.suspended_at = now
        elif value == AccountStatus.DEACTIVATED:
            self.deactivated_at = now
