"""Phase 36 multi-factor authentication, WebAuthn, and throttling models."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin


class TotpFactor(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """An encrypted RFC 6238 seed; plaintext exists only during setup/use."""

    __tablename__ = "totp_factors"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    label: Mapped[str] = mapped_column(String(255), nullable=False, default="Authenticator app")
    encrypted_secret: Mapped[str] = mapped_column(String(2048), nullable=False)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_timecode: Mapped[int | None] = mapped_column(Integer, nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MfaRecoveryCode(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A single recovery code stored as an independent Argon2 hash."""

    __tablename__ = "mfa_recovery_codes"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    code_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WebAuthnCredential(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A verified public-key credential; no authenticator private key is stored."""

    __tablename__ = "webauthn_credentials"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_id: Mapped[str] = mapped_column(
        String(1024), nullable=False, unique=True, index=True
    )
    credential_public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    label: Mapped[str] = mapped_column(String(255), nullable=False, default="Security key")
    transports_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    device_type: Mapped[str] = mapped_column(String(32), nullable=False, default="single_device")
    backed_up: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WebAuthnChallenge(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A short-lived, single-use registration or authentication challenge."""

    __tablename__ = "webauthn_challenges"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("user_sessions.id", ondelete="CASCADE"), nullable=True, index=True
    )
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    challenge: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MfaPolicy(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Organization MFA enforcement policy with an explicit grace period."""

    __tablename__ = "mfa_policies"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="optional")
    required_roles_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    grace_period_days: Mapped[int] = mapped_column(Integer, nullable=False, default=7)


class AuthenticationThrottle(UUIDPrimaryKeyMixin, Base):
    """Durable exponential-backoff state keyed by a hashed account or IP."""

    __tablename__ = "authentication_throttles"
    __table_args__ = (UniqueConstraint("key_type", "key_hash", name="uq_auth_throttle_key"),)

    key_type: Mapped[str] = mapped_column(String(16), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
