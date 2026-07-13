"""Purpose-bound credential vault, assignment, test, and usage models (Phase 42)."""

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
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    CredentialAssignmentTarget,
    CredentialAuthType,
    CredentialProtocol,
    CredentialTestStatus,
    CredentialUsageStatus,
)


class CredentialRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Non-secret metadata for one reusable credential."""

    __tablename__ = "credential_records"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_credential_record_org_name"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    protocol: Mapped[CredentialProtocol] = mapped_column(
        Enum(
            CredentialProtocol,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    auth_type: Mapped[CredentialAuthType] = mapped_column(
        Enum(
            CredentialAuthType,
            native_enum=False,
            length=32,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class CredentialSecretVersion(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only encrypted secret version; plaintext is never persisted."""

    __tablename__ = "credential_secret_versions"
    __table_args__ = (
        UniqueConstraint("credential_id", "version", name="uq_credential_secret_version"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("credential_records.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CredentialAssignment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One credential candidate at one deterministic resolution level."""

    __tablename__ = "credential_assignments"
    __table_args__ = (
        UniqueConstraint(
            "credential_id",
            "target_type",
            "target_id",
            name="uq_credential_assignment_target",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("credential_records.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_type: Mapped[CredentialAssignmentTarget] = mapped_column(
        Enum(
            CredentialAssignmentTarget,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    target_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=True, index=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    assigned_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class CredentialTest(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Sanitized result of a test collection; never stores command output."""

    __tablename__ = "credential_tests"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("credential_records.id", ondelete="CASCADE"), nullable=False, index=True
    )
    secret_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("credential_secret_versions.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[CredentialTestStatus] = mapped_column(
        Enum(
            CredentialTestStatus,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=CredentialTestStatus.PENDING,
    )
    message: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    tested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CredentialUsageAudit(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only record that a version was encrypted for or used by a job."""

    __tablename__ = "credential_usage_audit"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("credential_records.id", ondelete="CASCADE"), nullable=False, index=True
    )
    secret_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("credential_secret_versions.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    probe_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("probes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    protocol: Mapped[CredentialProtocol] = mapped_column(
        Enum(
            CredentialProtocol,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    status: Mapped[CredentialUsageStatus] = mapped_column(
        Enum(
            CredentialUsageStatus,
            native_enum=False,
            length=32,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=CredentialUsageStatus.ENCRYPTED_FOR_JOB,
    )
    detail: Mapped[str | None] = mapped_column(String(1024), nullable=True)
