"""Explainable risk, remediation grouping, and finding-decision models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
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
    FindingDecisionStatus,
    FindingDecisionType,
    FindingStatus,
    RemediationKeyType,
    RemediationSuggestionStatus,
    RemediationUnitStatus,
)


class RiskProfile(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """An immutable, organization-owned scoring profile version."""

    __tablename__ = "risk_profiles"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "name", "version", name="uq_risk_profile_org_name_version"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    weights_json: Mapped[dict[str, float]] = mapped_column(JSON, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class FindingScoreSnapshot(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only calculation inputs and factor contributions for one finding."""

    __tablename__ = "finding_score_snapshots"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    risk_profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("risk_profiles.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    profile_version: Mapped[int] = mapped_column(Integer, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    weighted_sum: Mapped[float] = mapped_column(Float, nullable=False)
    positive_maximum: Mapped[float] = mapped_column(Float, nullable=False)
    source_values_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    factors_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class RemediationUnit(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A set of findings sharing an exact, auditable remediation key."""

    __tablename__ = "remediation_units"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "site_id",
            "key_type",
            "exact_key",
            name="uq_remediation_unit_exact_key",
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_type: Mapped[RemediationKeyType] = mapped_column(
        Enum(
            RemediationKeyType,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    exact_key: Mapped[str] = mapped_column(String(512), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[RemediationUnitStatus] = mapped_column(
        Enum(
            RemediationUnitStatus,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=RemediationUnitStatus.OPEN,
        index=True,
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    automatically_created: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class RemediationUnitFinding(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Auditable membership of a finding in a remediation unit."""

    __tablename__ = "remediation_unit_findings"
    __table_args__ = (
        UniqueConstraint("remediation_unit_id", "finding_id", name="uq_remediation_membership"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    remediation_unit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("remediation_units.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    match_basis_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    added_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class RemediationSuggestion(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A fuzzy membership proposal that cannot apply without explicit review."""

    __tablename__ = "remediation_suggestions"
    __table_args__ = (
        UniqueConstraint(
            "remediation_unit_id", "finding_id", name="uq_remediation_suggestion_membership"
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    remediation_unit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("remediation_units.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    similarity: Mapped[float] = mapped_column(Float, nullable=False)
    explanation_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    status: Mapped[RemediationSuggestionStatus] = mapped_column(
        Enum(
            RemediationSuggestionStatus,
            native_enum=False,
            length=16,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=RemediationSuggestionStatus.PENDING,
        index=True,
    )
    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FindingDecision(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only, expiring false-positive, duplicate, or suppression decision."""

    __tablename__ = "finding_decisions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    decision_type: Mapped[FindingDecisionType] = mapped_column(
        Enum(
            FindingDecisionType,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    status: Mapped[FindingDecisionStatus] = mapped_column(
        Enum(
            FindingDecisionStatus,
            native_enum=False,
            length=16,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=FindingDecisionStatus.ACTIVE,
        index=True,
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    duplicate_of_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    previous_status: Mapped[FindingStatus] = mapped_column(
        Enum(
            FindingStatus,
            native_enum=False,
            length=32,
            validate_strings=True,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoked_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
