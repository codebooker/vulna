"""SLA policy, immutable deadline, exception, guidance, and history models."""

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
    RemediationClassification,
    SlaCalculationSource,
    SlaExceptionStatus,
    SlaHistoryEvent,
)


class SlaPolicy(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An explicitly ordered, first-match-wins SLA policy."""

    __tablename__ = "sla_policies"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_sla_policy_org_name"),
        UniqueConstraint("organization_id", "priority", name="uq_sla_policy_org_priority"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    match_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    due_days_json: Mapped[dict[str, int]] = mapped_column(JSON, nullable=False)
    pause_on_risk_acceptance: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

class FindingSlaCalculation(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only snapshot of every factor used to establish a deadline."""

    __tablename__ = "finding_sla_calculations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sla_policies.id", ondelete="SET NULL"), nullable=True, index=True
    )
    previous_calculation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("finding_sla_calculations.id", ondelete="SET NULL"), nullable=True
    )
    source: Mapped[SlaCalculationSource] = mapped_column(
        Enum(
            SlaCalculationSource,
            native_enum=False,
            length=32,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    calculation_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class SlaException(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Requested and reviewed exception to an established deadline."""

    __tablename__ = "sla_exceptions"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requested_due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[SlaExceptionStatus] = mapped_column(
        Enum(
            SlaExceptionStatus,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=SlaExceptionStatus.PENDING,
        index=True,
    )
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    resulting_calculation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("finding_sla_calculations.id", ondelete="SET NULL"), nullable=True
    )


class SlaHistory(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only audit facts for reconstruction and compliance metrics."""

    __tablename__ = "sla_history"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event: Mapped[SlaHistoryEvent] = mapped_column(
        Enum(
            SlaHistoryEvent,
            native_enum=False,
            length=32,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class RemediationGuidance(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Structured, source-attributed remediation instructions for one finding."""

    __tablename__ = "remediation_guidance"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    classification: Mapped[RemediationClassification] = mapped_column(
        Enum(
            RemediationClassification,
            native_enum=False,
            length=32,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    summary: Mapped[str] = mapped_column(String(1024), nullable=False)
    steps_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    validation_steps_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    references_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
