"""Risk acceptance model (build plan Section 9.19).

A risk acceptance records a decision to accept a finding's risk for a bounded
period, with a reason and (optionally) compensating controls. Acceptances expire
by default — ``expires_at`` is required — and an expiry sweep flips them to
``expired`` and reopens the finding.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import RiskAcceptanceStatus


class RiskAcceptance(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A bounded acceptance of a finding's risk."""

    __tablename__ = "risk_acceptances"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    compensating_controls: Mapped[str | None] = mapped_column(Text, nullable=True)
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[RiskAcceptanceStatus] = mapped_column(
        Enum(RiskAcceptanceStatus, native_enum=False, length=16, validate_strings=True),
        nullable=False,
        default=RiskAcceptanceStatus.PENDING,
        index=True,
    )
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
