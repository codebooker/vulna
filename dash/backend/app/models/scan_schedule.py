"""Scheduled scans: recurring, unattended assessments of a network.

A schedule fires a non-intrusive vulnerability-assessment scan job against a
network on a fixed interval, using the network's bound scout and ranges. The
scheduler (a background sweep) fires any schedule whose ``next_run_at`` has
passed and advances it to the next slot. Intrusive/full-spectrum runs are not
scheduled — they require an approval gate and stay operator-initiated.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import JobMode


class ScanSchedule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A recurring scan of a network."""

    __tablename__ = "scan_schedules"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    network_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("networks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    mode: Mapped[JobMode] = mapped_column(
        Enum(JobMode, native_enum=False, length=32, validate_strings=True),
        nullable=False,
        default=JobMode.VULNERABILITY_ASSESSMENT,
    )
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Outcome of the most recent firing, surfaced in the UI.
    last_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )
    last_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
