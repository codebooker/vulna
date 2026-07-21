"""Immutable, fenced delivery attempts for distributed Scout jobs."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin


class ScanJobAttempt(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One lease-bound offer of a signed job to its assigned Scout.

    Rows are never reused. ``fencing_token`` increases for every re-offer so
    stale agents and delayed durable result uploads can be rejected even though
    they still possess a valid Scout certificate and signed job envelope.
    """

    __tablename__ = "scan_job_attempts"
    __table_args__ = (
        UniqueConstraint("scan_job_id", "attempt_number", name="uq_job_attempt_number"),
        UniqueConstraint("scan_job_id", "fencing_token", name="uq_job_attempt_fence"),
        UniqueConstraint("lease_id", name="uq_job_attempt_lease_id"),
        Index("ix_job_attempt_active_lease", "scan_job_id", "lease_expires_at"),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    probe_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("probes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    fencing_token: Mapped[int] = mapped_column(Integer, nullable=False)
    lease_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="offered", index=True)
    offered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_renewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
