"""Scan job model (subset of build plan Section 9.8 for Phase 3).

A scan job is a signed unit of work delivered to a probe. The exact signed
envelope delivered over the wire is stored verbatim in ``envelope_json`` so the
bytes the probe verifies are byte-identical to what was signed at creation time.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import JobMode, JobStatus


class ScanJob(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A signed assessment job targeted at a probe."""

    __tablename__ = "scan_jobs"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    probe_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("probes.id", ondelete="CASCADE"), nullable=False, index=True
    )

    mode: Mapped[JobMode] = mapped_column(
        Enum(JobMode, native_enum=False, length=32, validate_strings=True), nullable=False
    )
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, native_enum=False, length=32, validate_strings=True),
        nullable=False,
        default=JobStatus.QUEUED,
        index=True,
    )

    requested_targets_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    workflow_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    limits_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    policy_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # The exact signed job envelope delivered to the probe (source of truth).
    envelope_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    job_signature: Mapped[str] = mapped_column(String(128), nullable=False)

    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    offered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    summary_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
