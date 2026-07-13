"""Scan job model (subset of build plan Section 9.8 for Phase 3).

A scan job is a signed unit of work delivered to a probe. The exact signed
envelope delivered over the wire is stored verbatim in ``envelope_json`` so the
bytes the probe verifies are byte-identical to what was signed at creation time.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Index, Integer, String, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import JobMode, JobStatus

# The active (non-terminal) statuses. A partial unique index over these enforces,
# at the database level, at most one active job per network — closing the race in
# the app-level "network already under test" check (no row lock there). The values
# are the stored enum NAMES (native_enum=False stores JobStatus.name, uppercase).
_ACTIVE_STATUS_SQL = "status IN ('QUEUED', 'OFFERED', 'ACCEPTED', 'RUNNING')"


class ScanJob(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A signed assessment job targeted at a probe."""

    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index(
            "uq_scan_jobs_active_network",
            "network_id",
            unique=True,
            sqlite_where=text(f"network_id IS NOT NULL AND {_ACTIVE_STATUS_SQL}"),
            postgresql_where=text(f"network_id IS NOT NULL AND {_ACTIVE_STATUS_SQL}"),
        ),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    probe_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("probes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Set for network-targeted jobs (workflow/schedule dispatch). Used to enforce
    # at most one active test per network at a time — no two scouts on one network.
    network_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("networks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
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
    # Finding IDs this job re-checks (targeted verification rescan, Phase 10). When
    # a scanner's results arrive, a verified finding it no longer observes is
    # resolved as fixed.
    verifies_finding_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    # Non-secret references only. The actual credential material exists solely
    # inside the Scout-specific encrypted envelope in ``envelope_json``.
    credential_protocols_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

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
    # Progress is Scout-reported, stage-based execution state. Keep the typed
    # percentage separate for cheap list rendering and retain the bounded,
    # non-secret counters/current-stage detail in progress_json.
    progress_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    estimated_completion_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_progress_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Detailed failure diagnostics are intentionally excluded from JobRead and
    # exposed only through the jobs.manage-protected diagnostics endpoint.
    failure_log_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list
    )
