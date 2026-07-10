"""Report model (build plan Section 9.18).

A report is a generated, stored artifact (PDF/CSV/JSON) derived from a scan job.
The rendered bytes are written to disk and their path + SHA-256 recorded here, so
a report is reproducible from its stored file even if the underlying findings
change later. ``parameters_json`` captures the request parameters and a small
data snapshot summary for provenance.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin
from app.models.enums import ReportFormat, ReportStatus, ReportType


class Report(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A stored, downloadable report artifact."""

    __tablename__ = "reports"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )

    report_type: Mapped[ReportType] = mapped_column(
        Enum(ReportType, native_enum=False, length=32, validate_strings=True), nullable=False
    )
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat, native_enum=False, length=8, validate_strings=True), nullable=False
    )
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, native_enum=False, length=16, validate_strings=True),
        nullable=False,
        default=ReportStatus.PENDING,
    )
    template_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1")
    storage_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    generated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    parameters_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
