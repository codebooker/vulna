"""Finding model (build plan Section 9.15).

A finding is a normalized security issue discovered by a scanner. Findings are
deduplicated by a ``canonical_finding_key`` (organization + asset + service +
weakness + scanner discriminator) so repeated scans update an existing finding
rather than creating a duplicate, while preserving first/last-seen history.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import (
    FindingStatus,
    FindingType,
    Severity,
    ValidationStatus,
)


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A normalized security finding."""

    __tablename__ = "findings"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    service_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("services.id", ondelete="SET NULL"), nullable=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )

    scanner_name: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_finding_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Stable dedup key across scans; unique within an organization.
    canonical_finding_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    finding_type: Mapped[FindingType] = mapped_column(
        Enum(FindingType, native_enum=False, length=48, validate_strings=True), nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, native_enum=False, length=16, validate_strings=True),
        nullable=False,
        default=Severity.INFO,
        index=True,
    )
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cve_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    cwe_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)

    # Threat-intelligence enrichment (Phase 7), copied from the matched CVE's
    # enrichment so findings can be prioritized and reported without a join.
    known_exploited: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True
    )
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)

    validation_status: Mapped[ValidationStatus] = mapped_column(
        Enum(ValidationStatus, native_enum=False, length=32, validate_strings=True),
        nullable=False,
        default=ValidationStatus.UNVALIDATED,
    )
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, native_enum=False, length=32, validate_strings=True),
        nullable=False,
        default=FindingStatus.NEW,
        index=True,
    )
    # Remediation / verification workflow (Phase 10).
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Points to the currently-active RiskAcceptance (soft reference; the owning FK
    # is risk_acceptances.finding_id, avoiding a circular foreign key).
    risk_acceptance_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    false_positive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reopened_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
