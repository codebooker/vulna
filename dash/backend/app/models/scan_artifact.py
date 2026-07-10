"""Raw scanner-output retention (build plan Section 4.x / Phase 4).

Each result upload stores the raw scanner output verbatim so a scan is
reproducible and auditable. Phase 4 keeps the raw output in the database for
simplicity; encrypted, filesystem/object-storage evidence with redaction is
introduced with the reporting subsystem in a later phase.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin


class ScanArtifact(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Raw output produced by a scanner stage of a scan job."""

    __tablename__ = "scan_artifacts"

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    probe_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("probes.id", ondelete="SET NULL"), nullable=True
    )
    stage: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_name: Mapped[str] = mapped_column(String(64), nullable=False)
    content_type: Mapped[str] = mapped_column(String(64), nullable=False, default="application/xml")
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    raw_output: Mapped[str] = mapped_column(Text, nullable=False)
