"""Idempotency records for probe result uploads (Phase 27).

A Scout on an intermittent WAN link keeps finished work in a durable local queue
and re-uploads it when connectivity returns. Each result batch carries a stable
idempotency key; recording the keys we have already processed lets the server
treat a re-upload after a lost acknowledgement as a no-op, so a disconnected
Scout never produces duplicate observations when it resumes.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin


class ProbeResultUpload(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One processed result upload, keyed for idempotent retries."""

    __tablename__ = "probe_result_uploads"
    __table_args__ = (
        UniqueConstraint(
            "scan_job_id", "idempotency_key", name="uq_probe_result_uploads_job_key"
        ),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
