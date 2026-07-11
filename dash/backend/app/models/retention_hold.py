"""Legal / retention holds (Phase 28).

A hold marks an object as exempt from retention cleanup: while a hold exists on a
report or a scan job, the maintenance cleanup workflow refuses to delete that
object (or the raw artifacts backing it), regardless of age. Holds are the
"legal hold" the cleanup safety rules honor.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin

# Target kinds a hold may apply to.
HOLD_REPORT = "report"
HOLD_SCAN_JOB = "scan_job"


class RetentionHold(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A hold that exempts one object from retention cleanup."""

    __tablename__ = "retention_holds"
    __table_args__ = (
        UniqueConstraint("target_type", "target_id", name="uq_retention_holds_target"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
