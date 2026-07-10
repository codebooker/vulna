"""Finding note model (Phase 10).

An append-only, human-authored note on a finding — remediation discussion,
triage rationale, verification observations. Notes are never edited or deleted,
preserving the remediation history.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin


class FindingNote(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """A comment attached to a finding."""

    __tablename__ = "finding_notes"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
