"""Change event model (build plan Section 9.17).

Change events record how the inventory changed between scans — assets appearing,
ports opening/closing, service versions changing — so operators can see a delta
over time. They are append-only.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import JSON, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin
from app.models.enums import ChangeEventType


class ChangeEvent(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """An append-only record of an inventory change."""

    __tablename__ = "change_events"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    event_type: Mapped[ChangeEventType] = mapped_column(
        Enum(ChangeEventType, native_enum=False, length=32, validate_strings=True),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    before_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    after_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
