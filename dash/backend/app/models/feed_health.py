"""Feed health model (build plan Section 14.7).

One row per intelligence source records the outcome of its most recent sync so
operators can see, at a glance, whether the CVE/KEV/EPSS feeds are current or a
sync has been failing. It is upserted by the sync jobs, not append-only.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Enum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin
from app.models.enums import FeedSource, FeedStatus


class FeedHealth(TimestampMixin, Base):
    """The synchronization health of one intelligence feed."""

    __tablename__ = "feed_health"

    source: Mapped[FeedSource] = mapped_column(
        Enum(FeedSource, native_enum=False, length=16, validate_strings=True),
        primary_key=True,
    )
    status: Mapped[FeedStatus] = mapped_column(
        Enum(FeedStatus, native_enum=False, length=16, validate_strings=True),
        nullable=False,
        default=FeedStatus.NEVER_SYNCED,
    )
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    records_processed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    records_changed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_source_timestamp: Mapped[str | None] = mapped_column(String(64), nullable=True)
