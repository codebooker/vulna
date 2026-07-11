"""Notification channels and delivery history (Phase 29).

A channel is a configured outbound destination (email or webhook) with its event
subscriptions and delivery policy. Its credential (SMTP password or webhook
signing key) is stored **encrypted** and is never returned through the API. A
delivery is one attempt to notify a channel about an event, kept for history,
retry state, and clear error reporting.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin

CHANNEL_EMAIL = "email"
CHANNEL_WEBHOOK = "webhook"

DELIVERY_PENDING = "pending"
DELIVERY_SENT = "sent"
DELIVERY_FAILED = "failed"
DELIVERY_SUPPRESSED = "suppressed"  # deduplicated
DELIVERY_DELAYED = "delayed"  # held by quiet hours, will send later


class NotificationChannel(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A configured outbound notification destination."""

    __tablename__ = "notification_channels"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    channel_type: Mapped[str] = mapped_column(String(16), nullable=False)
    # Non-secret configuration (webhook URL / SMTP host etc.). Never holds a secret.
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # Encrypted SMTP password / webhook signing key. Write-only; never serialized.
    encrypted_secret: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    events_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    policy: Mapped[str] = mapped_column(String(16), nullable=False, default="immediate")
    quiet_start_hour: Mapped[int | None] = mapped_column(Integer, nullable=True)
    quiet_end_hour: Mapped[int | None] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_digest_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class NotificationDelivery(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """One delivery attempt for a channel, kept for history and retry state."""

    __tablename__ = "notification_deliveries"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    channel_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("notification_channels.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=DELIVERY_PENDING)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    site_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    # The event's selected (non-sensitive) fields, so dispatch can rebuild the
    # exact payload. Never contains evidence, credentials, or scanner output.
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
