"""Ticket connector configuration and durable synchronization state."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import CreatedAtMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import TicketConnectorType, TicketSyncAction, TicketSyncStatus


class TicketConnector(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One organization-owned, purpose-encrypted ticket destination."""

    __tablename__ = "ticket_connectors"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_ticket_connector_org_name"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    connector_type: Mapped[TicketConnectorType] = mapped_column(
        Enum(
            TicketConnectorType,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        index=True,
    )
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    project_key: Mapped[str] = mapped_column(String(512), nullable=False)
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    close_after_verification: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    successful_test_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_test_error: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class TicketSync(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Materialized current relationship between a finding and external ticket."""

    __tablename__ = "ticket_syncs"
    __table_args__ = (
        UniqueConstraint("connector_id", "finding_id", name="uq_ticket_sync_connector_finding"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connector_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ticket_connectors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[TicketSyncStatus] = mapped_column(
        Enum(
            TicketSyncStatus,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=TicketSyncStatus.PENDING,
        index=True,
    )
    last_action: Mapped[TicketSyncAction] = mapped_column(
        Enum(
            TicketSyncAction,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
        default=TicketSyncAction.UPSERT,
    )
    external_ticket_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    external_ticket_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    last_payload_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class TicketSyncEvent(UUIDPrimaryKeyMixin, CreatedAtMixin, Base):
    """Append-only connector attempt, response metadata, and idempotency record."""

    __tablename__ = "ticket_sync_events"
    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_ticket_sync_event_idempotency"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sync_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ticket_syncs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    background_task_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("background_tasks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[TicketSyncAction] = mapped_column(
        Enum(
            TicketSyncAction,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    status: Mapped[TicketSyncStatus] = mapped_column(
        Enum(
            TicketSyncStatus,
            native_enum=False,
            length=16,
            values_callable=lambda enum: [item.value for item in enum],
        ),
        nullable=False,
    )
    idempotency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    response_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(String(2048), nullable=True)
