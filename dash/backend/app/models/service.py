"""Service model (build plan Section 9.12).

A service is a network service discovered on an asset (a transport/port with an
optional identified product and version).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import ServiceState, ServiceTransport


class Service(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A network service on an asset (one row per transport/port)."""

    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint(
            "asset_id", "transport", "port", name="uq_services_asset_transport_port"
        ),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    transport: Mapped[ServiceTransport] = mapped_column(
        Enum(ServiceTransport, native_enum=False, length=8, validate_strings=True), nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[ServiceState] = mapped_column(
        Enum(ServiceState, native_enum=False, length=16, validate_strings=True),
        nullable=False,
        default=ServiceState.OPEN,
    )
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(255), nullable=True)
    banner_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
