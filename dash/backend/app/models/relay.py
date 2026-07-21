"""VulnaRelay: an optional thin-site tunnel endpoint (Phase 16, opt-in).

A relay runs **no scanners**. It is a minimal authenticated tunnel through which a
central scanner reaches a constrained site. Because the relay has no local
cryptographic scope/kill-switch boundary (unlike a smart VulnaScout), scope is
enforced at the **central egress** from the fields recorded here: a relay may only
carry scan traffic to its ``approved_cidrs`` while it is ``ENROLLED`` with the
tunnel up. The relay never receives job-signing keys or scanner credentials.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import RelayStatus


class Relay(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A thin-site tunnel endpoint."""

    __tablename__ = "relays"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sites.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[RelayStatus] = mapped_column(
        Enum(RelayStatus, native_enum=False, length=24, validate_strings=True),
        nullable=False,
        default=RelayStatus.PENDING_ENROLLMENT,
    )
    # Single-use enrollment token hash (cleared after registration).
    enrollment_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enrollment_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # mTLS control-channel client-certificate fingerprint (set at registration).
    certificate_fingerprint: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    # Renewal keeps the previously-presented certificate valid briefly. This
    # prevents a lost renewal response from permanently stranding a remote
    # Relay after the server has already committed the new fingerprint.
    previous_certificate_fingerprint: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    previous_certificate_valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    certificate_serial: Mapped[str | None] = mapped_column(String(128), nullable=True)
    certificate_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # WireGuard public key of the relay (non-secret). The relay keeps its private key.
    tunnel_public_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Address allocated to the relay inside the central WireGuard tunnel. The
    # endpoint receives only its own address and the server public key.
    tunnel_address: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True, index=True
    )
    # Live tunnel state as last reported by heartbeat.
    tunnel_up: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Approved egress CIDRs, enforced at the central egress.
    approved_cidrs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    denied_cidrs_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    killed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
