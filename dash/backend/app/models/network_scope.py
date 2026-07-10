"""Network scope model (build plan Section 9.4).

A network scope is an explicitly approved CIDR that a probe at a site is
permitted to assess. Scopes are the foundation of local target enforcement:
CIDRs are normalized, ``0.0.0.0/0`` / ``::/0`` are rejected, and public ranges
are denied by default. ``probe_id`` is nullable until probe enrollment lands in
Phase 2.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class NetworkScope(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An approved (or pending-approval) address range for assessment."""

    __tablename__ = "network_scopes"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Populated in Phase 2 once probes exist; a scope may be site-wide until then.
    probe_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True, index=True)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Stored in normalized/canonical form (e.g. "10.20.0.0/24").
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    allow_public_addresses: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    maximum_hosts: Mapped[int | None] = mapped_column(Integer, nullable=True)
    maximum_packets_per_second: Mapped[int | None] = mapped_column(Integer, nullable=True)
    maximum_concurrency: Mapped[int | None] = mapped_column(Integer, nullable=True)

    notes: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    # Bumped whenever the scope changes so probes can detect a stale local policy.
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
