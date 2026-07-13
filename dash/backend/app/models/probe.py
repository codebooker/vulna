"""VulnaScout probe model (build plan Section 9.3).

A probe is a remote assessment appliance enrolled to a site. It authenticates
to the orchestrator with a client certificate (mutual TLS); the certificate
fingerprint is the probe's stable network identity. Live connectivity is derived
from ``last_seen_at`` rather than stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.enums import ProbeStatus


class Probe(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A remote VulnaScout appliance."""

    __tablename__ = "probes"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    site_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    status: Mapped[ProbeStatus] = mapped_column(
        Enum(ProbeStatus, native_enum=False, length=32, validate_strings=True),
        nullable=False,
        default=ProbeStatus.PENDING_ENROLLMENT,
        index=True,
    )

    # Current client-certificate identity. Fingerprint is unique across probes.
    certificate_fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    certificate_serial: Mapped[str | None] = mapped_column(String(64), nullable=True)
    certificate_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Self-reported inventory (from heartbeats).
    agent_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    operating_system: Mapped[str | None] = mapped_column(String(128), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    primary_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    capabilities_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    health_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    policy_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    upgrade_channel: Mapped[str] = mapped_column(String(32), nullable=False, default="stable")
    # Operator opt-in for controlled-pentest execution. Only when true does the
    # scout's signed policy permit the controlled_pentest mode, so a scout that is
    # not explicitly enabled fails closed on any pentest job — even from a
    # compromised orchestrator.
    pentest_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Separate, explicit opt-in for credential delivery. Existing Scouts remain
    # unable to receive vault material until an administrator enables this and
    # the Scout has enrolled an X25519 public key.
    credentialed_scans_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    encryption_public_key_b64: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Lifecycle timestamps.
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_job_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
