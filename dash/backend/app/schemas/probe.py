"""Probe read schema, heartbeat request/response, and serialization helper."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import ProbeStatus
from app.models.probe import Probe


class ProbeRead(BaseModel):
    """A probe as returned by the API, including derived connectivity."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    site_id: uuid.UUID
    name: str
    description: str | None
    status: ProbeStatus
    # Derived from last_seen_at (not stored).
    online: bool
    certificate_fingerprint: str
    certificate_expires_at: datetime | None
    agent_version: str | None
    operating_system: str | None
    architecture: str | None
    hostname: str | None
    primary_ip: str | None
    capabilities: list[str]
    health: dict[str, Any]
    policy_hash: str | None
    upgrade_channel: str
    pentest_enabled: bool = False
    last_seen_at: datetime | None
    last_job_at: datetime | None
    enrolled_at: datetime | None
    approved_at: datetime | None
    created_at: datetime
    updated_at: datetime


class PentestToggle(BaseModel):
    """Enable or disable controlled-pentest execution on a scout."""

    enabled: bool


def is_probe_online(
    probe: Probe, *, offline_after_seconds: int, now: datetime | None = None
) -> bool:
    """Return whether a probe has sent a heartbeat within the offline threshold."""
    if probe.last_seen_at is None:
        return False
    now = now or datetime.now(UTC)
    last_seen = probe.last_seen_at
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    return (now - last_seen) < timedelta(seconds=offline_after_seconds)


def serialize_probe(probe: Probe, *, offline_after_seconds: int) -> ProbeRead:
    """Build a ``ProbeRead`` from an ORM probe, computing derived connectivity."""
    return ProbeRead(
        id=probe.id,
        organization_id=probe.organization_id,
        site_id=probe.site_id,
        name=probe.name,
        description=probe.description,
        status=probe.status,
        online=is_probe_online(probe, offline_after_seconds=offline_after_seconds),
        certificate_fingerprint=probe.certificate_fingerprint,
        certificate_expires_at=probe.certificate_expires_at,
        agent_version=probe.agent_version,
        operating_system=probe.operating_system,
        architecture=probe.architecture,
        hostname=probe.hostname,
        primary_ip=probe.primary_ip,
        capabilities=probe.capabilities_json,
        health=probe.health_json,
        policy_hash=probe.policy_hash,
        upgrade_channel=probe.upgrade_channel,
        pentest_enabled=probe.pentest_enabled,
        last_seen_at=probe.last_seen_at,
        last_job_at=probe.last_job_at,
        enrolled_at=probe.enrolled_at,
        approved_at=probe.approved_at,
        created_at=probe.created_at,
        updated_at=probe.updated_at,
    )


class HeartbeatRequest(BaseModel):
    """Payload a probe sends on each heartbeat (build plan Section 11.1)."""

    agent_version: str | None = Field(default=None, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    operating_system: str | None = Field(default=None, max_length=128)
    architecture: str | None = Field(default=None, max_length=32)
    capabilities: list[str] = Field(default_factory=list)
    health: dict[str, Any] = Field(default_factory=dict)
    active_job_id: uuid.UUID | None = None
    policy_hash: str | None = Field(default=None, max_length=64)


class CertificateStatus(BaseModel):
    fingerprint: str
    expires_at: datetime | None
    # "ok" | "expiring_soon" | "unknown"
    status: str


class PolicyStatus(BaseModel):
    # Populated in Phase 3 when signed local policy is delivered.
    version: int | None = None
    hash: str | None = None
    update_available: bool = False


class HeartbeatResponse(BaseModel):
    """Server response to a heartbeat (build plan Section 11.1)."""

    server_time: datetime
    probe_status: ProbeStatus
    certificate: CertificateStatus
    policy: PolicyStatus
    agent_update: dict[str, Any] | None = None
    pending_job_count: int = 0
    cancellations: list[uuid.UUID] = Field(default_factory=list)
    heartbeat_interval_seconds: int
