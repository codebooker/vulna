"""Shared enumerations for the ORM domain model."""

from __future__ import annotations

from enum import StrEnum


class UserRole(StrEnum):
    """Initial role set (build plan Section 5).

    A single role per user is sufficient for the MVP and keeps authorization
    checks explicit and testable. Finer-grained, multi-role assignment can be
    layered on later without changing the enum values.
    """

    ADMINISTRATOR = "administrator"
    SECURITY_OPERATOR = "security_operator"
    PENTEST_APPROVER = "pentest_approver"
    REMEDIATION_OWNER = "remediation_owner"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class ActorType(StrEnum):
    """Origin of an audited action."""

    USER = "user"
    SYSTEM = "system"
    PROBE = "probe"


class ProbeStatus(StrEnum):
    """Administrative lifecycle state of a VulnaScout (build plan Section 9.3).

    This is the *stored* lifecycle status. Live connectivity (online/offline) is
    derived from ``last_seen_at`` at read time rather than persisted, since it is
    time-dependent.
    """

    PENDING_ENROLLMENT = "pending_enrollment"  # enrolled, awaiting admin approval
    ENROLLED = "enrolled"  # approved and active
    DISABLED = "disabled"
    REVOKED = "revoked"


class JobMode(StrEnum):
    """Assessment mode of a scan job (build plan Section 1.2–1.4).

    Phase 3 supports vulnerability assessment only; controlled pentest and
    full-spectrum modes are reserved for later phases.
    """

    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    CONTROLLED_PENTEST = "controlled_pentest"
    FULL_SPECTRUM = "full_spectrum"


class JobStatus(StrEnum):
    """Scan-job lifecycle status (subset of build plan Section 9.8 for Phase 3)."""

    QUEUED = "queued"  # signed and waiting to be offered to the probe
    OFFERED = "offered"  # delivered to the probe via jobs/next
    ACCEPTED = "accepted"  # probe accepted the job
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    REJECTED_BY_PROBE = "rejected_by_probe"

