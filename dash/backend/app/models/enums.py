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

