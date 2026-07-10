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


class AssetType(StrEnum):
    """Asset classification (build plan Section 9.10)."""

    WORKSTATION = "workstation"
    SERVER = "server"
    NETWORK_DEVICE = "network_device"
    PRINTER = "printer"
    CAMERA = "camera"
    PHONE = "phone"
    STORAGE = "storage"
    HYPERVISOR = "hypervisor"
    VIRTUAL_MACHINE = "virtual_machine"
    CLOUD_INSTANCE = "cloud_instance"
    IOT = "iot"
    EMBEDDED = "embedded"
    WEB_APPLICATION = "web_application"
    UNKNOWN = "unknown"


class AssetStatus(StrEnum):
    """Whether an asset was seen in the most recent relevant assessment."""

    ACTIVE = "active"
    INACTIVE = "inactive"


class IdentifierType(StrEnum):
    """Types of stable asset identifier (build plan Section 9.11)."""

    IP_ADDRESS = "ip_address"
    MAC_ADDRESS = "mac_address"
    HOSTNAME = "hostname"
    FQDN = "fqdn"
    SMB_NAME = "smb_name"
    SSH_HOST_KEY = "ssh_host_key"
    TLS_CERT_FINGERPRINT = "tls_cert_fingerprint"
    SNMP_ENGINE_ID = "snmp_engine_id"
    CLOUD_INSTANCE_ID = "cloud_instance_id"
    AGENT_ID = "agent_id"


class ServiceTransport(StrEnum):
    """Transport protocol of a discovered service."""

    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


class ServiceState(StrEnum):
    """Nmap-style port state."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open_filtered"
    UNFILTERED = "unfiltered"

