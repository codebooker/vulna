"""Shared enumerations for the ORM domain model."""

from __future__ import annotations

from enum import StrEnum


class ExperienceProfile(StrEnum):
    """Dashboard discoverability profile; never an authorization control."""

    SMALL_BUSINESS = "small_business"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


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


class AccountStatus(StrEnum):
    """Authoritative lifecycle state of an interactive user account."""

    INVITED = "invited"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"
    LOCKED = "locked"


class AuthenticationSource(StrEnum):
    """System that owns an account's authentication lifecycle."""

    LOCAL = "local"
    JIT = "jit"
    SCIM = "scim"


class IdentityProviderProtocol(StrEnum):
    """Supported organization identity-provider protocols."""

    OIDC = "oidc"
    SAML = "saml"


class SsoPolicyMode(StrEnum):
    """Local/SSO sign-in policy; enforced mode always keeps break-glass."""

    DISABLED = "disabled"
    OPTIONAL = "optional"
    ENFORCED = "enforced"


class SiteAccessMode(StrEnum):
    """Compatibility scope used until Phase 39 migrates it to grants."""

    ALL = "all"
    ASSIGNED = "assigned"


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


class ChangeEventType(StrEnum):
    """Types of asset/service change event (subset of build plan Section 9.17)."""

    ASSET_DISCOVERED = "asset_discovered"
    ASSET_DISAPPEARED = "asset_disappeared"
    IP_CHANGED = "ip_changed"
    NEW_PORT_OPENED = "new_port_opened"
    PORT_CLOSED = "port_closed"
    SERVICE_VERSION_CHANGED = "service_version_changed"
    NEW_FINDING = "new_finding"
    FINDING_RESOLVED = "finding_resolved"
    FINDING_REOPENED = "finding_reopened"
    NEW_VULNERABILITY = "new_vulnerability"
    CVE_SEVERITY_CHANGED = "cve_severity_changed"
    CVE_ADDED_TO_KEV = "cve_added_to_kev"
    EPSS_THRESHOLD_CROSSED = "epss_threshold_crossed"
    FINDING_VERIFIED = "finding_verified"
    RISK_ACCEPTANCE_EXPIRED = "risk_acceptance_expired"


class FeedSource(StrEnum):
    """A vulnerability-intelligence data source (build plan Section 14.1)."""

    NVD = "nvd"
    KEV = "kev"
    EPSS = "epss"


class FeedStatus(StrEnum):
    """Health of an intelligence feed's synchronization (build plan Section 14.7)."""

    OK = "ok"  # last sync succeeded
    DEGRADED = "degraded"  # succeeded after retries or with partial errors
    FAILED = "failed"  # last sync failed outright
    STALE = "stale"  # no successful sync within the expected interval
    NEVER_SYNCED = "never_synced"


class MatchConfidence(StrEnum):
    """Confidence that a CVE applies to an asset/service (build plan Section 14.3)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class WorkflowRunStatus(StrEnum):
    """Overall status of a multi-stage assessment run (build plan §13.3)."""

    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"  # a stage failed; cleanup/verification/reporting still ran
    CANCELLED = "cancelled"


class WorkflowStageStatus(StrEnum):
    """Status of a single workflow stage."""

    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"  # conditional stage that did not apply
    DENIED = "denied"  # intrusive stage denied at the approval gate


class PentestSessionStatus(StrEnum):
    """Lifecycle of a controlled-pentest validation session (build plan §13.2).

    A session is created ``pending_approval``; only after an approver moves it to
    ``approved`` may it run. It ends ``completed``/``terminated``/``expired``, and
    ``cleanup_required`` sessions are not considered closed until ``cleaned``.
    """

    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    RUNNING = "running"
    COMPLETED = "completed"
    TERMINATED = "terminated"  # stopped by kill switch or timeout
    EXPIRED = "expired"  # timed out before running
    CLEANUP_PENDING = "cleanup_pending"
    CLEANED = "cleaned"


class RiskAcceptanceStatus(StrEnum):
    """Lifecycle of a finding risk acceptance (build plan Section 9.19)."""

    PENDING = "pending"  # requested, awaiting approval
    ACTIVE = "active"  # approved and currently in force
    EXPIRED = "expired"  # passed its expiry (default outcome)
    REVOKED = "revoked"  # withdrawn before expiry
    REJECTED = "rejected"  # approval declined


class WebScanProfile(StrEnum):
    """OWASP ZAP web-assessment profile (build plan Section 12.5).

    ``passive_baseline`` spiders and passively analyzes only (no attacks).
    ``limited_active`` additionally runs an allowlisted set of active rules and
    therefore requires approval.
    """

    PASSIVE_BASELINE = "passive_baseline"
    LIMITED_ACTIVE = "limited_active"


class ReportType(StrEnum):
    """A report/export artifact type (build plan Section 16)."""

    EXECUTIVE_PDF = "executive_pdf"
    TECHNICAL_PDF = "technical_pdf"
    PENTEST_PDF = "pentest_pdf"
    FULL_SPECTRUM_PDF = "full_spectrum_pdf"
    FINDINGS_CSV = "findings_csv"
    ASSETS_CSV = "assets_csv"
    SERVICES_CSV = "services_csv"
    CVE_EXPOSURE_CSV = "cve_exposure_csv"
    JSON_BUNDLE = "json_bundle"


class ReportFormat(StrEnum):
    """Serialized format of a report artifact."""

    PDF = "pdf"
    CSV = "csv"
    JSON = "json"


class ReportStatus(StrEnum):
    """Lifecycle of a report artifact (build plan Section 9.18)."""

    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(StrEnum):
    """Finding severity."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(StrEnum):
    """Finding classification (build plan Section 9.15)."""

    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    WEAK_PROTOCOL = "weak_protocol"
    EXPOSED_SERVICE = "exposed_service"
    DEFAULT_CREDENTIAL = "default_credential"
    MISSING_PATCH = "missing_patch"
    UNSUPPORTED_SOFTWARE = "unsupported_software"
    WEB_APPLICATION_ISSUE = "web_application_issue"
    CREDENTIALED_CONFIGURATION_ISSUE = "credentialed_configuration_issue"
    VALIDATED_EXPLOITABILITY = "validated_exploitability"
    INFORMATIONAL = "informational"


class ValidationStatus(StrEnum):
    """How strongly a finding's exploitability has been validated (Section 9.15)."""

    UNVALIDATED = "unvalidated"
    LIKELY = "likely"
    CONFIRMED_NON_EXPLOIT = "confirmed_non_exploit"
    CONFIRMED_EXPLOITABLE = "confirmed_exploitable"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"


class FindingStatus(StrEnum):
    """Finding workflow state (build plan Section 9.15)."""

    NEW = "new"
    TRIAGE = "triage"
    VALIDATED = "validated"
    ASSIGNED = "assigned"
    REMEDIATION_IN_PROGRESS = "remediation_in_progress"
    READY_FOR_VERIFICATION = "ready_for_verification"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    SUPPRESSED = "suppressed"



class RelayStatus(StrEnum):
    """Administrative lifecycle state of a VulnaRelay (Phase 16, opt-in).

    A relay is a thin tunnel endpoint with no scanners. Live tunnel connectivity
    is tracked separately (``tunnel_up``); this is the stored lifecycle status.
    """

    PENDING_ENROLLMENT = "pending_enrollment"  # token issued, awaiting registration
    ENROLLED = "enrolled"  # registered and usable
    KILLED = "killed"  # kill switch engaged; scanning is blocked
    REVOKED = "revoked"  # decommissioned
