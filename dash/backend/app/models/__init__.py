"""ORM models for VulnaDash.

Importing this package registers every model on ``Base.metadata`` so that
Alembic and ``metadata.create_all`` see the full schema.
"""

from app.models.asset import Asset, AssetIdentifier
from app.models.audit import AuditEvent
from app.models.change_event import ChangeEvent
from app.models.cve import CveRecord, ThreatIntelEnrichment
from app.models.enrollment_token import EnrollmentToken
from app.models.enums import (
    ActorType,
    AssetStatus,
    AssetType,
    ChangeEventType,
    FeedSource,
    FeedStatus,
    FindingStatus,
    FindingType,
    IdentifierType,
    JobMode,
    JobStatus,
    MatchConfidence,
    PentestSessionStatus,
    ProbeStatus,
    ReportFormat,
    ReportStatus,
    ReportType,
    RiskAcceptanceStatus,
    ServiceState,
    ServiceTransport,
    Severity,
    UserRole,
    ValidationStatus,
    WebScanProfile,
)
from app.models.feed_health import FeedHealth
from app.models.finding import Finding
from app.models.finding_note import FindingNote
from app.models.network_scope import NetworkScope
from app.models.organization import Organization
from app.models.pentest_session import PentestSession
from app.models.probe import Probe
from app.models.report import Report
from app.models.risk_acceptance import RiskAcceptance
from app.models.rules_of_engagement import RulesOfEngagement
from app.models.scan_artifact import ScanArtifact
from app.models.scan_job import ScanJob
from app.models.service import Service
from app.models.site import Site
from app.models.user import User

__all__ = [
    "ActorType",
    "Asset",
    "AssetIdentifier",
    "AssetStatus",
    "AssetType",
    "AuditEvent",
    "ChangeEvent",
    "ChangeEventType",
    "CveRecord",
    "EnrollmentToken",
    "FeedHealth",
    "FeedSource",
    "FeedStatus",
    "Finding",
    "FindingNote",
    "FindingStatus",
    "FindingType",
    "IdentifierType",
    "JobMode",
    "JobStatus",
    "MatchConfidence",
    "NetworkScope",
    "Organization",
    "PentestSession",
    "PentestSessionStatus",
    "Probe",
    "ProbeStatus",
    "Report",
    "ReportFormat",
    "ReportStatus",
    "ReportType",
    "RiskAcceptance",
    "RiskAcceptanceStatus",
    "RulesOfEngagement",
    "ScanArtifact",
    "ScanJob",
    "Service",
    "ServiceState",
    "ServiceTransport",
    "Severity",
    "Site",
    "ThreatIntelEnrichment",
    "User",
    "UserRole",
    "ValidationStatus",
    "WebScanProfile",
]
