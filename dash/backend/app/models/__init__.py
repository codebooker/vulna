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
    ProbeStatus,
    ServiceState,
    ServiceTransport,
    Severity,
    UserRole,
    ValidationStatus,
)
from app.models.feed_health import FeedHealth
from app.models.finding import Finding
from app.models.network_scope import NetworkScope
from app.models.organization import Organization
from app.models.probe import Probe
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
    "FindingStatus",
    "FindingType",
    "IdentifierType",
    "JobMode",
    "JobStatus",
    "MatchConfidence",
    "NetworkScope",
    "Organization",
    "Probe",
    "ProbeStatus",
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
]
