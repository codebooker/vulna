"""Normalize and ingest scanner findings into the findings inventory.

Parsers (Nuclei, testssl.sh) produce ``ParsedFinding`` objects; this module maps
them to assets/services, computes a stable ``canonical_finding_key``, and upserts
findings — deduplicating repeats and reopening resolved findings that recur.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, AssetIdentifier
from app.models.change_event import ChangeEvent
from app.models.enums import (
    ChangeEventType,
    FindingStatus,
    FindingType,
    IdentifierType,
    ServiceTransport,
    Severity,
)
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.models.service import Service
from app.services import risk, sla


@dataclass
class ParsedFinding:
    """A scanner-agnostic finding produced by a parser."""

    scanner: str
    weakness_key: str  # stable per-weakness discriminator (e.g. nuclei template id)
    finding_type: FindingType
    title: str
    severity: Severity
    target_ip: str | None = None
    port: int | None = None
    transport: ServiceTransport = ServiceTransport.TCP
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    # 0-100 confidence that this finding is real; defaults to the Finding model's
    # neutral 50. Version-based CVE correlation sets it from the match confidence.
    confidence: int = 50
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    remediation: str | None = None
    evidence: dict[str, object] = field(default_factory=dict)
    scanner_finding_id: str | None = None


@dataclass
class FindingIngestSummary:
    findings_seen: int = 0
    findings_created: int = 0
    findings_updated: int = 0
    findings_reopened: int = 0
    change_events: int = 0
    # Canonical keys observed in this ingest, so a verification rescan can tell
    # which verified findings are still present versus fixed.
    seen_keys: set[str] = field(default_factory=set)


def canonical_finding_key(
    organization_id: uuid.UUID,
    asset_id: uuid.UUID | None,
    service_id: uuid.UUID | None,
    scanner: str,
    weakness_key: str,
) -> str:
    """Return a stable SHA-256 dedup key for a finding."""
    raw = f"{organization_id}|{asset_id or '-'}|{service_id or '-'}|{scanner}|{weakness_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def _resolve_asset(session: AsyncSession, job: ScanJob, ip: str | None) -> Asset | None:
    if not ip:
        return None
    result = await session.execute(
        select(Asset)
        .join(AssetIdentifier, AssetIdentifier.asset_id == Asset.id)
        .where(
            Asset.organization_id == job.organization_id,
            Asset.site_id == job.site_id,
            AssetIdentifier.identifier_type == IdentifierType.IP_ADDRESS,
            AssetIdentifier.identifier_value == ip,
        )
    )
    return result.scalars().first()


async def _resolve_service(
    session: AsyncSession, asset: Asset | None, transport: ServiceTransport, port: int | None
) -> Service | None:
    if asset is None or port is None:
        return None
    result = await session.execute(
        select(Service).where(
            Service.asset_id == asset.id,
            Service.transport == transport,
            Service.port == port,
        )
    )
    return result.scalar_one_or_none()


def _record_change(
    session: AsyncSession,
    job: ScanJob,
    asset: Asset,
    event_type: ChangeEventType,
    summary_text: str,
    severity: str,
) -> None:
    session.add(
        ChangeEvent(
            organization_id=job.organization_id,
            site_id=job.site_id,
            asset_id=asset.id,
            scan_job_id=job.id,
            event_type=event_type,
            severity=severity,
            summary=summary_text,
        )
    )


async def ingest_findings(
    session: AsyncSession,
    *,
    job: ScanJob,
    parsed: list[ParsedFinding],
    now: datetime,
) -> FindingIngestSummary:
    """Upsert parsed findings for a job, deduplicating by canonical key."""
    summary = FindingIngestSummary(findings_seen=len(parsed))
    for pf in parsed:
        asset = await _resolve_asset(session, job, pf.target_ip)
        service = await _resolve_service(session, asset, pf.transport, pf.port)
        asset_id = asset.id if asset else None
        service_id = service.id if service else None
        key = canonical_finding_key(
            job.organization_id, asset_id, service_id, pf.scanner, pf.weakness_key
        )
        summary.seen_keys.add(key)

        existing = await session.scalar(
            select(Finding).where(
                Finding.organization_id == job.organization_id,
                Finding.canonical_finding_key == key,
            )
        )
        if existing is None:
            session.add(
                finding := Finding(
                    organization_id=job.organization_id,
                    site_id=job.site_id,
                    asset_id=asset_id,
                    service_id=service_id,
                    scan_job_id=job.id,
                    scanner_name=pf.scanner,
                    scanner_finding_id=pf.scanner_finding_id,
                    canonical_finding_key=key,
                    finding_type=pf.finding_type,
                    title=pf.title,
                    description=pf.description,
                    severity=pf.severity,
                    cvss_score=pf.cvss_score,
                    cvss_vector=pf.cvss_vector,
                    confidence=pf.confidence,
                    cve_ids_json=pf.cve_ids,
                    cwe_ids_json=pf.cwe_ids,
                    evidence_json=pf.evidence,
                    remediation=pf.remediation,
                    references_json=pf.references,
                    status=FindingStatus.NEW,
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            summary.findings_created += 1
            if asset is not None:
                _record_change(
                    session, job, asset, ChangeEventType.NEW_FINDING,
                    f"New {pf.severity.value} finding: {pf.title}", pf.severity.value,
                )
                summary.change_events += 1
        else:
            finding = existing
            existing.last_seen_at = now
            existing.severity = pf.severity
            existing.cvss_score = pf.cvss_score
            existing.evidence_json = pf.evidence
            existing.description = pf.description or existing.description
            existing.references_json = pf.references or existing.references_json
            # Refresh the scanner-derived presentation too, so a re-scan picks up
            # improved titles/remediation/CVE mapping on findings that already
            # exist (these are never operator-edited — status/owner are separate).
            existing.title = pf.title
            existing.confidence = pf.confidence
            existing.remediation = pf.remediation or existing.remediation
            existing.cve_ids_json = pf.cve_ids or existing.cve_ids_json
            existing.cwe_ids_json = pf.cwe_ids or existing.cwe_ids_json
            existing.scan_job_id = job.id
            summary.findings_updated += 1
            if existing.status in (FindingStatus.RESOLVED,):
                existing.status = FindingStatus.REOPENED
                existing.reopened_count += 1
                existing.resolved_at = None
                summary.findings_reopened += 1
                if asset is not None:
                    _record_change(
                        session, job, asset, ChangeEventType.FINDING_REOPENED,
                        f"Finding reopened: {existing.title}", existing.severity.value,
                    )
                    summary.change_events += 1
        await session.flush()
        await risk.score_finding(session, finding, now=now)
        await sla.calculate_deadline(session, finding, now=now)
    return summary
