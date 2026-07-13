"""Remediation and verification services (Phase 10).

Covers the automatic resolve/reopen behavior tied to verification rescans and the
risk-acceptance lifecycle (including expiry, which reopens the finding and raises
an alerting change event).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.change_event import ChangeEvent
from app.models.enums import ChangeEventType, FindingStatus, RiskAcceptanceStatus
from app.models.finding import Finding
from app.models.risk_acceptance import RiskAcceptance
from app.models.scan_job import ScanJob
from app.services import sla


def _emit(
    session: AsyncSession,
    finding: Finding,
    event_type: ChangeEventType,
    summary: str,
    severity: str,
) -> None:
    session.add(
        ChangeEvent(
            organization_id=finding.organization_id,
            site_id=finding.site_id,
            asset_id=finding.asset_id,
            scan_job_id=finding.scan_job_id,
            event_type=event_type,
            severity=severity,
            summary=summary,
        )
    )


async def apply_verification(
    session: AsyncSession,
    *,
    job: ScanJob,
    scanner: str,
    seen_keys: set[str],
    now: datetime,
) -> int:
    """For a verification rescan, resolve each verified finding this scanner no
    longer observes (it is fixed). Returns the number resolved.

    Only findings produced by the same ``scanner`` are considered, so a finding
    is never resolved by the absence of a scanner that could not observe it.
    """
    ids = job.verifies_finding_ids_json or []
    if not ids:
        return 0
    resolved = 0
    for raw in ids:
        try:
            finding = await session.get(Finding, uuid.UUID(str(raw)))
        except ValueError:
            continue
        if finding is None or finding.organization_id != job.organization_id:
            continue
        if finding.scanner_name != scanner:
            continue
        finding.last_verified_at = now
        if finding.canonical_finding_key in seen_keys:
            continue  # still present
        if finding.status not in (FindingStatus.RESOLVED, FindingStatus.RISK_ACCEPTED):
            finding.status = FindingStatus.RESOLVED
            finding.resolved_at = now
            await sla.complete_finding(session, finding, now=now)
            _emit(
                session,
                finding,
                ChangeEventType.FINDING_VERIFIED,
                f"Verified fixed: {finding.title}",
                finding.severity.value,
            )
            resolved += 1
    return resolved


async def create_risk_acceptance(
    session: AsyncSession,
    *,
    finding: Finding,
    requested_by: uuid.UUID | None,
    reason: str,
    compensating_controls: str | None,
    starts_at: datetime | None,
    expires_at: datetime,
    now: datetime,
) -> RiskAcceptance:
    """Create a pending risk acceptance for a finding."""
    ra = RiskAcceptance(
        organization_id=finding.organization_id,
        finding_id=finding.id,
        requested_by=requested_by,
        reason=reason,
        compensating_controls=compensating_controls,
        starts_at=starts_at or now,
        expires_at=expires_at,
        status=RiskAcceptanceStatus.PENDING,
    )
    session.add(ra)
    await session.flush()
    return ra


async def decide_risk_acceptance(
    session: AsyncSession,
    *,
    ra: RiskAcceptance,
    finding: Finding,
    approve: bool,
    approved_by: uuid.UUID | None,
    review_notes: str | None,
) -> None:
    """Approve or reject a pending risk acceptance. Approval marks the finding
    risk-accepted and links the acceptance."""
    ra.approved_by = approved_by
    ra.review_notes = review_notes
    if approve:
        ra.status = RiskAcceptanceStatus.ACTIVE
        finding.status = FindingStatus.RISK_ACCEPTED
        finding.risk_acceptance_id = ra.id
        await sla.pause_for_risk_acceptance(session, finding)
    else:
        ra.status = RiskAcceptanceStatus.REJECTED


async def expire_risk_acceptances(session: AsyncSession, now: datetime) -> int:
    """Expire active risk acceptances past their expiry, reopen the finding, and
    raise an alerting change event. Returns the number expired."""
    result = await session.execute(
        select(RiskAcceptance).where(
            RiskAcceptance.status == RiskAcceptanceStatus.ACTIVE,
            RiskAcceptance.expires_at < now,
        )
    )
    count = 0
    for ra in result.scalars():
        ra.status = RiskAcceptanceStatus.EXPIRED
        finding = await session.get(Finding, ra.finding_id)
        if finding is not None and finding.risk_acceptance_id == ra.id:
            finding.risk_acceptance_id = None
            finding.status = FindingStatus.REOPENED
            await sla.resume_after_risk_acceptance(session, finding, now=now)
            _emit(
                session,
                finding,
                ChangeEventType.RISK_ACCEPTANCE_EXPIRED,
                f"Risk acceptance expired, finding reopened: {finding.title}",
                "high",
            )
        count += 1
    return count
