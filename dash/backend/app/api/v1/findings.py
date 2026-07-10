"""Finding read and workflow endpoints.

Reading findings is available to any authenticated user in the organization;
changing a finding's workflow status requires the Administrator or Security
Operator role.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_roles
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.asset import AssetIdentifier
from app.models.enums import (
    FindingStatus,
    FindingType,
    IdentifierType,
    JobMode,
    ProbeStatus,
    Severity,
    UserRole,
)
from app.models.finding import Finding
from app.models.finding_note import FindingNote
from app.models.probe import Probe
from app.models.user import User
from app.schemas.common import Page
from app.schemas.finding import (
    BulkFindingAction,
    BulkFindingResult,
    FindingNoteCreate,
    FindingNoteRead,
    FindingRead,
    FindingUpdate,
)
from app.schemas.job import JobRead
from app.schemas.risk_acceptance import RiskAcceptanceCreate, RiskAcceptanceRead
from app.services.audit import record_audit
from app.services.jobs import JobValidationError, create_scan_job
from app.services.remediation import create_risk_acceptance

router = APIRouter(prefix="/findings", tags=["findings"])

_require_operator = require_roles(UserRole.ADMINISTRATOR, UserRole.SECURITY_OPERATOR)
_OPERATOR_ROLES = (UserRole.ADMINISTRATOR, UserRole.SECURITY_OPERATOR)


async def _get_owned_finding(
    session: AsyncSession, finding_id: uuid.UUID, org_id: uuid.UUID
) -> Finding:
    finding = await session.get(Finding, finding_id)
    if finding is None or finding.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


@router.get("", response_model=Page[FindingRead], summary="List findings")
async def list_findings(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    site_id: Annotated[uuid.UUID | None, Query()] = None,
    severity: Annotated[Severity | None, Query()] = None,
    finding_status: Annotated[FindingStatus | None, Query(alias="status")] = None,
    finding_type: Annotated[FindingType | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[FindingRead]:
    """List findings in the caller's organization, most recent first."""
    filters = [Finding.organization_id == current_user.organization_id]
    if asset_id is not None:
        filters.append(Finding.asset_id == asset_id)
    if site_id is not None:
        filters.append(Finding.site_id == site_id)
    if severity is not None:
        filters.append(Finding.severity == severity)
    if finding_status is not None:
        filters.append(Finding.status == finding_status)
    if finding_type is not None:
        filters.append(Finding.finding_type == finding_type)

    total = await session.scalar(select(func.count()).select_from(Finding).where(*filters))
    result = await session.execute(
        select(Finding).where(*filters).order_by(Finding.last_seen_at.desc()).limit(limit).offset(offset)
    )
    findings = result.scalars().all()
    return Page[FindingRead](
        items=[FindingRead.from_model(f) for f in findings],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


_BULK_ACTIONS = {"assign", "false_positive", "start_remediation", "triage"}


@router.post("/bulk", response_model=BulkFindingResult, summary="Apply an action to many findings")
async def bulk_update(
    payload: BulkFindingAction,
    operator: Annotated[User, Depends(require_roles(*_OPERATOR_ROLES))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> BulkFindingResult:
    """Apply one workflow action to several findings. Each finding is checked for
    per-object ownership (findings outside the caller's org are skipped, never
    touched) and every change produces its own audit event."""
    if payload.action not in _BULK_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"action must be one of {sorted(_BULK_ACTIONS)}",
        )
    if payload.action == "assign" and payload.owner_user_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="assign requires owner_user_id",
        )

    updated: list[uuid.UUID] = []
    skipped = 0
    for finding_id in payload.finding_ids:
        finding = await session.get(Finding, finding_id)
        # Per-object authorization: silently skip anything not in the caller's org.
        if finding is None or finding.organization_id != operator.organization_id:
            skipped += 1
            continue
        if payload.action == "assign":
            finding.owner_user_id = payload.owner_user_id
            finding.status = FindingStatus.ASSIGNED
        elif payload.action == "false_positive":
            finding.status = FindingStatus.FALSE_POSITIVE
            finding.false_positive_reason = payload.false_positive_reason
        elif payload.action == "start_remediation":
            finding.status = FindingStatus.REMEDIATION_IN_PROGRESS
        elif payload.action == "triage":
            finding.status = FindingStatus.TRIAGE
        session.add(finding)
        record_audit(
            session,
            action="finding.bulk_updated",
            actor=operator,
            organization_id=operator.organization_id,
            target_type="finding",
            target_id=finding.id,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            request_id=context.request_id,
            metadata={"action": payload.action},
        )
        updated.append(finding.id)

    await session.commit()
    return BulkFindingResult(updated=updated, skipped=skipped)


@router.get("/{finding_id}", response_model=FindingRead, summary="Get a finding")
async def get_finding(
    finding_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> FindingRead:
    finding = await _get_owned_finding(session, finding_id, current_user.organization_id)
    return FindingRead.from_model(finding)


@router.patch("/{finding_id}", response_model=FindingRead, summary="Update a finding's workflow")
async def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> FindingRead:
    """Update a finding's workflow, validation, assignment, or due date.

    Operators and administrators may update any finding; the assigned owner may
    update their own finding (e.g. mark it ready for verification).
    """
    finding = await _get_owned_finding(session, finding_id, current_user.organization_id)
    is_owner = finding.owner_user_id == current_user.id
    if current_user.role not in _OPERATOR_ROLES and not is_owner:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only an operator, administrator, or the finding owner may update it",
        )

    changes = payload.model_dump(exclude_unset=True)
    if "status" in changes:
        finding.status = changes["status"]
        if changes["status"] == FindingStatus.RESOLVED:
            finding.resolved_at = datetime.now(UTC)
    if "validation_status" in changes:
        finding.validation_status = changes["validation_status"]
    if "owner_user_id" in changes:
        finding.owner_user_id = changes["owner_user_id"]
    if "due_at" in changes:
        finding.due_at = changes["due_at"]
    if "false_positive_reason" in changes:
        finding.false_positive_reason = changes["false_positive_reason"]
    await session.flush()

    record_audit(
        session,
        action="finding.updated",
        actor=current_user,
        organization_id=current_user.organization_id,
        target_type="finding",
        target_id=finding.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": sorted(changes.keys())},
    )
    return FindingRead.from_model(finding)


@router.get(
    "/{finding_id}/notes",
    response_model=list[FindingNoteRead],
    summary="List a finding's notes",
)
async def list_finding_notes(
    finding_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[FindingNoteRead]:
    await _get_owned_finding(session, finding_id, current_user.organization_id)
    result = await session.execute(
        select(FindingNote)
        .where(FindingNote.finding_id == finding_id)
        .order_by(FindingNote.created_at)
    )
    return [FindingNoteRead.model_validate(n) for n in result.scalars().all()]


@router.post(
    "/{finding_id}/notes",
    response_model=FindingNoteRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add a note to a finding",
)
async def add_finding_note(
    finding_id: uuid.UUID,
    payload: FindingNoteCreate,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> FindingNoteRead:
    """Add an append-only note (any authenticated user in the organization)."""
    await _get_owned_finding(session, finding_id, current_user.organization_id)
    note = FindingNote(
        finding_id=finding_id, author_user_id=current_user.id, body=payload.body
    )
    session.add(note)
    await session.flush()
    return FindingNoteRead.model_validate(note)


@router.post(
    "/{finding_id}/rescan",
    response_model=JobRead,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger a targeted verification rescan",
)
async def rescan_finding(
    finding_id: uuid.UUID,
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> JobRead:
    """Create a scan job that re-checks this finding's asset. If the scanner no
    longer observes the finding, it is resolved as fixed."""
    finding = await _get_owned_finding(session, finding_id, operator.organization_id)
    if finding.asset_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Finding is not tied to an asset and cannot be rescanned",
        )
    ip = await session.scalar(
        select(AssetIdentifier.identifier_value)
        .where(
            AssetIdentifier.asset_id == finding.asset_id,
            AssetIdentifier.identifier_type == IdentifierType.IP_ADDRESS,
        )
        .order_by(AssetIdentifier.created_at)
        .limit(1)
    )
    if ip is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Finding's asset has no IP address to rescan",
        )
    probe = await session.scalar(
        select(Probe)
        .where(Probe.site_id == finding.site_id, Probe.status == ProbeStatus.ENROLLED)
        .limit(1)
    )
    if probe is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No enrolled probe at this finding's site to run a verification scan",
        )
    try:
        job = await create_scan_job(
            session,
            probe,
            settings,
            targets=[ip],
            mode=JobMode.VULNERABILITY_ASSESSMENT,
            created_by=operator.id,
            verifies_finding_ids=[str(finding.id)],
        )
    except JobValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    record_audit(
        session,
        action="finding.rescan",
        actor=operator,
        organization_id=operator.organization_id,
        target_type="finding",
        target_id=finding.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"job_id": str(job.id), "target": ip},
    )
    return JobRead.model_validate(job)


@router.post(
    "/{finding_id}/risk-acceptances",
    response_model=RiskAcceptanceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Request risk acceptance for a finding",
)
async def request_risk_acceptance(
    finding_id: uuid.UUID,
    payload: RiskAcceptanceCreate,
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> RiskAcceptanceRead:
    """Request a bounded risk acceptance (an approver activates it separately)."""
    finding = await _get_owned_finding(session, finding_id, operator.organization_id)
    ra = await create_risk_acceptance(
        session,
        finding=finding,
        requested_by=operator.id,
        reason=payload.reason,
        compensating_controls=payload.compensating_controls,
        starts_at=payload.starts_at,
        expires_at=payload.expires_at,
        now=datetime.now(UTC),
    )
    record_audit(
        session,
        action="risk_acceptance.requested",
        actor=operator,
        organization_id=operator.organization_id,
        target_type="risk_acceptance",
        target_id=ra.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"finding_id": str(finding.id)},
    )
    return RiskAcceptanceRead.model_validate(ra)
