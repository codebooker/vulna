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
from app.db.session import get_session
from app.models.enums import FindingStatus, FindingType, Severity, UserRole
from app.models.finding import Finding
from app.models.user import User
from app.schemas.common import Page
from app.schemas.finding import FindingRead, FindingUpdate
from app.services.audit import record_audit

router = APIRouter(prefix="/findings", tags=["findings"])

_require_operator = require_roles(UserRole.ADMINISTRATOR, UserRole.SECURITY_OPERATOR)


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
        items=[FindingRead.model_validate(f) for f in findings],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{finding_id}", response_model=FindingRead, summary="Get a finding")
async def get_finding(
    finding_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> FindingRead:
    finding = await _get_owned_finding(session, finding_id, current_user.organization_id)
    return FindingRead.model_validate(finding)


@router.patch("/{finding_id}", response_model=FindingRead, summary="Update a finding's workflow")
async def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    operator: Annotated[User, Depends(_require_operator)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> FindingRead:
    """Update a finding's workflow/validation status (Operator/Administrator)."""
    finding = await _get_owned_finding(session, finding_id, operator.organization_id)
    changes = payload.model_dump(exclude_unset=True)
    if "status" in changes:
        finding.status = changes["status"]
        if changes["status"] == FindingStatus.RESOLVED:
            finding.resolved_at = datetime.now(UTC)
    if "validation_status" in changes:
        finding.validation_status = changes["validation_status"]
    await session.flush()

    record_audit(
        session,
        action="finding.updated",
        actor=operator,
        organization_id=operator.organization_id,
        target_type="finding",
        target_id=finding.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": sorted(changes.keys())},
    )
    return FindingRead.model_validate(finding)
