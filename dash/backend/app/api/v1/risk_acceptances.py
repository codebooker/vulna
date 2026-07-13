"""Risk-acceptance listing, approval/rejection, and expiry."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_permission
from app.auth.site_scope import site_scope_clause
from app.db.session import get_session
from app.models.enums import RiskAcceptanceStatus
from app.models.finding import Finding
from app.models.risk_acceptance import RiskAcceptance
from app.models.user import User
from app.schemas.common import Page
from app.schemas.risk_acceptance import (
    ExpiryResult,
    RiskAcceptanceDecision,
    RiskAcceptanceRead,
)
from app.services.audit import record_audit
from app.services.remediation import decide_risk_acceptance, expire_risk_acceptances

router = APIRouter(
    prefix="/risk-acceptances",
    tags=["risk-acceptances"],
    dependencies=[Depends(require_permission("risk_acceptance.read"))],
)

_require_approver = require_permission("risk_acceptance.approve")


@router.get("", response_model=Page[RiskAcceptanceRead], summary="List risk acceptances")
async def list_risk_acceptances(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    finding_id: Annotated[uuid.UUID | None, Query()] = None,
    ra_status: Annotated[RiskAcceptanceStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[RiskAcceptanceRead]:
    filters = [
        RiskAcceptance.organization_id == current_user.organization_id,
        site_scope_clause(
            current_user, Finding.site_id, permission_key="risk_acceptance.read"
        ),
    ]
    if finding_id is not None:
        filters.append(RiskAcceptance.finding_id == finding_id)
    if ra_status is not None:
        filters.append(RiskAcceptance.status == ra_status)
    total = await session.scalar(
        select(func.count())
        .select_from(RiskAcceptance)
        .join(Finding, Finding.id == RiskAcceptance.finding_id)
        .where(*filters)
    )
    result = await session.execute(
        select(RiskAcceptance)
        .join(Finding, Finding.id == RiskAcceptance.finding_id)
        .where(*filters)
        .order_by(RiskAcceptance.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return Page[RiskAcceptanceRead](
        items=[RiskAcceptanceRead.model_validate(r) for r in result.scalars().all()],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.patch(
    "/{acceptance_id}",
    response_model=RiskAcceptanceRead,
    summary="Approve or reject a risk acceptance",
)
async def decide(
    acceptance_id: uuid.UUID,
    payload: RiskAcceptanceDecision,
    approver: Annotated[User, Depends(_require_approver)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> RiskAcceptanceRead:
    """Activate (approve) or decline (reject) a pending risk acceptance."""
    ra = await session.scalar(
        select(RiskAcceptance)
        .join(Finding, Finding.id == RiskAcceptance.finding_id)
        .where(
            RiskAcceptance.id == acceptance_id,
            RiskAcceptance.organization_id == approver.organization_id,
            site_scope_clause(
                approver, Finding.site_id, permission_key="risk_acceptance.approve"
            ),
        )
    )
    if ra is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Risk acceptance not found"
        )
    if ra.status != RiskAcceptanceStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Risk acceptance is not pending (is '{ra.status.value}')",
        )
    finding = await session.get(Finding, ra.finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    await decide_risk_acceptance(
        session,
        ra=ra,
        finding=finding,
        approve=payload.approve,
        approved_by=approver.id,
        review_notes=payload.review_notes,
    )
    record_audit(
        session,
        action="risk_acceptance.approved" if payload.approve else "risk_acceptance.rejected",
        actor=approver,
        organization_id=approver.organization_id,
        target_type="risk_acceptance",
        target_id=ra.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"finding_id": str(finding.id)},
    )
    return RiskAcceptanceRead.model_validate(ra)


@router.post(
    "/run-expiry",
    response_model=ExpiryResult,
    summary="Expire lapsed risk acceptances (admin)",
)
async def run_expiry(
    admin: Annotated[User, Depends(require_permission("risk_acceptance.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ExpiryResult:
    """Expire active acceptances past their expiry, reopening each finding and
    raising an alerting change event. Intended for a scheduled sweep."""
    count = await expire_risk_acceptances(session, datetime.now(UTC))
    return ExpiryResult(expired=count)
