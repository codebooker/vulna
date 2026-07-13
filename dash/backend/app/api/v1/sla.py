"""Prioritized SLA policies, immutable deadlines, guidance, and metrics."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import (
    AuthenticatedIdentity,
    CurrentUser,
    require_permission,
    require_step_up_permission,
)
from app.auth.site_scope import accessible_site_ids, site_scope_clause
from app.db.session import get_session
from app.models.finding import Finding
from app.models.sla import (
    FindingSlaCalculation,
    RemediationGuidance,
    SlaException,
    SlaHistory,
    SlaPolicy,
)
from app.schemas.sla import (
    RemediationGuidanceCreate,
    RemediationGuidanceRead,
    SlaCalculationRead,
    SlaExceptionCreate,
    SlaExceptionDecision,
    SlaExceptionRead,
    SlaHistoryRead,
    SlaMetricsRead,
    SlaPolicyCreate,
    SlaPolicyRead,
    SlaPolicyUpdate,
)
from app.services import sla
from app.services.audit import record_audit

router = APIRouter(
    prefix="/sla", tags=["sla"], dependencies=[Depends(require_permission("sla.read"))]
)


async def _owned_finding(
    session: AsyncSession,
    finding_id: uuid.UUID,
    actor: CurrentUser,
    *,
    permission_key: str,
) -> Finding:
    finding = await session.scalar(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.organization_id == actor.organization_id,
            site_scope_clause(actor, Finding.site_id, permission_key=permission_key),
        )
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


async def _unique_policy_fields(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    name: str,
    priority: int,
    exclude_id: uuid.UUID | None = None,
) -> None:
    statement = select(SlaPolicy.id).where(
        SlaPolicy.organization_id == organization_id,
        or_(SlaPolicy.name == name, SlaPolicy.priority == priority),
    )
    if exclude_id is not None:
        statement = statement.where(SlaPolicy.id != exclude_id)
    if await session.scalar(statement) is not None:
        raise HTTPException(
            status_code=409, detail="SLA policy name and priority must be unique"
        )


@router.get("/policies", response_model=list[SlaPolicyRead])
async def list_policies(
    actor: CurrentUser, session: Annotated[AsyncSession, Depends(get_session)]
) -> list[SlaPolicyRead]:
    rows = (
        await session.execute(
            select(SlaPolicy)
            .where(SlaPolicy.organization_id == actor.organization_id)
            .order_by(SlaPolicy.priority)
        )
    ).scalars()
    return [SlaPolicyRead.model_validate(row) for row in rows]


@router.post("/policies", response_model=SlaPolicyRead, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: SlaPolicyCreate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("sla.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> SlaPolicyRead:
    actor = identity.user
    await _unique_policy_fields(
        session, actor.organization_id, name=payload.name.strip(), priority=payload.priority
    )
    try:
        match = sla.validate_match(payload.match)
        due_days = sla.validate_due_days(payload.due_days)
    except sla.SlaError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    policy = SlaPolicy(
        organization_id=actor.organization_id,
        name=payload.name.strip(),
        description=payload.description,
        priority=payload.priority,
        enabled=payload.enabled,
        match_json=match,
        due_days_json=due_days,
        pause_on_risk_acceptance=payload.pause_on_risk_acceptance,
        created_by_user_id=actor.id,
    )
    session.add(policy)
    await session.flush()
    record_audit(
        session,
        action="sla.policy_created",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="sla_policy",
        target_id=policy.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"priority": policy.priority, "enabled": policy.enabled},
    )
    return SlaPolicyRead.model_validate(policy)


@router.patch("/policies/{policy_id}", response_model=SlaPolicyRead)
async def update_policy(
    policy_id: uuid.UUID,
    payload: SlaPolicyUpdate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("sla.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> SlaPolicyRead:
    actor = identity.user
    policy = await session.scalar(
        select(SlaPolicy).where(
            SlaPolicy.id == policy_id, SlaPolicy.organization_id == actor.organization_id
        )
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="SLA policy not found")
    changes = payload.model_dump(exclude_unset=True)
    name = str(changes.get("name", policy.name)).strip()
    priority = int(changes.get("priority", policy.priority))
    await _unique_policy_fields(
        session,
        actor.organization_id,
        name=name,
        priority=priority,
        exclude_id=policy.id,
    )
    try:
        if "match" in changes:
            policy.match_json = sla.validate_match(changes.pop("match"))
        if "due_days" in changes:
            policy.due_days_json = sla.validate_due_days(changes.pop("due_days"))
    except sla.SlaError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    policy.name = name
    policy.priority = priority
    for field in ("description", "enabled", "pause_on_risk_acceptance"):
        if field in changes:
            setattr(policy, field, changes[field])
    record_audit(
        session,
        action="sla.policy_updated",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="sla_policy",
        target_id=policy.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": sorted(payload.model_fields_set)},
    )
    return SlaPolicyRead.model_validate(policy)


@router.get("/metrics", response_model=SlaMetricsRead)
async def get_metrics(
    actor: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> SlaMetricsRead:
    sites = await accessible_site_ids(session, actor, permission_key="sla.read")
    return SlaMetricsRead.model_validate(
        await sla.metrics(session, actor.organization_id, site_ids=sites)
    )


@router.post("/findings/{finding_id}/calculate", response_model=SlaCalculationRead)
async def calculate_finding_sla(
    finding_id: uuid.UUID,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("sla.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> SlaCalculationRead:
    actor = identity.user
    finding = await _owned_finding(
        session, finding_id, actor, permission_key="sla.manage"
    )
    calculation = await sla.calculate_deadline(
        session, finding, created_by_user_id=actor.id
    )
    record_audit(
        session,
        action="sla.finding_calculated",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="finding",
        target_id=finding.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"calculation_id": str(calculation.id), "due_at": calculation.due_at.isoformat()},
    )
    return SlaCalculationRead.model_validate(calculation)


@router.get("/findings/{finding_id}/calculations", response_model=list[SlaCalculationRead])
async def list_calculations(
    finding_id: uuid.UUID,
    actor: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[SlaCalculationRead]:
    await _owned_finding(session, finding_id, actor, permission_key="sla.read")
    rows = (
        await session.execute(
            select(FindingSlaCalculation)
            .where(FindingSlaCalculation.finding_id == finding_id)
            .order_by(FindingSlaCalculation.created_at)
        )
    ).scalars()
    return [SlaCalculationRead.model_validate(row) for row in rows]


@router.post(
    "/findings/{finding_id}/exceptions",
    response_model=SlaExceptionRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_exception(
    finding_id: uuid.UUID,
    payload: SlaExceptionCreate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("sla.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> SlaExceptionRead:
    actor = identity.user
    finding = await _owned_finding(session, finding_id, actor, permission_key="sla.manage")
    try:
        exception = await sla.request_exception(
            session,
            finding,
            requested_due_at=payload.requested_due_at,
            reason=payload.reason,
            requested_by_user_id=actor.id,
        )
    except sla.SlaError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record_audit(
        session,
        action="sla.exception_requested",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="sla_exception",
        target_id=exception.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "finding_id": str(finding.id),
            "requested_due_at": payload.requested_due_at.isoformat(),
        },
    )
    return SlaExceptionRead.model_validate(exception)


@router.patch("/exceptions/{exception_id}", response_model=SlaExceptionRead)
async def review_exception(
    exception_id: uuid.UUID,
    payload: SlaExceptionDecision,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("sla.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> SlaExceptionRead:
    actor = identity.user
    exception = await session.scalar(
        select(SlaException)
        .join(Finding, Finding.id == SlaException.finding_id)
        .where(
            SlaException.id == exception_id,
            SlaException.organization_id == actor.organization_id,
            site_scope_clause(actor, Finding.site_id, permission_key="sla.manage"),
        )
    )
    if exception is None:
        raise HTTPException(status_code=404, detail="SLA exception not found")
    finding = await session.get(Finding, exception.finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    try:
        await sla.decide_exception(
            session,
            finding,
            exception,
            approve=payload.approve,
            reviewed_by_user_id=actor.id,
            review_notes=payload.review_notes,
        )
    except sla.SlaError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    record_audit(
        session,
        action="sla.exception_approved" if payload.approve else "sla.exception_rejected",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="sla_exception",
        target_id=exception.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"finding_id": str(finding.id)},
    )
    return SlaExceptionRead.model_validate(exception)


@router.get("/findings/{finding_id}/history", response_model=list[SlaHistoryRead])
async def list_history(
    finding_id: uuid.UUID,
    actor: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[SlaHistoryRead]:
    await _owned_finding(session, finding_id, actor, permission_key="sla.read")
    rows = (
        await session.execute(
            select(SlaHistory)
            .where(SlaHistory.finding_id == finding_id)
            .order_by(SlaHistory.created_at)
        )
    ).scalars()
    return [SlaHistoryRead.model_validate(row) for row in rows]


@router.get("/findings/{finding_id}/guidance", response_model=list[RemediationGuidanceRead])
async def list_guidance(
    finding_id: uuid.UUID,
    actor: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[RemediationGuidanceRead]:
    await _owned_finding(session, finding_id, actor, permission_key="sla.read")
    rows = (
        await session.execute(
            select(RemediationGuidance)
            .where(RemediationGuidance.finding_id == finding_id)
            .order_by(RemediationGuidance.created_at.desc())
        )
    ).scalars()
    return [RemediationGuidanceRead.model_validate(row) for row in rows]


@router.post(
    "/findings/{finding_id}/guidance",
    response_model=RemediationGuidanceRead,
    status_code=status.HTTP_201_CREATED,
)
async def add_guidance(
    finding_id: uuid.UUID,
    payload: RemediationGuidanceCreate,
    identity: Annotated[
        AuthenticatedIdentity, Depends(require_step_up_permission("sla.manage"))
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> RemediationGuidanceRead:
    actor = identity.user
    finding = await _owned_finding(session, finding_id, actor, permission_key="sla.manage")
    try:
        guidance = await sla.create_guidance(
            session,
            finding,
            classification=payload.classification,
            summary=payload.summary,
            steps=[step.model_dump() for step in payload.steps],
            validation_steps=[step.model_dump() for step in payload.validation_steps],
            references=payload.references,
            source=payload.source,
            created_by_user_id=actor.id,
        )
    except sla.SlaError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record_audit(
        session,
        action="remediation.guidance_created",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="remediation_guidance",
        target_id=guidance.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"finding_id": str(finding.id), "classification": payload.classification.value},
    )
    return RemediationGuidanceRead.model_validate(guidance)
