"""Explainable risk profiles, remediation units, and bounded decisions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth import site_scope
from app.auth.dependencies import CurrentUser, require_permission, require_step_up_permission
from app.db.session import get_session
from app.models.enums import (
    GrantScopeType,
    RemediationUnitStatus,
)
from app.models.finding import Finding
from app.models.risk import (
    FindingDecision,
    FindingScoreSnapshot,
    RemediationSuggestion,
    RemediationUnit,
    RemediationUnitFinding,
    RiskProfile,
)
from app.models.user import User
from app.schemas.common import Page
from app.schemas.risk import (
    AutoGroupRequest,
    AutoGroupResult,
    FindingDecisionCreate,
    FindingDecisionRead,
    FindingScoreRead,
    FuzzySuggestionRead,
    FuzzySuggestionRequest,
    RemediationMembershipRead,
    RemediationUnitCreate,
    RemediationUnitRead,
    RemediationUnitUpdate,
    RiskProfileCreate,
    RiskProfileRead,
    SuggestionReview,
)
from app.services import authorization, risk
from app.services.audit import record_audit

profile_router = APIRouter(
    prefix="/risk-profiles",
    tags=["explainable risk"],
    dependencies=[Depends(require_permission("findings.read"))],
)
score_router = APIRouter(
    prefix="/finding-scores",
    tags=["explainable risk"],
    dependencies=[Depends(require_permission("findings.read"))],
)
unit_router = APIRouter(
    prefix="/remediation-units",
    tags=["remediation units"],
    dependencies=[Depends(require_permission("remediation.read"))],
)
decision_router = APIRouter(
    prefix="/findings",
    tags=["finding decisions"],
    dependencies=[Depends(require_permission("findings.read"))],
)


def _error(exc: risk.RiskError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc))


def _audit(
    session: AsyncSession,
    *,
    action: str,
    actor: User,
    context: RequestContext,
    target_type: str,
    target_id: uuid.UUID | None,
    metadata: dict[str, Any] | None = None,
) -> None:
    record_audit(
        session,
        action=action,
        actor=actor,
        organization_id=actor.organization_id,
        target_type=target_type,
        target_id=target_id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata=metadata,
    )


async def _require_org_permission(session: AsyncSession, actor: User, permission_key: str) -> None:
    if not await authorization.has_permission(
        session,
        actor,
        permission_key,
        scope_type=GrantScopeType.ORGANIZATION,
        scope_id=actor.organization_id,
    ):
        raise HTTPException(status_code=403, detail="Organization-wide access is required")


async def _finding(
    session: AsyncSession,
    finding_id: uuid.UUID,
    actor: User,
    permission_key: str,
) -> Finding:
    finding = await session.scalar(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.organization_id == actor.organization_id,
            site_scope.site_scope_clause(actor, Finding.site_id, permission_key=permission_key),
        )
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


async def _findings(
    session: AsyncSession,
    finding_ids: list[uuid.UUID],
    actor: User,
    permission_key: str,
) -> list[Finding]:
    unique_ids = list(dict.fromkeys(finding_ids))
    rows = list(
        (
            await session.execute(
                select(Finding).where(
                    Finding.id.in_(unique_ids),
                    Finding.organization_id == actor.organization_id,
                    site_scope.site_scope_clause(
                        actor, Finding.site_id, permission_key=permission_key
                    ),
                )
            )
        ).scalars()
    )
    if len(rows) != len(unique_ids):
        raise HTTPException(status_code=404, detail="One or more findings were not found")
    return rows


async def _unit(
    session: AsyncSession,
    unit_id: uuid.UUID,
    actor: User,
    permission_key: str,
) -> RemediationUnit:
    unit = await session.get(RemediationUnit, unit_id)
    if unit is None or unit.organization_id != actor.organization_id:
        raise HTTPException(status_code=404, detail="Remediation unit not found")
    await site_scope.require_site_access(
        session,
        actor,
        unit.site_id,
        not_found_detail="Remediation unit not found",
        permission_key=permission_key,
    )
    return unit


async def _validate_owner(
    session: AsyncSession,
    actor: User,
    site_id: uuid.UUID,
    owner_user_id: uuid.UUID | None,
) -> None:
    if owner_user_id is None:
        return
    owner = await session.get(User, owner_user_id)
    if (
        owner is None
        or owner.organization_id != actor.organization_id
        or not await site_scope.can_access_site(
            session, owner, site_id, permission_key="remediation.read"
        )
    ):
        raise HTTPException(
            status_code=422,
            detail="The selected owner does not have remediation access to this site",
        )


async def _unit_read(session: AsyncSession, unit: RemediationUnit) -> RemediationUnitRead:
    memberships = list(
        (
            await session.execute(
                select(RemediationUnitFinding).where(
                    RemediationUnitFinding.remediation_unit_id == unit.id
                )
            )
        ).scalars()
    )
    scores = 0.0
    if memberships:
        scores = float(
            await session.scalar(
                select(func.coalesce(func.sum(Finding.risk_score), 0.0)).where(
                    Finding.id.in_([membership.finding_id for membership in memberships])
                )
            )
            or 0.0
        )
    return RemediationUnitRead.model_validate(unit).model_copy(
        update={
            "finding_count": len(memberships),
            "projected_risk_reduction": round(scores, 2),
        }
    )


@profile_router.get("", response_model=list[RiskProfileRead])
async def list_profiles(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[RiskProfileRead]:
    await risk.default_profile(session, current_user.organization_id)
    profiles = (
        await session.execute(
            select(RiskProfile)
            .where(RiskProfile.organization_id == current_user.organization_id)
            .order_by(RiskProfile.name, RiskProfile.version.desc())
        )
    ).scalars()
    return [RiskProfileRead.model_validate(profile) for profile in profiles]


@profile_router.post("", response_model=RiskProfileRead, status_code=201)
async def create_profile_version(
    payload: RiskProfileCreate,
    identity: Annotated[Any, Depends(require_step_up_permission("findings.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> RiskProfileRead:
    actor = identity.user
    await _require_org_permission(session, actor, "findings.manage")
    try:
        profile = await risk.create_profile_version(
            session,
            organization_id=actor.organization_id,
            name=payload.name,
            description=payload.description,
            weights=payload.weights,
            created_by_user_id=actor.id,
            make_default=payload.make_default,
        )
    except risk.RiskError as exc:
        raise _error(exc) from exc
    if payload.make_default:
        findings = (
            await session.execute(
                select(Finding).where(Finding.organization_id == actor.organization_id)
            )
        ).scalars()
        for finding in findings:
            await risk.score_finding(session, finding, profile=profile, created_by_user_id=actor.id)
    _audit(
        session,
        action="risk_profile.version_created",
        actor=actor,
        context=context,
        target_type="risk_profile",
        target_id=profile.id,
        metadata={"version": profile.version, "made_default": profile.is_default},
    )
    return RiskProfileRead.model_validate(profile)


@profile_router.post("/{profile_id}/activate", response_model=RiskProfileRead)
async def activate_profile(
    profile_id: uuid.UUID,
    identity: Annotated[Any, Depends(require_step_up_permission("findings.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> RiskProfileRead:
    actor = identity.user
    await _require_org_permission(session, actor, "findings.manage")
    profile = await session.get(RiskProfile, profile_id)
    if profile is None or profile.organization_id != actor.organization_id:
        raise HTTPException(status_code=404, detail="Risk profile not found")
    await risk.activate_profile(session, profile)
    findings = (
        await session.execute(
            select(Finding).where(Finding.organization_id == actor.organization_id)
        )
    ).scalars()
    count = 0
    for finding in findings:
        await risk.score_finding(
            session, finding, profile=profile, created_by_user_id=actor.id, force=True
        )
        count += 1
    _audit(
        session,
        action="risk_profile.activated",
        actor=actor,
        context=context,
        target_type="risk_profile",
        target_id=profile.id,
        metadata={"rescored_findings": count},
    )
    return RiskProfileRead.model_validate(profile)


@score_router.get("/{finding_id}", response_model=list[FindingScoreRead])
async def score_history(
    finding_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[FindingScoreRead]:
    await _finding(session, finding_id, current_user, "findings.read")
    rows = (
        await session.execute(
            select(FindingScoreSnapshot)
            .where(FindingScoreSnapshot.finding_id == finding_id)
            .order_by(FindingScoreSnapshot.created_at.desc())
        )
    ).scalars()
    return [FindingScoreRead.from_model(row) for row in rows]


@score_router.post("/{finding_id}/recalculate", response_model=FindingScoreRead)
async def recalculate_score(
    finding_id: uuid.UUID,
    identity: Annotated[Any, Depends(require_step_up_permission("findings.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> FindingScoreRead:
    actor = identity.user
    finding = await _finding(session, finding_id, actor, "findings.manage")
    snapshot = await risk.score_finding(session, finding, created_by_user_id=actor.id, force=True)
    _audit(
        session,
        action="finding.score_recalculated",
        actor=actor,
        context=context,
        target_type="finding_score_snapshot",
        target_id=snapshot.id,
        metadata={"finding_id": str(finding.id), "score": snapshot.score},
    )
    return FindingScoreRead.from_model(snapshot)


@unit_router.get("", response_model=Page[RemediationUnitRead])
async def list_units(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: Annotated[uuid.UUID | None, Query()] = None,
    unit_status: Annotated[RemediationUnitStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[RemediationUnitRead]:
    filters = [
        RemediationUnit.organization_id == current_user.organization_id,
        site_scope.site_scope_clause(
            current_user, RemediationUnit.site_id, permission_key="remediation.read"
        ),
    ]
    if site_id is not None:
        filters.append(RemediationUnit.site_id == site_id)
    if unit_status is not None:
        filters.append(RemediationUnit.status == unit_status)
    total = await session.scalar(select(func.count()).select_from(RemediationUnit).where(*filters))
    units = (
        await session.execute(
            select(RemediationUnit)
            .where(*filters)
            .order_by(RemediationUnit.updated_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars()
    return Page[RemediationUnitRead](
        items=[await _unit_read(session, unit) for unit in units],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@unit_router.post("", response_model=RemediationUnitRead, status_code=201)
async def create_unit(
    payload: RemediationUnitCreate,
    identity: Annotated[Any, Depends(require_step_up_permission("remediation.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> RemediationUnitRead:
    actor = identity.user
    await site_scope.require_site_access(
        session, actor, payload.site_id, permission_key="remediation.manage"
    )
    findings = await _findings(session, payload.finding_ids, actor, "remediation.manage")
    if any(finding.site_id != payload.site_id for finding in findings):
        raise HTTPException(status_code=422, detail="All findings must belong to the unit site")
    await _validate_owner(session, actor, payload.site_id, payload.owner_user_id)
    exact_key = " ".join(payload.exact_key.casefold().split())
    duplicate = await session.scalar(
        select(RemediationUnit.id).where(
            RemediationUnit.organization_id == actor.organization_id,
            RemediationUnit.site_id == payload.site_id,
            RemediationUnit.key_type == payload.key_type,
            RemediationUnit.exact_key == exact_key,
        )
    )
    if duplicate is not None:
        raise HTTPException(
            status_code=409, detail="A remediation unit already uses this exact key"
        )
    unit = RemediationUnit(
        organization_id=actor.organization_id,
        site_id=payload.site_id,
        key_type=payload.key_type,
        exact_key=exact_key,
        title=" ".join(payload.title.split()),
        description=payload.description,
        owner_user_id=payload.owner_user_id,
        status=RemediationUnitStatus.OPEN,
        automatically_created=False,
        created_by_user_id=actor.id,
    )
    session.add(unit)
    await session.flush()
    for finding in findings:
        session.add(
            RemediationUnitFinding(
                organization_id=actor.organization_id,
                remediation_unit_id=unit.id,
                finding_id=finding.id,
                match_basis_json={"method": "manual"},
                added_by_user_id=actor.id,
            )
        )
    await session.flush()
    _audit(
        session,
        action="remediation_unit.created",
        actor=actor,
        context=context,
        target_type="remediation_unit",
        target_id=unit.id,
        metadata={"finding_count": len(findings), "key_type": unit.key_type.value},
    )
    return await _unit_read(session, unit)


@unit_router.patch("/{unit_id}", response_model=RemediationUnitRead)
async def update_unit(
    unit_id: uuid.UUID,
    payload: RemediationUnitUpdate,
    identity: Annotated[Any, Depends(require_step_up_permission("remediation.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> RemediationUnitRead:
    actor = identity.user
    unit = await _unit(session, unit_id, actor, "remediation.manage")
    changes = payload.model_dump(exclude_unset=True)
    if "owner_user_id" in changes:
        await _validate_owner(session, actor, unit.site_id, changes["owner_user_id"])
    for field, value in changes.items():
        setattr(unit, field, value)
    _audit(
        session,
        action="remediation_unit.updated",
        actor=actor,
        context=context,
        target_type="remediation_unit",
        target_id=unit.id,
        metadata={"changed_fields": sorted(changes)},
    )
    return await _unit_read(session, unit)


@unit_router.post("/auto-group", response_model=AutoGroupResult)
async def auto_group(
    payload: AutoGroupRequest,
    identity: Annotated[Any, Depends(require_step_up_permission("remediation.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> AutoGroupResult:
    actor = identity.user
    findings = await _findings(session, payload.finding_ids, actor, "remediation.manage")
    created, memberships = await risk.auto_group_findings(session, findings, actor_user_id=actor.id)
    _audit(
        session,
        action="remediation_units.auto_grouped",
        actor=actor,
        context=context,
        target_type="remediation_unit",
        target_id=None,
        metadata={"units_created": created, "memberships_created": memberships},
    )
    return AutoGroupResult(units_created=created, memberships_created=memberships)


@unit_router.get("/{unit_id}/findings", response_model=list[RemediationMembershipRead])
async def list_memberships(
    unit_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[RemediationMembershipRead]:
    unit = await _unit(session, unit_id, current_user, "remediation.read")
    rows = (
        await session.execute(
            select(RemediationUnitFinding).where(
                RemediationUnitFinding.remediation_unit_id == unit.id
            )
        )
    ).scalars()
    return [RemediationMembershipRead.model_validate(row) for row in rows]


@unit_router.put(
    "/{unit_id}/findings/{finding_id}",
    response_model=RemediationMembershipRead,
    status_code=201,
)
async def add_membership(
    unit_id: uuid.UUID,
    finding_id: uuid.UUID,
    identity: Annotated[Any, Depends(require_step_up_permission("remediation.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> RemediationMembershipRead:
    actor = identity.user
    unit = await _unit(session, unit_id, actor, "remediation.manage")
    finding = await _finding(session, finding_id, actor, "remediation.manage")
    if finding.site_id != unit.site_id:
        raise HTTPException(status_code=422, detail="Finding and unit must belong to one site")
    membership = await session.scalar(
        select(RemediationUnitFinding).where(
            RemediationUnitFinding.remediation_unit_id == unit.id,
            RemediationUnitFinding.finding_id == finding.id,
        )
    )
    if membership is None:
        membership = RemediationUnitFinding(
            organization_id=actor.organization_id,
            remediation_unit_id=unit.id,
            finding_id=finding.id,
            match_basis_json={"method": "manual"},
            added_by_user_id=actor.id,
        )
        session.add(membership)
        await session.flush()
        _audit(
            session,
            action="remediation_unit.finding_added",
            actor=actor,
            context=context,
            target_type="remediation_unit",
            target_id=unit.id,
            metadata={"finding_id": str(finding.id)},
        )
    return RemediationMembershipRead.model_validate(membership)


@unit_router.delete("/{unit_id}/findings/{finding_id}", status_code=204)
async def remove_membership(
    unit_id: uuid.UUID,
    finding_id: uuid.UUID,
    identity: Annotated[Any, Depends(require_step_up_permission("remediation.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    actor = identity.user
    unit = await _unit(session, unit_id, actor, "remediation.manage")
    result = await session.execute(
        delete(RemediationUnitFinding).where(
            RemediationUnitFinding.remediation_unit_id == unit.id,
            RemediationUnitFinding.finding_id == finding_id,
        )
    )
    if not getattr(result, "rowcount", 0):
        raise HTTPException(status_code=404, detail="Remediation membership not found")
    _audit(
        session,
        action="remediation_unit.finding_removed",
        actor=actor,
        context=context,
        target_type="remediation_unit",
        target_id=unit.id,
        metadata={"finding_id": str(finding_id)},
    )


@unit_router.post("/{unit_id}/suggestions", response_model=list[FuzzySuggestionRead])
async def create_suggestions(
    unit_id: uuid.UUID,
    payload: FuzzySuggestionRequest,
    identity: Annotated[Any, Depends(require_step_up_permission("remediation.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> list[FuzzySuggestionRead]:
    actor = identity.user
    unit = await _unit(session, unit_id, actor, "remediation.manage")
    findings = await _findings(session, payload.finding_ids, actor, "remediation.manage")
    if any(finding.site_id != unit.site_id for finding in findings):
        raise HTTPException(status_code=422, detail="All findings must belong to the unit site")
    suggestions = await risk.suggest_fuzzy_memberships(
        session, unit=unit, findings=findings, threshold=payload.threshold
    )
    _audit(
        session,
        action="remediation_suggestions.generated",
        actor=actor,
        context=context,
        target_type="remediation_unit",
        target_id=unit.id,
        metadata={"suggestions_created": len(suggestions)},
    )
    return [FuzzySuggestionRead.model_validate(item) for item in suggestions]


@unit_router.get("/{unit_id}/suggestions", response_model=list[FuzzySuggestionRead])
async def list_suggestions(
    unit_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[FuzzySuggestionRead]:
    unit = await _unit(session, unit_id, current_user, "remediation.read")
    rows = (
        await session.execute(
            select(RemediationSuggestion)
            .where(RemediationSuggestion.remediation_unit_id == unit.id)
            .order_by(RemediationSuggestion.created_at.desc())
        )
    ).scalars()
    return [FuzzySuggestionRead.model_validate(row) for row in rows]


@unit_router.post("/suggestions/{suggestion_id}/review", response_model=FuzzySuggestionRead)
async def review_suggestion(
    suggestion_id: uuid.UUID,
    payload: SuggestionReview,
    identity: Annotated[Any, Depends(require_step_up_permission("remediation.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> FuzzySuggestionRead:
    actor = identity.user
    suggestion = await session.get(RemediationSuggestion, suggestion_id)
    if suggestion is None or suggestion.organization_id != actor.organization_id:
        raise HTTPException(status_code=404, detail="Remediation suggestion not found")
    await site_scope.require_site_access(
        session, actor, suggestion.site_id, permission_key="remediation.manage"
    )
    try:
        await risk.review_suggestion(
            session, suggestion, accept=payload.accept, reviewer_user_id=actor.id
        )
    except risk.RiskError as exc:
        raise _error(exc) from exc
    _audit(
        session,
        action="remediation_suggestion.reviewed",
        actor=actor,
        context=context,
        target_type="remediation_suggestion",
        target_id=suggestion.id,
        metadata={"accepted": payload.accept},
    )
    return FuzzySuggestionRead.model_validate(suggestion)


@decision_router.get("/{finding_id}/decisions", response_model=list[FindingDecisionRead])
async def list_decisions(
    finding_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[FindingDecisionRead]:
    await _finding(session, finding_id, current_user, "findings.read")
    rows = (
        await session.execute(
            select(FindingDecision)
            .where(FindingDecision.finding_id == finding_id)
            .order_by(FindingDecision.created_at.desc())
        )
    ).scalars()
    return [FindingDecisionRead.model_validate(row) for row in rows]


@decision_router.post(
    "/{finding_id}/decisions", response_model=FindingDecisionRead, status_code=201
)
async def create_decision(
    finding_id: uuid.UUID,
    payload: FindingDecisionCreate,
    identity: Annotated[Any, Depends(require_step_up_permission("findings.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> FindingDecisionRead:
    actor = identity.user
    finding = await _finding(session, finding_id, actor, "findings.manage")
    duplicate = None
    if payload.duplicate_of_finding_id:
        duplicate = await _finding(
            session, payload.duplicate_of_finding_id, actor, "findings.manage"
        )
    try:
        decision = await risk.create_finding_decision(
            session,
            finding=finding,
            decision_type=payload.decision_type,
            reason=payload.reason,
            evidence=payload.evidence,
            expires_at=payload.expires_at,
            duplicate_of=duplicate,
            actor_user_id=actor.id,
        )
    except risk.RiskError as exc:
        raise _error(exc) from exc
    _audit(
        session,
        action="finding_decision.created",
        actor=actor,
        context=context,
        target_type="finding_decision",
        target_id=decision.id,
        metadata={
            "finding_id": str(finding.id),
            "decision_type": decision.decision_type.value,
            "expires_at": decision.expires_at.isoformat(),
        },
    )
    return FindingDecisionRead.model_validate(decision)


@decision_router.post(
    "/{finding_id}/decisions/{decision_id}/revoke",
    response_model=FindingDecisionRead,
)
async def revoke_decision(
    finding_id: uuid.UUID,
    decision_id: uuid.UUID,
    identity: Annotated[Any, Depends(require_step_up_permission("findings.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> FindingDecisionRead:
    actor = identity.user
    await _finding(session, finding_id, actor, "findings.manage")
    decision = await session.get(FindingDecision, decision_id)
    if (
        decision is None
        or decision.organization_id != actor.organization_id
        or decision.finding_id != finding_id
    ):
        raise HTTPException(status_code=404, detail="Finding decision not found")
    try:
        await risk.revoke_finding_decision(session, decision, actor_user_id=actor.id)
    except risk.RiskError as exc:
        raise _error(exc) from exc
    _audit(
        session,
        action="finding_decision.revoked",
        actor=actor,
        context=context,
        target_type="finding_decision",
        target_id=decision.id,
    )
    return FindingDecisionRead.model_validate(decision)


@decision_router.post("/decisions/expire", response_model=dict[str, int])
async def expire_decisions(
    identity: Annotated[Any, Depends(require_step_up_permission("findings.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, int]:
    actor = identity.user
    await _require_org_permission(session, actor, "findings.manage")
    count = await risk.expire_finding_decisions(
        session, datetime.now(UTC), organization_id=actor.organization_id
    )
    _audit(
        session,
        action="finding_decisions.expired",
        actor=actor,
        context=context,
        target_type="finding_decision",
        target_id=None,
        metadata={"count": count},
    )
    return {"expired": count}
