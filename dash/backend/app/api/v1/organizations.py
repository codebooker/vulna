"""Organization endpoints.

The MVP exposes a single organization but preserves organization boundaries:
callers only ever see and modify their own organization.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_permission
from app.db.session import get_session
from app.models.organization import Organization
from app.models.user import User
from app.schemas.organization import (
    ExperienceChange,
    ExperiencePreview,
    ExperienceRead,
    OrganizationRead,
    OrganizationUpdate,
)
from app.schemas.session import SessionPolicyRead, SessionPolicyUpdate
from app.services.audit import record_audit
from app.services.experience import experience_payload
from app.services.sessions import policy_dict, session_policy, update_session_policy

router = APIRouter(prefix="/organizations", tags=["organizations"])


async def _get_own_org(session: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = await session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    return org


@router.get("/current", response_model=OrganizationRead, summary="Get the caller's organization")
async def get_current_org(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> OrganizationRead:
    org = await _get_own_org(session, current_user.organization_id)
    return OrganizationRead.model_validate(org)


@router.get(
    "/current/experience",
    response_model=ExperienceRead,
    summary="Get the dashboard experience profile",
)
async def get_current_experience(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ExperienceRead:
    org = await _get_own_org(session, current_user.organization_id)
    return ExperienceRead.model_validate(
        experience_payload(org.experience_profile, org.feature_overrides_json)
    )


@router.post(
    "/current/experience/preview",
    response_model=ExperiencePreview,
    summary="Preview a dashboard experience change",
)
async def preview_current_experience(
    payload: ExperienceChange,
    admin: Annotated[User, Depends(require_permission("organization.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ExperiencePreview:
    org = await _get_own_org(session, admin.organization_id)
    try:
        result = experience_payload(
            payload.experience_profile,
            payload.feature_overrides,
            previous=(org.experience_profile, org.feature_overrides_json),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return ExperiencePreview.model_validate(result)


@router.patch(
    "/current/experience",
    response_model=ExperienceRead,
    summary="Update the dashboard experience profile",
)
async def update_current_experience(
    payload: ExperienceChange,
    admin: Annotated[User, Depends(require_permission("organization.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ExperienceRead:
    org = await _get_own_org(session, admin.organization_id)
    old_profile = org.experience_profile
    old_overrides = dict(org.feature_overrides_json or {})
    try:
        result = experience_payload(
            payload.experience_profile,
            payload.feature_overrides,
            previous=(old_profile, old_overrides),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    org.experience_profile = payload.experience_profile
    org.feature_overrides_json = dict(payload.feature_overrides)
    session.add(org)
    await session.flush()
    record_audit(
        session,
        action="organization.experience_profile_updated",
        actor=admin,
        organization_id=org.id,
        target_type="organization",
        target_id=org.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "old_profile": old_profile.value,
            "new_profile": payload.experience_profile.value,
            "old_overrides": old_overrides,
            "new_overrides": payload.feature_overrides,
            "changed_routes": result["changed_routes"],
        },
    )
    return ExperienceRead.model_validate(result)


@router.get(
    "/current/session-policy",
    response_model=SessionPolicyRead,
    summary="Get the organization session policy",
)
async def get_session_policy(
    admin: Annotated[User, Depends(require_permission("organization.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> SessionPolicyRead:
    org = await _get_own_org(session, admin.organization_id)
    return SessionPolicyRead.model_validate(policy_dict(session_policy(org)))


@router.patch(
    "/current/session-policy",
    response_model=SessionPolicyRead,
    summary="Update the organization session policy",
)
async def patch_session_policy(
    payload: SessionPolicyUpdate,
    admin: Annotated[User, Depends(require_permission("organization.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> SessionPolicyRead:
    org = await _get_own_org(session, admin.organization_id)
    old = policy_dict(session_policy(org))
    changes = payload.model_dump(exclude_none=True)
    updated = update_session_policy(org, changes)
    await session.flush()
    record_audit(
        session,
        action="organization.session_policy_updated",
        actor=admin,
        target_type="organization",
        target_id=org.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"old": old, "new": policy_dict(updated)},
    )
    return SessionPolicyRead.model_validate(policy_dict(updated))


@router.get("/{org_id}", response_model=OrganizationRead, summary="Get an organization")
async def get_org(
    org_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> OrganizationRead:
    if org_id != current_user.organization_id:
        # Do not disclose the existence of other organizations.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    org = await _get_own_org(session, org_id)
    return OrganizationRead.model_validate(org)


@router.patch("/{org_id}", response_model=OrganizationRead, summary="Update an organization")
async def update_org(
    org_id: uuid.UUID,
    payload: OrganizationUpdate,
    admin: Annotated[User, Depends(require_permission("organization.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> OrganizationRead:
    """Update the caller's organization (Administrator only)."""
    if org_id != admin.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    org = await _get_own_org(session, org_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(org, field, value)
    await session.flush()

    record_audit(
        session,
        action="organization.updated",
        actor=admin,
        organization_id=org.id,
        target_type="organization",
        target_id=org.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"changed_fields": sorted(changes.keys())},
    )
    return OrganizationRead.model_validate(org)
