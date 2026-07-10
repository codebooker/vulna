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
from app.auth.dependencies import CurrentUser, require_admin
from app.db.session import get_session
from app.models.organization import Organization
from app.models.user import User
from app.schemas.organization import OrganizationRead, OrganizationUpdate
from app.services.audit import record_audit

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
    admin: Annotated[User, Depends(require_admin)],
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
