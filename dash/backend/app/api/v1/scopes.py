"""Network-scope management endpoints (retained as a convenience).

The standalone scope model is retired: a scope is now a range in the site's
*default network*, and policy is sourced only from networks (see
``services/policy`` and ``services/networks``). These endpoints remain as a
simple "approve a range for a site" convenience — creating a scope makes/uses the
site's default network and binds the site's probes — so existing flows (and the
onboarding wizard) keep working. New setups should prefer ``/networks`` directly.

CIDRs are normalized and validated (no default routes, public ranges denied by
default), overlaps within a site are rejected, and mutations require the
Administrator role and are audited.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_admin
from app.db.session import get_session
from app.models.network_scope import NetworkScope
from app.models.site import Site
from app.models.user import User
from app.schemas.common import Page
from app.schemas.scope import NetworkScopeCreate, NetworkScopeRead, NetworkScopeUpdate
from app.services import networks
from app.services.audit import record_audit
from app.services.scopes import ScopeValidationError, find_overlaps, validate_cidr

router = APIRouter(prefix="/scopes", tags=["scopes"])


async def _get_owned_scope(
    session: AsyncSession, scope_id: uuid.UUID, org_id: uuid.UUID
) -> NetworkScope:
    scope = await session.get(NetworkScope, scope_id)
    if scope is None or scope.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope not found")
    return scope


async def _require_owned_site(
    session: AsyncSession, site_id: uuid.UUID, org_id: uuid.UUID
) -> Site:
    site = await session.get(Site, site_id)
    if site is None or site.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")
    return site


async def _sibling_cidrs(
    session: AsyncSession, site_id: uuid.UUID, exclude_id: uuid.UUID | None
) -> list[str]:
    """Return the CIDRs of other scopes in the same site (for overlap checks)."""
    stmt = select(NetworkScope.cidr).where(NetworkScope.site_id == site_id)
    if exclude_id is not None:
        stmt = stmt.where(NetworkScope.id != exclude_id)
    result = await session.execute(stmt)
    return [row[0] for row in result.all()]


def _validate_or_400(cidr: str, *, allow_public: bool) -> str:
    try:
        return validate_cidr(cidr, allow_public=allow_public)
    except ScopeValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


@router.get("", response_model=Page[NetworkScopeRead], summary="List network scopes")
async def list_scopes(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    site_id: Annotated[uuid.UUID | None, Query(description="Filter by site")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[NetworkScopeRead]:
    """List network scopes in the caller's organization (any authenticated role)."""
    org_id = current_user.organization_id
    filters = [NetworkScope.organization_id == org_id]
    if site_id is not None:
        filters.append(NetworkScope.site_id == site_id)

    total = await session.scalar(
        select(func.count()).select_from(NetworkScope).where(*filters)
    )
    result = await session.execute(
        select(NetworkScope)
        .where(*filters)
        .order_by(NetworkScope.created_at.asc())
        .limit(limit)
        .offset(offset)
    )
    scopes = result.scalars().all()
    return Page[NetworkScopeRead](
        items=[NetworkScopeRead.model_validate(s) for s in scopes],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{scope_id}", response_model=NetworkScopeRead, summary="Get a network scope")
async def get_scope(
    scope_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> NetworkScopeRead:
    scope = await _get_owned_scope(session, scope_id, current_user.organization_id)
    return NetworkScopeRead.model_validate(scope)


@router.post(
    "",
    response_model=NetworkScopeRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a network scope",
)
async def create_scope(
    payload: NetworkScopeCreate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> NetworkScopeRead:
    """Create an approved network scope (Administrator only)."""
    org_id = admin.organization_id
    await _require_owned_site(session, payload.site_id, org_id)

    canonical = _validate_or_400(payload.cidr, allow_public=payload.allow_public_addresses)

    overlaps = find_overlaps(canonical, await _sibling_cidrs(session, payload.site_id, None))
    if overlaps:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"CIDR {canonical} overlaps existing scope(s): {', '.join(overlaps)}",
        )

    # The standalone scope model is retired: a scope is a range in the site's
    # default network, and every site probe is bound to that network — preserving
    # the old site-wide behavior while policy is sourced only from networks.
    default_network = await networks.ensure_default_network(session, org_id, payload.site_id)
    scope = NetworkScope(
        organization_id=org_id,
        site_id=payload.site_id,
        network_id=default_network.id,
        name=payload.name,
        cidr=canonical,
        enabled=payload.enabled,
        allow_public_addresses=payload.allow_public_addresses,
        expires_at=payload.expires_at,
        maximum_hosts=payload.maximum_hosts,
        maximum_packets_per_second=payload.maximum_packets_per_second,
        maximum_concurrency=payload.maximum_concurrency,
        notes=payload.notes,
        policy_version=1,
    )
    session.add(scope)
    await networks.bind_all_site_probes(session, default_network, payload.site_id)
    await session.flush()

    record_audit(
        session,
        action="scope.created",
        actor=admin,
        organization_id=org_id,
        target_type="network_scope",
        target_id=scope.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "site_id": str(payload.site_id),
            "cidr": canonical,
            "allow_public_addresses": scope.allow_public_addresses,
        },
    )
    return NetworkScopeRead.model_validate(scope)


@router.patch("/{scope_id}", response_model=NetworkScopeRead, summary="Update a network scope")
async def update_scope(
    scope_id: uuid.UUID,
    payload: NetworkScopeUpdate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> NetworkScopeRead:
    """Update a network scope (Administrator only)."""
    org_id = admin.organization_id
    scope = await _get_owned_scope(session, scope_id, org_id)
    changes = payload.model_dump(exclude_unset=True)

    # Re-validate the CIDR whenever the range or the public-address flag changes.
    new_allow_public = changes.get("allow_public_addresses", scope.allow_public_addresses)
    if "cidr" in changes or "allow_public_addresses" in changes:
        target_cidr = changes.get("cidr", scope.cidr)
        canonical = _validate_or_400(target_cidr, allow_public=new_allow_public)
        overlaps = find_overlaps(
            canonical, await _sibling_cidrs(session, scope.site_id, exclude_id=scope.id)
        )
        if overlaps:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"CIDR {canonical} overlaps existing scope(s): {', '.join(overlaps)}",
            )
        changes["cidr"] = canonical

    for field, value in changes.items():
        setattr(scope, field, value)
    # Any scope change bumps the policy version so probes detect stale policy.
    scope.policy_version += 1
    await session.flush()

    record_audit(
        session,
        action="scope.updated",
        actor=admin,
        organization_id=org_id,
        target_type="network_scope",
        target_id=scope.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "changed_fields": sorted(changes.keys()),
            "policy_version": scope.policy_version,
        },
    )
    return NetworkScopeRead.model_validate(scope)


@router.post(
    "/{scope_id}/approve",
    response_model=NetworkScopeRead,
    summary="Approve a network scope",
)
async def approve_scope(
    scope_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> NetworkScopeRead:
    """Record administrator approval of a scope (Administrator only)."""
    scope = await _get_owned_scope(session, scope_id, admin.organization_id)
    scope.approved_by = admin.id
    scope.approved_at = datetime.now(UTC)
    scope.policy_version += 1
    await session.flush()

    record_audit(
        session,
        action="scope.approved",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="network_scope",
        target_id=scope.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"cidr": scope.cidr, "policy_version": scope.policy_version},
    )
    return NetworkScopeRead.model_validate(scope)


@router.delete(
    "/{scope_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Delete a network scope",
)
async def delete_scope(
    scope_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    """Delete a network scope (Administrator only)."""
    scope = await _get_owned_scope(session, scope_id, admin.organization_id)
    record_audit(
        session,
        action="scope.deleted",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="network_scope",
        target_id=scope.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"cidr": scope.cidr},
    )
    await session.delete(scope)
