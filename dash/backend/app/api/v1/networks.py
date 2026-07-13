"""Network management endpoints.

A *network* is a named group of address ranges under a site, bound to one or more
VulnaScouts. Ranges are ``network_scopes`` rows carrying the network's id; scout
bindings are ``network_scouts`` rows. Mutations require the Administrator role,
CIDRs are normalized/validated and checked for overlap within the site, and
range/binding changes bump the network's ``policy_version`` so bound scouts
detect stale local policy. Job dispatch targets a network and routes to one of
its enrolled scouts (see the workflow engine).
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import CurrentUser, require_admin
from app.auth.site_scope import get_accessible_site, site_scope_clause
from app.db.session import get_session
from app.models.network import Network, NetworkScout
from app.models.network_scope import NetworkScope
from app.models.probe import Probe
from app.models.user import User
from app.schemas.network import (
    NetworkCreate,
    NetworkRangeCreate,
    NetworkRead,
    NetworkScoutBind,
    NetworkUpdate,
)
from app.services.audit import record_audit
from app.services.scopes import ScopeValidationError, find_overlaps, validate_cidr

router = APIRouter(prefix="/networks", tags=["networks"])


async def _owned_network(
    session: AsyncSession, network_id: uuid.UUID, current_user: User
) -> Network:
    net = await session.scalar(
        select(Network).where(
            Network.id == network_id,
            Network.organization_id == current_user.organization_id,
            site_scope_clause(current_user, Network.site_id),
        )
    )
    if net is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Network not found")
    return net


async def _require_owned_probe(
    session: AsyncSession, probe_id: uuid.UUID, org_id: uuid.UUID
) -> Probe:
    probe = await session.get(Probe, probe_id)
    if probe is None or probe.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scout not found")
    return probe


def _validate_or_400(cidr: str, *, allow_public: bool) -> str:
    try:
        return validate_cidr(cidr, allow_public=allow_public)
    except ScopeValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


async def _site_sibling_cidrs(
    session: AsyncSession, site_id: uuid.UUID, exclude_id: uuid.UUID | None
) -> list[str]:
    stmt = select(NetworkScope.cidr).where(NetworkScope.site_id == site_id)
    if exclude_id is not None:
        stmt = stmt.where(NetworkScope.id != exclude_id)
    return [row[0] for row in (await session.execute(stmt)).all()]


async def _serialize(session: AsyncSession, net: Network) -> dict[str, Any]:
    ranges = (
        await session.execute(
            select(NetworkScope)
            .where(NetworkScope.network_id == net.id)
            .order_by(NetworkScope.cidr)
        )
    ).scalars().all()
    scouts = (
        await session.execute(
            select(NetworkScout, Probe.name)
            .join(Probe, Probe.id == NetworkScout.probe_id)
            .where(NetworkScout.network_id == net.id)
        )
    ).all()
    return {
        "id": net.id,
        "organization_id": net.organization_id,
        "site_id": net.site_id,
        "name": net.name,
        "description": net.description,
        "enabled": net.enabled,
        "policy_version": net.policy_version,
        "ranges": [
            {
                "id": r.id,
                "cidr": r.cidr,
                "enabled": r.enabled,
                "allow_public_addresses": r.allow_public_addresses,
                "maximum_hosts": r.maximum_hosts,
                "maximum_packets_per_second": r.maximum_packets_per_second,
                "maximum_concurrency": r.maximum_concurrency,
            }
            for r in ranges
        ],
        "scouts": [
            {"probe_id": ns.probe_id, "probe_name": name, "is_primary": ns.is_primary}
            for ns, name in scouts
        ],
        "created_at": net.created_at,
        "updated_at": net.updated_at,
    }


async def _add_range(
    session: AsyncSession, net: Network, payload: NetworkRangeCreate
) -> NetworkScope:
    canonical = _validate_or_400(payload.cidr, allow_public=payload.allow_public_addresses)
    overlaps = find_overlaps(canonical, await _site_sibling_cidrs(session, net.site_id, None))
    if overlaps:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"CIDR {canonical} overlaps existing range(s): {', '.join(overlaps)}",
        )
    scope = NetworkScope(
        organization_id=net.organization_id,
        site_id=net.site_id,
        network_id=net.id,
        name=net.name,
        cidr=canonical,
        enabled=True,
        allow_public_addresses=payload.allow_public_addresses,
        maximum_hosts=payload.maximum_hosts,
        maximum_packets_per_second=payload.maximum_packets_per_second,
        maximum_concurrency=payload.maximum_concurrency,
        policy_version=1,
    )
    session.add(scope)
    return scope


async def _bind_scout(session: AsyncSession, net: Network, bind: NetworkScoutBind) -> None:
    probe = await _require_owned_probe(session, bind.probe_id, net.organization_id)
    existing = (
        await session.execute(
            select(NetworkScout).where(
                NetworkScout.network_id == net.id, NetworkScout.probe_id == probe.id
            )
        )
    ).scalar_one_or_none()
    if bind.is_primary:
        # Only one primary scout per network; demote any current primary.
        for other in (
            await session.execute(
                select(NetworkScout).where(
                    NetworkScout.network_id == net.id, NetworkScout.is_primary.is_(True)
                )
            )
        ).scalars():
            other.is_primary = False
    if existing is not None:
        existing.is_primary = bind.is_primary
    else:
        session.add(NetworkScout(network_id=net.id, probe_id=probe.id, is_primary=bind.is_primary))


@router.post("", response_model=NetworkRead, status_code=status.HTTP_201_CREATED,
             summary="Create a network")
async def create_network(
    payload: NetworkCreate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> NetworkRead:
    org_id = admin.organization_id
    await get_accessible_site(session, admin, payload.site_id)
    net = Network(
        organization_id=org_id,
        site_id=payload.site_id,
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        policy_version=1,
    )
    session.add(net)
    await session.flush()
    for r in payload.ranges:
        await _add_range(session, net, r)
    for b in payload.scouts:
        await _bind_scout(session, net, b)
    record_audit(
        session, action="network.created", actor=admin, organization_id=org_id,
        target_type="network", target_id=net.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
        metadata={"site_id": str(payload.site_id), "name": net.name},
    )
    await session.flush()
    return NetworkRead.model_validate(await _serialize(session, net))


@router.get("", response_model=list[NetworkRead], summary="List networks")
async def list_networks(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[NetworkRead]:
    nets = (
        await session.execute(
            select(Network)
            .where(
                Network.organization_id == current_user.organization_id,
                site_scope_clause(current_user, Network.site_id),
            )
            .order_by(Network.name)
        )
    ).scalars().all()
    return [NetworkRead.model_validate(await _serialize(session, n)) for n in nets]


@router.get("/{network_id}", response_model=NetworkRead, summary="Get a network")
async def get_network(
    network_id: uuid.UUID,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> NetworkRead:
    net = await _owned_network(session, network_id, current_user)
    return NetworkRead.model_validate(await _serialize(session, net))


@router.patch("/{network_id}", response_model=NetworkRead, summary="Update a network")
async def update_network(
    network_id: uuid.UUID,
    payload: NetworkUpdate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> NetworkRead:
    net = await _owned_network(session, network_id, admin)
    if payload.name is not None:
        net.name = payload.name
    if payload.description is not None:
        net.description = payload.description
    if payload.enabled is not None:
        net.enabled = payload.enabled
    net.policy_version += 1
    record_audit(
        session, action="network.updated", actor=admin, organization_id=admin.organization_id,
        target_type="network", target_id=net.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
    )
    return NetworkRead.model_validate(await _serialize(session, net))


@router.delete("/{network_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a network")
async def delete_network(
    network_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> None:
    net = await _owned_network(session, network_id, admin)
    record_audit(
        session, action="network.deleted", actor=admin, organization_id=admin.organization_id,
        target_type="network", target_id=net.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
    )
    await session.delete(net)


@router.post("/{network_id}/ranges", response_model=NetworkRead, summary="Add a range")
async def add_range(
    network_id: uuid.UUID,
    payload: NetworkRangeCreate,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> NetworkRead:
    net = await _owned_network(session, network_id, admin)
    scope = await _add_range(session, net, payload)
    net.policy_version += 1
    record_audit(
        session, action="network.range_added", actor=admin, organization_id=admin.organization_id,
        target_type="network", target_id=net.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
        metadata={"cidr": scope.cidr},
    )
    await session.flush()
    return NetworkRead.model_validate(await _serialize(session, net))


@router.delete("/{network_id}/ranges/{range_id}", response_model=NetworkRead,
               summary="Remove a range")
async def remove_range(
    network_id: uuid.UUID,
    range_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> NetworkRead:
    net = await _owned_network(session, network_id, admin)
    scope = await session.get(NetworkScope, range_id)
    if scope is None or scope.network_id != net.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Range not found")
    await session.delete(scope)
    net.policy_version += 1
    record_audit(
        session, action="network.range_removed", actor=admin,
        organization_id=admin.organization_id, target_type="network", target_id=net.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
        metadata={"cidr": scope.cidr},
    )
    await session.flush()
    return NetworkRead.model_validate(await _serialize(session, net))


@router.post("/{network_id}/scouts", response_model=NetworkRead, summary="Bind a scout")
async def bind_scout(
    network_id: uuid.UUID,
    payload: NetworkScoutBind,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> NetworkRead:
    net = await _owned_network(session, network_id, admin)
    await _bind_scout(session, net, payload)
    net.policy_version += 1
    record_audit(
        session, action="network.scout_bound", actor=admin, organization_id=admin.organization_id,
        target_type="network", target_id=net.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
        metadata={"probe_id": str(payload.probe_id), "is_primary": payload.is_primary},
    )
    await session.flush()
    return NetworkRead.model_validate(await _serialize(session, net))


@router.delete("/{network_id}/scouts/{probe_id}", response_model=NetworkRead,
               summary="Unbind a scout")
async def unbind_scout(
    network_id: uuid.UUID,
    probe_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> NetworkRead:
    net = await _owned_network(session, network_id, admin)
    binding = (
        await session.execute(
            select(NetworkScout).where(
                NetworkScout.network_id == net.id, NetworkScout.probe_id == probe_id
            )
        )
    ).scalar_one_or_none()
    if binding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scout is not bound")
    await session.delete(binding)
    net.policy_version += 1
    record_audit(
        session, action="network.scout_unbound", actor=admin,
        organization_id=admin.organization_id, target_type="network", target_id=net.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
        metadata={"probe_id": str(probe_id)},
    )
    await session.flush()
    return NetworkRead.model_validate(await _serialize(session, net))
