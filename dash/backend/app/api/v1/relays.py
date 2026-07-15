"""VulnaRelay endpoints (Phase 16, opt-in).

Relay mode is **off by default** and must be enabled in settings. While disabled,
new enrollment and scope changes are refused, and — because disabling must fail
closed — the central egress blocks all relay traffic and heartbeats cannot mark a
tunnel up, so already-enrolled relays stop carrying scans. Scope is enforced at
the central egress; the relay never receives job-signing keys or scanner
credentials. Kill switch, enrollment (token + mTLS), heartbeat, and egress checks
live here.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.api.relay_auth import CurrentRelay
from app.auth.dependencies import require_permission
from app.auth.site_scope import get_accessible_site, optional_site_scope_clause
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import ActorType, ProbeStatus, RelayStatus
from app.models.network import Network, NetworkScout
from app.models.network_scope import NetworkScope
from app.models.organization import Organization
from app.models.probe import Probe
from app.models.relay import Relay
from app.models.user import User
from app.services import networks
from app.services import relay as relay_svc
from app.services.audit import record_audit
from app.services.ca import CertificateAuthorityError, certificate_fingerprint, get_ca
from app.services.enrollment import generate_token, hash_token
from app.services.scopes import ScopeValidationError

router = APIRouter(prefix="/relays", tags=["relays"])


class RelaySettings(BaseModel):
    enabled: bool


class EnrollmentCommandRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    site_id: uuid.UUID | None = None


class RegisterRequest(BaseModel):
    token: str
    csr_pem: str
    tunnel_public_key: str = Field(min_length=1, max_length=128)


class HeartbeatRequest(BaseModel):
    tunnel_up: bool
    health: dict[str, Any] = Field(default_factory=dict)


class ScopeRequest(BaseModel):
    approved_cidrs: list[str] = Field(default_factory=list)
    denied_cidrs: list[str] = Field(default_factory=list)
    allow_public_addresses: bool = False


class EgressCheckRequest(BaseModel):
    target: str


async def _org(session: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = await session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="organization not found")
    return org


async def _require_enabled(session: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = await _org(session, org_id)
    if not relay_svc.relay_enabled(org):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Relay mode is disabled. Enable it in Settings to use VulnaRelay.",
        )
    return org


def _serialize(r: Relay) -> dict[str, Any]:
    return {
        "id": str(r.id),
        "name": r.name,
        "status": r.status.value,
        "tunnel_up": r.tunnel_up,
        "tunnel_address": r.tunnel_address,
        "site_id": str(r.site_id) if r.site_id else None,
        "approved_cidrs": r.approved_cidrs_json,
        "denied_cidrs": r.denied_cidrs_json,
        "allow_public_addresses": bool(r.metadata_json.get("allow_public_addresses", False)),
        "certificate_fingerprint": r.certificate_fingerprint,
        "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
        "enrolled_at": r.enrolled_at.isoformat() if r.enrolled_at else None,
    }


@router.get("/settings", summary="Relay mode status")
async def get_relay_settings(
    current_user: Annotated[User, Depends(require_permission("relays.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    org = await _org(session, current_user.organization_id)
    return {"enabled": relay_svc.relay_enabled(org)}


@router.post("/settings", summary="Enable or disable relay mode (admin)")
async def update_relay_settings(
    payload: RelaySettings,
    admin: Annotated[User, Depends(require_permission("relays.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    """Relay mode is off by default. Turning it on is an explicit admin action."""
    org = await _org(session, admin.organization_id)
    enabled = relay_svc.set_relay_enabled(org, payload.enabled)
    record_audit(
        session, action="relay.mode_" + ("enabled" if enabled else "disabled"), actor=admin,
        organization_id=admin.organization_id, target_type="relay_mode",
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
    )
    await session.commit()
    return {"enabled": enabled}


@router.get("", summary="List relays")
async def list_relays(
    current_user: Annotated[User, Depends(require_permission("relays.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    rows = (
        await session.execute(
            select(Relay).where(
                Relay.organization_id == current_user.organization_id,
                optional_site_scope_clause(
                    current_user, Relay.site_id, permission_key="relays.read"
                ),
            )
        )
    ).scalars().all()
    return {"relays": [_serialize(r) for r in rows]}


@router.post("/enrollment-command", summary="Create a relay enrollment command (admin)")
async def enrollment_command(
    payload: EnrollmentCommandRequest,
    request: Request,
    admin: Annotated[User, Depends(require_permission("relays.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    await _require_enabled(session, admin.organization_id)
    if payload.site_id is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A relay must be assigned to a site.",
        )
    await get_accessible_site(
        session, admin, payload.site_id, permission_key="relays.manage"
    )
    generated = generate_token()
    relay = Relay(
        organization_id=admin.organization_id,
        site_id=payload.site_id,
        name=payload.name,
        status=RelayStatus.PENDING_ENROLLMENT,
        enrollment_token_hash=generated.token_hash,
        created_by=admin.id,
    )
    session.add(relay)
    record_audit(
        session, action="relay.enrollment_created", actor=admin,
        organization_id=admin.organization_id, target_type="relay",
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
    )
    await session.commit()
    effective_settings = settings
    if not settings.public_base_url:
        effective_settings = settings.model_copy(update={"public_base_url": str(request.base_url)})
    return {
        "relay_id": str(relay.id),
        "token": generated.secret,  # shown once
        "short_code": generated.short_code,
        "install": relay_svc.build_relay_install(
            effective_settings, generated.secret, payload.name
        ),
    }


@router.post("/register", summary="Register a relay with its enrollment token")
async def register_relay(
    payload: RegisterRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """Consume the single-use token and issue an mTLS control certificate. The
    response contains the control cert and CA only — never job-signing keys or
    scanner credentials."""
    invalid = HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    relay = (
        await session.execute(
            select(Relay).where(Relay.enrollment_token_hash == hash_token(payload.token))
        )
    ).scalar_one_or_none()
    if relay is None or relay.status != RelayStatus.PENDING_ENROLLMENT:
        raise invalid

    org = await _org(session, relay.organization_id)
    if not relay_svc.relay_enabled(org):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Relay mode is disabled."
        )

    ca = get_ca(settings)
    try:
        cert = ca.sign_csr(
            payload.csr_pem.encode("utf-8"),
            common_name=str(relay.id),
            validity_days=settings.client_cert_validity_days,
        )
    except CertificateAuthorityError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    now = datetime.now(UTC)
    relay.status = RelayStatus.ENROLLED
    relay.certificate_fingerprint = certificate_fingerprint(cert)
    relay.tunnel_public_key = payload.tunnel_public_key
    try:
        relay.tunnel_address = await relay_svc.allocate_tunnel_address(session, settings)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    relay.enrollment_token_hash = None  # single-use
    relay.enrolled_at = now
    record_audit(
        session, action="relay.registered", actor_type=ActorType.SYSTEM,
        organization_id=relay.organization_id, target_type="relay", target_id=relay.id,
    )
    await session.commit()
    return {
        "relay_id": str(relay.id),
        "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "ca_pem": ca.cert_pem.decode(),
        # No job-signing keys, no scanner credentials: a relay never runs scanners.
    }


@router.get("/config", summary="Fetch this relay's WireGuard configuration (mTLS)")
async def relay_config(
    relay: CurrentRelay,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    org = await _org(session, relay.organization_id)
    active = relay_svc.relay_enabled(org) and relay.status == RelayStatus.ENROLLED
    try:
        endpoint = relay_svc.relay_endpoint(settings)
        server_key = relay_svc.relay_server_public_key(settings)
        server_address = relay_svc.relay_server_address(settings)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    if relay.tunnel_address is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Relay has no allocated tunnel address; revoke and enroll it again.",
        )
    return {
        "active": active,
        "endpoint": endpoint,
        "server_public_key": server_key,
        "server_address": server_address,
        "tunnel_address": relay.tunnel_address,
        "approved_cidrs": relay.approved_cidrs_json,
        "denied_cidrs": relay.denied_cidrs_json,
        "refresh_seconds": 5,
    }


@router.get("/egress/config", summary="Internal relay-egress controller configuration")
async def relay_egress_config(
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    supplied_token: Annotated[str | None, Header(alias="X-Vulna-Relay-Egress-Token")] = None,
) -> dict[str, Any]:
    expected = settings.relay_egress_token
    if not expected or not supplied_token or not secrets.compare_digest(expected, supplied_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid egress token")
    rows = (
        await session.execute(
            select(Relay, Organization)
            .join(Organization, Organization.id == Relay.organization_id)
            .where(Relay.status == RelayStatus.ENROLLED)
        )
    ).all()
    peers = []
    now = datetime.now(UTC)
    for relay, org in rows:
        if (
            not relay_svc.relay_enabled(org)
            or not relay.tunnel_public_key
            or not relay.tunnel_address
        ):
            continue
        # Permit a brief first-configuration window after enrollment, then require
        # fresh heartbeats. A crashed/uninstalled relay therefore loses its central
        # peer and routes instead of leaving a forgotten tunnel indefinitely.
        freshness = relay.last_seen_at or relay.enrolled_at
        if freshness is not None and freshness.tzinfo is None:
            # SQLite drops timezone information; database timestamps are UTC.
            freshness = freshness.replace(tzinfo=UTC)
        if freshness is None or (
            now - freshness > timedelta(seconds=settings.relay_offline_after_seconds)
        ):
            continue
        peers.append(
            {
                "id": str(relay.id),
                "public_key": relay.tunnel_public_key,
                "tunnel_address": relay.tunnel_address,
                "approved_cidrs": relay.approved_cidrs_json,
                "denied_cidrs": relay.denied_cidrs_json,
            }
        )
    return {
        "listen_port": settings.relay_listen_port,
        "server_address": relay_svc.relay_server_address(settings),
        "peers": peers,
    }


@router.post("/heartbeat", summary="Relay heartbeat (mTLS)")
async def heartbeat(
    payload: HeartbeatRequest,
    relay: CurrentRelay,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    if relay.status == RelayStatus.KILLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Relay kill switch is engaged; tunnel must stay down.",
        )
    relay.last_seen_at = datetime.now(UTC)
    # Fail closed when relay mode is disabled: the tunnel may not be marked up, so
    # a relay left enrolled after an admin turns the feature off stops carrying scans.
    org = await _org(session, relay.organization_id)
    relay.tunnel_up = payload.tunnel_up and relay_svc.relay_enabled(org)
    await session.commit()
    return {"status": relay.status.value, "tunnel_up": relay.tunnel_up}


@router.post("/{relay_id}/scope", summary="Set a relay's approved egress scope (admin)")
async def set_scope(
    relay_id: uuid.UUID,
    payload: ScopeRequest,
    admin: Annotated[User, Depends(require_permission("relays.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    await _require_enabled(session, admin.organization_id)
    relay = await _get_relay(
        session, relay_id, admin, permission_key="relays.manage"
    )
    try:
        approved = relay_svc.validate_egress_cidrs(
            payload.approved_cidrs, allow_public=payload.allow_public_addresses
        )
        denied = relay_svc.validate_egress_cidrs(payload.denied_cidrs, allow_public=True)
    except ScopeValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    if any(":" in cidr for cidr in [*approved, *denied]):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="VulnaRelay currently supports IPv4 scopes only.",
        )
    other_relays = (
        await session.execute(
            select(Relay).where(
                Relay.organization_id == relay.organization_id,
                Relay.id != relay.id,
                Relay.status != RelayStatus.REVOKED,
            )
        )
    ).scalars()
    for other in other_relays:
        overlap = relay_svc.overlapping_cidrs(approved, other.approved_cidrs_json)
        if overlap is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Relay range {overlap[0]} overlaps {overlap[1]} on relay "
                    f"{other.name}; WireGuard cannot route an overlapping range "
                    "to two peers."
                ),
            )
    relay.approved_cidrs_json = approved
    relay.denied_cidrs_json = denied

    # Materialize relay ranges into the ordinary network policy model and bind the
    # central scanner. Jobs then use the existing signed-policy + dispatch path; the
    # WireGuard egress controller supplies reachability but never bypasses scope.
    if relay.site_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Relay is not assigned to a site; revoke and enroll it again.",
        )
    net = await networks.ensure_default_network(session, relay.organization_id, relay.site_id)
    managed_ids = [
        uuid.UUID(value)
        for value in relay.metadata_json.get("managed_scope_ids", [])
        if isinstance(value, str)
    ]
    if managed_ids:
        await session.execute(
            delete(NetworkScope).where(
                NetworkScope.id.in_(managed_ids), NetworkScope.network_id == net.id
            )
        )
    existing_cidrs = set(
        (
            await session.execute(
                select(NetworkScope.cidr).where(NetworkScope.network_id == net.id)
            )
        ).scalars()
    )
    created_scopes: list[NetworkScope] = []
    now = datetime.now(UTC)
    for cidr in approved:
        if cidr in existing_cidrs:
            continue
        scope = NetworkScope(
            organization_id=relay.organization_id,
            site_id=relay.site_id,
            network_id=net.id,
            name=f"VulnaRelay {relay.name}: {cidr}",
            cidr=cidr,
            enabled=True,
            allow_public_addresses=payload.allow_public_addresses,
            approved_by=admin.id,
            approved_at=now,
            notes=f"Managed by relay {relay.id}",
            policy_version=net.policy_version + 1,
        )
        session.add(scope)
        created_scopes.append(scope)
    await session.flush()
    relay.metadata_json = {
        **relay.metadata_json,
        "managed_scope_ids": [str(scope.id) for scope in created_scopes],
        "allow_public_addresses": payload.allow_public_addresses,
    }
    net.policy_version += 1

    scanner = (
        await session.execute(
            select(Probe)
            .where(
                Probe.organization_id == relay.organization_id,
                Probe.name == settings.relay_scanner_probe_name,
                Probe.status == ProbeStatus.ENROLLED,
            )
            .order_by(Probe.created_at.asc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if scanner is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"No enrolled central scanner named "
                f"'{settings.relay_scanner_probe_name}' is available."
            ),
        )
    bindings = list(
        (
            await session.execute(
            select(NetworkScout).where(
                NetworkScout.network_id == net.id,
            )
        )
        ).scalars()
    )
    binding = next((item for item in bindings if item.probe_id == scanner.id), None)
    # Relay-backed ranges must always dispatch through the central scanner. A
    # pre-existing primary Scout would otherwise win the normal network routing
    # path and attempt the scan directly, bypassing the relay tunnel.
    for item in bindings:
        item.is_primary = item.probe_id == scanner.id
    if binding is None:
        session.add(NetworkScout(network_id=net.id, probe_id=scanner.id, is_primary=True))
    record_audit(
        session, action="relay.scope_set", actor=admin,
        organization_id=admin.organization_id, target_type="relay", target_id=relay.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
        metadata={"approved": approved, "denied": denied},
    )
    await session.commit()
    return {"approved_cidrs": approved, "denied_cidrs": denied}


@router.post("/{relay_id}/egress-check", summary="Central egress decision for a target")
async def egress_check(
    relay_id: uuid.UUID,
    payload: EgressCheckRequest,
    current_user: Annotated[User, Depends(require_permission("relays.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    relay = await _get_relay(
        session, relay_id, current_user, permission_key="relays.read"
    )
    # Fail closed when relay mode is disabled: the central egress is the security
    # boundary, so a disabled feature blocks all relay traffic regardless of the
    # relay's stored scope/tunnel state.
    org = await _org(session, current_user.organization_id)
    if not relay_svc.relay_enabled(org):
        return {
            "allowed": False,
            "reason": "Relay mode is disabled; the central egress blocks all relay traffic.",
        }
    decision = relay_svc.egress_decision(
        payload.target, relay.approved_cidrs_json, relay.denied_cidrs_json,
        status=relay.status, tunnel_up=relay.tunnel_up,
    )
    return {"allowed": decision.allowed, "reason": decision.reason}


@router.post("/{relay_id}/kill", summary="Engage the relay kill switch (admin)")
async def kill(
    relay_id: uuid.UUID,
    admin: Annotated[User, Depends(require_permission("relays.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    """Tear the tunnel and block all scanning through this relay immediately."""
    relay = await _get_relay(
        session, relay_id, admin, permission_key="relays.manage"
    )
    relay.status = RelayStatus.KILLED
    relay.tunnel_up = False
    relay.killed_at = datetime.now(UTC)
    record_audit(
        session, action="relay.killed", actor=admin,
        organization_id=admin.organization_id, target_type="relay", target_id=relay.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
    )
    await session.commit()
    return _serialize(relay)


@router.post("/{relay_id}/resume", summary="Clear the kill switch (admin)")
async def resume(
    relay_id: uuid.UUID,
    admin: Annotated[User, Depends(require_permission("relays.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    relay = await _get_relay(
        session, relay_id, admin, permission_key="relays.manage"
    )
    if relay.status == RelayStatus.KILLED:
        relay.status = RelayStatus.ENROLLED
        relay.killed_at = None
    record_audit(
        session, action="relay.resumed", actor=admin,
        organization_id=admin.organization_id, target_type="relay", target_id=relay.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
    )
    await session.commit()
    return _serialize(relay)


@router.delete("/{relay_id}", summary="Revoke a relay (admin)")
async def revoke(
    relay_id: uuid.UUID,
    admin: Annotated[User, Depends(require_permission("relays.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> dict[str, Any]:
    relay = await _get_relay(
        session, relay_id, admin, permission_key="relays.manage"
    )
    relay.status = RelayStatus.REVOKED
    relay.tunnel_up = False
    managed_ids = [
        uuid.UUID(value)
        for value in relay.metadata_json.get("managed_scope_ids", [])
        if isinstance(value, str)
    ]
    if managed_ids:
        scopes = list(
            (
                await session.execute(
                    select(NetworkScope).where(NetworkScope.id.in_(managed_ids))
                )
            ).scalars()
        )
        network_ids = {scope.network_id for scope in scopes}
        await session.execute(delete(NetworkScope).where(NetworkScope.id.in_(managed_ids)))
        for network_id in network_ids:
            network = await session.get(Network, network_id)
            if network is not None:
                network.policy_version += 1
    relay.approved_cidrs_json = []
    relay.denied_cidrs_json = []
    relay.metadata_json = {
        **relay.metadata_json,
        "managed_scope_ids": [],
        "allow_public_addresses": False,
    }
    record_audit(
        session, action="relay.revoked", actor=admin,
        organization_id=admin.organization_id, target_type="relay", target_id=relay.id,
        source_ip=context.source_ip, user_agent=context.user_agent, request_id=context.request_id,
    )
    await session.commit()
    return {"revoked": True}


async def _get_relay(
    session: AsyncSession,
    relay_id: uuid.UUID,
    user: User,
    *,
    permission_key: str,
) -> Relay:
    relay = await session.scalar(
        select(Relay).where(
            Relay.id == relay_id,
            Relay.organization_id == user.organization_id,
            optional_site_scope_clause(user, Relay.site_id, permission_key=permission_key),
        )
    )
    if relay is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="relay not found")
    return relay
