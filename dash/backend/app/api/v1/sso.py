"""Organization SSO administration plus public OIDC/SAML browser flows."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any
from urllib.parse import parse_qs

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.auth.dependencies import StepUpIdentity, require_permission
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enums import ActorType, IdentityProviderProtocol, SsoPolicyMode, UserRole
from app.models.organization import Organization
from app.models.site import Site
from app.models.sso import (
    ExternalIdentityLink,
    IdentityGroupMapping,
    IdentityProvider,
    IdentityProviderTest,
)
from app.models.user import User
from app.schemas.sso import (
    BreakGlassUpdate,
    GroupMappingRead,
    GroupMappingWrite,
    IdentityProviderCreate,
    IdentityProviderEnable,
    IdentityProviderRead,
    IdentityProviderUpdate,
    PublicIdentityProvider,
    SamlMetadataImport,
    SsoPolicyRead,
    SsoPolicyUpdate,
    SsoStartRequest,
    SsoStartResponse,
    SsoTestRecordRead,
)
from app.services import authorization, mfa, sso
from app.services.audit import record_audit
from app.services.secret_crypto import SecretPurpose, encrypt_secret
from app.services.sessions import REFRESH_COOKIE_NAME, create_session, revoke_user_sessions

router = APIRouter(tags=["identity"])


def _error(detail: str, code: int = status.HTTP_400_BAD_REQUEST) -> HTTPException:
    return HTTPException(status_code=code, detail=detail)


async def _ensure_identity_manager(session: AsyncSession, actor: User) -> None:
    if not await authorization.has_permission(session, actor, "identity.manage"):
        raise _error("You do not have permission to manage identity providers", 403)


async def _owned_provider(
    session: AsyncSession, provider_id: uuid.UUID, organization_id: uuid.UUID
) -> IdentityProvider:
    provider = await session.scalar(
        select(IdentityProvider).where(
            IdentityProvider.id == provider_id,
            IdentityProvider.organization_id == organization_id,
        )
    )
    if provider is None:
        raise _error("Identity provider not found", status.HTTP_404_NOT_FOUND)
    return provider


def _read_provider(provider: IdentityProvider) -> IdentityProviderRead:
    return IdentityProviderRead(
        id=provider.id,
        organization_id=provider.organization_id,
        name=provider.name,
        slug=provider.slug,
        protocol=provider.protocol,
        enabled=provider.enabled,
        jit_provisioning=provider.jit_provisioning,
        default_role=provider.default_role,
        preset=provider.preset,
        allow_private_network=provider.allow_private_network,
        issuer=provider.issuer,
        discovery_url=provider.discovery_url,
        client_id=provider.client_id,
        scopes=list(provider.scopes_json or []),
        idp_entity_id=provider.idp_entity_id,
        idp_sso_url=provider.idp_sso_url,
        idp_slo_url=provider.idp_slo_url,
        want_assertions_encrypted=provider.want_assertions_encrypted,
        has_client_secret=provider.encrypted_client_secret is not None,
        has_idp_certificate=provider.encrypted_idp_certificate is not None,
        has_next_idp_certificate=provider.encrypted_next_idp_certificate is not None,
        has_sp_certificate=provider.encrypted_sp_certificate is not None,
        validated_at=provider.validated_at,
        last_test_succeeded_at=provider.last_test_succeeded_at,
        created_at=provider.created_at,
        updated_at=provider.updated_at,
    )


def _set_refresh_cookie(
    response: Response, settings: Settings, secret: str, expires_at: datetime
) -> None:
    expiry = sso.aware(expires_at)
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        secret,
        max_age=max(0, int((expiry - datetime.now(UTC)).total_seconds())),
        expires=expiry,
        path="/api/v1/auth",
        secure=settings.env == "production",
        httponly=True,
        samesite="lax",
    )


def _record(
    session: AsyncSession,
    context: RequestContext,
    actor: User | None,
    action: str,
    provider: IdentityProvider,
    **metadata: object,
) -> None:
    record_audit(
        session,
        action=action,
        actor=actor,
        actor_type=ActorType.SYSTEM if actor is None else ActorType.USER,
        organization_id=provider.organization_id,
        target_type="identity_provider",
        target_id=provider.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata=dict(metadata),
    )


@router.get(
    "/identity/providers",
    response_model=list[IdentityProviderRead],
    summary="List identity providers",
)
async def list_providers(
    admin: Annotated[User, Depends(require_permission("identity.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[IdentityProviderRead]:
    rows = list(
        (
            await session.execute(
                select(IdentityProvider)
                .where(IdentityProvider.organization_id == admin.organization_id)
                .order_by(IdentityProvider.name.asc())
            )
        ).scalars()
    )
    return [_read_provider(row) for row in rows]


@router.post(
    "/identity/providers",
    response_model=IdentityProviderRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create an identity provider",
)
async def create_provider(
    payload: IdentityProviderCreate,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> IdentityProviderRead:
    actor = identity.user
    await _ensure_identity_manager(session, actor)
    scopes = payload.scopes or sso.OIDC_PRESET_SCOPES.get(
        payload.preset, sso.OIDC_PRESET_SCOPES["generic"]
    )
    provider = IdentityProvider(
        organization_id=actor.organization_id,
        name=payload.name.strip(),
        slug=payload.slug,
        protocol=payload.protocol,
        enabled=False,
        jit_provisioning=payload.jit_provisioning,
        default_role=payload.default_role,
        preset=payload.preset,
        allow_private_network=payload.allow_private_network,
        issuer=str(payload.issuer) if payload.issuer else None,
        discovery_url=str(payload.discovery_url) if payload.discovery_url else None,
        client_id=payload.client_id,
        scopes_json=scopes if payload.protocol == IdentityProviderProtocol.OIDC else [],
        want_assertions_encrypted=payload.want_assertions_encrypted,
    )
    if payload.client_secret:
        provider.encrypted_client_secret = encrypt_secret(
            settings.require_secret_key(),
            SecretPurpose.OIDC_CLIENT_SECRET,
            payload.client_secret,
        )
    session.add(provider)
    await session.flush()
    _record(session, context, actor, "identity.provider_created", provider)
    return _read_provider(provider)


@router.patch(
    "/identity/providers/{provider_id}",
    response_model=IdentityProviderRead,
    summary="Update an identity provider",
)
async def update_provider(
    provider_id: uuid.UUID,
    payload: IdentityProviderUpdate,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> IdentityProviderRead:
    actor = identity.user
    await _ensure_identity_manager(session, actor)
    provider = await _owned_provider(session, provider_id, actor.organization_id)
    values = payload.model_dump(exclude_unset=True)
    oidc_fields = {"issuer", "discovery_url", "client_id", "client_secret", "scopes"}
    if provider.protocol == IdentityProviderProtocol.SAML and set(values) & oidc_fields:
        raise _error("SAML providers are configured through metadata import")
    if provider.protocol == IdentityProviderProtocol.OIDC and "next_idp_certificate" in values:
        raise _error("OIDC providers do not use SAML signing certificates")
    sensitive_change = bool(
        set(values)
        & {
            "issuer",
            "discovery_url",
            "client_id",
            "client_secret",
            "next_idp_certificate",
            "want_assertions_encrypted",
        }
    )
    for field in (
        "name",
        "preset",
        "jit_provisioning",
        "default_role",
        "allow_private_network",
        "client_id",
        "want_assertions_encrypted",
    ):
        if field in values:
            setattr(provider, field, values[field])
    if "issuer" in values:
        provider.issuer = str(payload.issuer) if payload.issuer else None
    if "discovery_url" in values:
        provider.discovery_url = str(payload.discovery_url) if payload.discovery_url else None
    if "scopes" in values:
        provider.scopes_json = payload.scopes or []
    if payload.client_secret is not None:
        provider.encrypted_client_secret = encrypt_secret(
            settings.require_secret_key(),
            SecretPurpose.OIDC_CLIENT_SECRET,
            payload.client_secret,
        )
    if payload.next_idp_certificate is not None:
        try:
            next_certificate = sso.normalize_x509_certificate(payload.next_idp_certificate)
        except sso.SsoError as exc:
            raise _error(str(exc)) from exc
        provider.encrypted_next_idp_certificate = encrypt_secret(
            settings.require_secret_key(),
            SecretPurpose.SAML_IDP_CERTIFICATE,
            next_certificate,
        )
    if sensitive_change:
        provider.enabled = False
        provider.last_test_succeeded_at = None
        provider.last_tested_by_user_id = None
        if set(values) & {"issuer", "discovery_url", "client_id"}:
            provider.validated_at = None
            provider.oidc_metadata_json = {}
    _record(
        session,
        context,
        actor,
        "identity.provider_updated",
        provider,
        changed_fields=sorted(values),
    )
    return _read_provider(provider)


@router.delete(
    "/identity/providers/{provider_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an unused identity provider",
)
async def delete_provider(
    provider_id: uuid.UUID,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> Response:
    actor = identity.user
    await _ensure_identity_manager(session, actor)
    provider = await _owned_provider(session, provider_id, actor.organization_id)
    policy = await sso.get_policy(session, actor.organization_id)
    if policy.identity_provider_id == provider.id:
        raise _error("Remove this provider from the SSO policy before deleting it", 409)
    _record(session, context, actor, "identity.provider_deleted", provider)
    await session.delete(provider)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/identity/providers/{provider_id}/validate",
    response_model=IdentityProviderRead,
    summary="Validate OIDC discovery",
)
async def validate_provider(
    provider_id: uuid.UUID,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> IdentityProviderRead:
    actor = identity.user
    await _ensure_identity_manager(session, actor)
    provider = await _owned_provider(session, provider_id, actor.organization_id)
    try:
        await sso.validate_oidc_discovery(provider)
    except (sso.SsoError, httpx.HTTPError) as exc:
        raise _error("Identity-provider validation failed") from exc
    session.add(
        IdentityProviderTest(
            organization_id=provider.organization_id,
            identity_provider_id=provider.id,
            tested_by_user_id=actor.id,
            test_type="configuration",
            succeeded=True,
            detail="OIDC discovery metadata validated",
        )
    )
    _record(session, context, actor, "identity.provider_validated", provider)
    return _read_provider(provider)


@router.post(
    "/identity/providers/{provider_id}/saml-metadata",
    response_model=IdentityProviderRead,
    summary="Import and validate SAML IdP metadata",
)
async def import_provider_metadata(
    provider_id: uuid.UUID,
    payload: SamlMetadataImport,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> IdentityProviderRead:
    actor = identity.user
    await _ensure_identity_manager(session, actor)
    provider = await _owned_provider(session, provider_id, actor.organization_id)
    try:
        sso.import_saml_metadata(
            settings, provider, payload.metadata_xml, entity_id=payload.entity_id
        )
    except sso.SsoError as exc:
        raise _error(str(exc)) from exc
    provider.enabled = False
    provider.last_test_succeeded_at = None
    provider.last_tested_by_user_id = None
    session.add(
        IdentityProviderTest(
            organization_id=provider.organization_id,
            identity_provider_id=provider.id,
            tested_by_user_id=actor.id,
            test_type="configuration",
            succeeded=True,
            detail="SAML metadata and SP configuration validated",
        )
    )
    _record(session, context, actor, "identity.saml_metadata_imported", provider)
    return _read_provider(provider)


@router.put(
    "/identity/providers/{provider_id}/enabled",
    response_model=IdentityProviderRead,
    summary="Enable or disable a tested provider",
)
async def set_provider_enabled(
    provider_id: uuid.UUID,
    payload: IdentityProviderEnable,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> IdentityProviderRead:
    actor = identity.user
    await _ensure_identity_manager(session, actor)
    provider = await _owned_provider(session, provider_id, actor.organization_id)
    if payload.enabled and (
        provider.validated_at is None or provider.last_test_succeeded_at is None
    ):
        raise _error("Validate the provider and complete a successful test login first", 409)
    provider.enabled = payload.enabled
    if not payload.enabled:
        policy = await sso.get_policy(session, actor.organization_id)
        if policy.mode == SsoPolicyMode.ENFORCED and policy.identity_provider_id == provider.id:
            raise _error("Disable SSO enforcement before disabling its provider", 409)
    _record(
        session,
        context,
        actor,
        "identity.provider_enabled" if payload.enabled else "identity.provider_disabled",
        provider,
    )
    return _read_provider(provider)


@router.get(
    "/identity/providers/{provider_id}/tests",
    response_model=list[SsoTestRecordRead],
    summary="List identity-provider test history",
)
async def list_provider_tests(
    provider_id: uuid.UUID,
    admin: Annotated[User, Depends(require_permission("identity.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[SsoTestRecordRead]:
    provider = await _owned_provider(session, provider_id, admin.organization_id)
    rows = list(
        (
            await session.execute(
                select(IdentityProviderTest)
                .where(
                    IdentityProviderTest.identity_provider_id == provider.id,
                    IdentityProviderTest.organization_id == admin.organization_id,
                )
                .order_by(IdentityProviderTest.created_at.desc())
            )
        ).scalars()
    )
    return [
        SsoTestRecordRead(
            id=row.id,
            test_type=row.test_type,
            succeeded=row.succeeded,
            detail=row.detail,
            tested_by_user_id=row.tested_by_user_id,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.get(
    "/identity/providers/{provider_id}/group-mappings",
    response_model=list[GroupMappingRead],
    summary="List provider group mappings",
)
async def list_group_mappings(
    provider_id: uuid.UUID,
    admin: Annotated[User, Depends(require_permission("identity.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[GroupMappingRead]:
    provider = await _owned_provider(session, provider_id, admin.organization_id)
    rows = list(
        (
            await session.execute(
                select(IdentityGroupMapping)
                .where(IdentityGroupMapping.identity_provider_id == provider.id)
                .order_by(IdentityGroupMapping.external_group.asc())
            )
        ).scalars()
    )
    return [
        GroupMappingRead(
            id=row.id,
            external_group=row.external_group,
            role=row.role,
            site_ids=[uuid.UUID(value) for value in row.site_ids_json or []],
        )
        for row in rows
    ]


@router.put(
    "/identity/providers/{provider_id}/group-mappings",
    response_model=list[GroupMappingRead],
    summary="Replace provider group mappings",
)
async def replace_group_mappings(
    provider_id: uuid.UUID,
    payload: list[GroupMappingWrite],
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> list[GroupMappingRead]:
    actor = identity.user
    await _ensure_identity_manager(session, actor)
    provider = await _owned_provider(session, provider_id, actor.organization_id)
    groups = [value.external_group for value in payload]
    if len(groups) != len(set(groups)):
        raise _error("External groups must be unique")
    site_ids = {site_id for value in payload for site_id in value.site_ids}
    if site_ids:
        owned = set(
            (
                await session.execute(
                    select(Site.id).where(
                        Site.organization_id == actor.organization_id,
                        Site.id.in_(site_ids),
                    )
                )
            ).scalars()
        )
        if owned != site_ids:
            raise _error("One or more sites do not belong to this organization")
    await session.execute(
        delete(IdentityGroupMapping).where(IdentityGroupMapping.identity_provider_id == provider.id)
    )
    rows = [
        IdentityGroupMapping(
            organization_id=actor.organization_id,
            identity_provider_id=provider.id,
            external_group=value.external_group,
            role=value.role,
            site_ids_json=[str(site_id) for site_id in value.site_ids],
        )
        for value in payload
    ]
    session.add_all(rows)
    provider.last_test_succeeded_at = None
    provider.enabled = False
    try:
        await sso.reconcile_provider_jit_users(session, provider)
    except sso.SsoError as exc:
        raise _error(str(exc), status.HTTP_409_CONFLICT) from exc
    await session.flush()
    _record(
        session,
        context,
        actor,
        "identity.group_mappings_replaced",
        provider,
        mapping_count=len(rows),
    )
    return [
        GroupMappingRead(
            id=row.id,
            external_group=row.external_group,
            role=row.role,
            site_ids=[uuid.UUID(value) for value in row.site_ids_json],
        )
        for row in rows
    ]


async def _policy_read(session: AsyncSession, organization_id: uuid.UUID) -> SsoPolicyRead:
    policy = await sso.get_policy(session, organization_id)
    ready, reasons, _provider = await sso.enforcement_readiness(
        session, organization_id, policy.identity_provider_id
    )
    flagged = list(
        (
            await session.execute(
                select(User.id).where(
                    User.organization_id == organization_id,
                    User.is_break_glass.is_(True),
                )
            )
        ).scalars()
    )
    return SsoPolicyRead(
        mode=policy.mode,
        identity_provider_id=policy.identity_provider_id,
        break_glass_user_ids=flagged,
        enforcement_ready=ready,
        readiness_reasons=reasons,
    )


@router.get("/identity/policy", response_model=SsoPolicyRead, summary="Read SSO policy")
async def read_policy(
    admin: Annotated[User, Depends(require_permission("identity.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> SsoPolicyRead:
    return await _policy_read(session, admin.organization_id)


@router.put("/identity/policy", response_model=SsoPolicyRead, summary="Update SSO policy")
async def update_policy(
    payload: SsoPolicyUpdate,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> SsoPolicyRead:
    actor = identity.user
    await _ensure_identity_manager(session, actor)
    policy = await sso.get_policy(session, actor.organization_id)
    old_mode = policy.mode
    old_provider = policy.identity_provider_id
    if payload.identity_provider_id is not None:
        await _owned_provider(session, payload.identity_provider_id, actor.organization_id)
    if payload.mode == SsoPolicyMode.ENFORCED:
        ready, reasons, _provider = await sso.enforcement_readiness(
            session, actor.organization_id, payload.identity_provider_id
        )
        if not ready:
            raise _error("SSO enforcement is not ready: " + "; ".join(reasons), 409)
    policy.mode = payload.mode
    policy.identity_provider_id = payload.identity_provider_id
    record_audit(
        session,
        action="identity.policy_updated",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="sso_policy",
        target_id=policy.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={
            "old_mode": old_mode.value,
            "new_mode": policy.mode.value,
            "old_provider_id": str(old_provider) if old_provider else None,
            "new_provider_id": str(policy.identity_provider_id)
            if policy.identity_provider_id
            else None,
        },
    )
    return await _policy_read(session, actor.organization_id)


@router.put(
    "/identity/break-glass/{user_id}",
    response_model=SsoPolicyRead,
    summary="Set a protected local break-glass administrator",
)
async def set_break_glass(
    user_id: uuid.UUID,
    payload: BreakGlassUpdate,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> SsoPolicyRead:
    actor = identity.user
    await _ensure_identity_manager(session, actor)
    target = await session.scalar(
        select(User).where(
            User.id == user_id,
            User.organization_id == actor.organization_id,
        )
    )
    if target is None:
        raise _error("User not found", 404)
    if payload.enabled:
        methods = set(await mfa.methods(session, target))
        if (
            target.role != UserRole.ADMINISTRATOR
            or target.authentication_source.value != "local"
            or not target.hashed_password
            or not target.is_active
            or not methods & {"totp", "webauthn"}
        ):
            raise _error(
                "Break-glass users must be active local administrators "
                "with a password and strong MFA",
                409,
            )
    previous = target.is_break_glass
    target.is_break_glass = payload.enabled
    await session.flush()
    if not payload.enabled:
        policy = await sso.get_policy(session, actor.organization_id)
        if policy.mode == SsoPolicyMode.ENFORCED and not await sso.active_break_glass_users(
            session, actor.organization_id
        ):
            target.is_break_glass = previous
            raise _error("SSO enforcement requires at least one protected break-glass user", 409)
    await revoke_user_sessions(
        session, target.id, reason="Break-glass access configuration changed"
    )
    record_audit(
        session,
        action="identity.break_glass_updated",
        actor=actor,
        organization_id=actor.organization_id,
        target_type="user",
        target_id=target.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"old": previous, "new": payload.enabled},
    )
    return await _policy_read(session, actor.organization_id)


async def _public_provider(
    session: AsyncSession,
    provider_id: uuid.UUID,
    *,
    allow_disabled_test_for: User | None = None,
) -> IdentityProvider:
    provider = await session.get(IdentityProvider, provider_id)
    if provider is None:
        raise _error("Identity provider is unavailable", 404)
    if allow_disabled_test_for is not None:
        if (
            allow_disabled_test_for.organization_id != provider.organization_id
            or allow_disabled_test_for.role != UserRole.ADMINISTRATOR
            or provider.validated_at is None
        ):
            raise _error("Identity provider is unavailable", 404)
        return provider
    policy = await sso.get_policy(session, provider.organization_id)
    allowed = provider.enabled and policy.mode != SsoPolicyMode.DISABLED
    if policy.mode == SsoPolicyMode.ENFORCED:
        allowed = allowed and policy.identity_provider_id == provider.id
    if not allowed:
        raise _error("Identity provider is unavailable", 404)
    return provider


@router.get(
    "/sso/providers",
    response_model=list[PublicIdentityProvider],
    summary="List public SSO choices",
)
async def public_providers(
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    organization: Annotated[str | None, Query(max_length=100)] = None,
) -> list[PublicIdentityProvider]:
    slug = organization or settings.default_org_slug
    org = await session.scalar(select(Organization).where(Organization.slug == slug))
    if org is None:
        return []
    policy = await sso.get_policy(session, org.id)
    if policy.mode == SsoPolicyMode.DISABLED:
        return []
    filters: list[Any] = [
        IdentityProvider.organization_id == org.id,
        IdentityProvider.enabled.is_(True),
    ]
    if policy.mode == SsoPolicyMode.ENFORCED:
        filters.append(IdentityProvider.id == policy.identity_provider_id)
    rows = list(
        (
            await session.execute(
                select(IdentityProvider).where(*filters).order_by(IdentityProvider.name.asc())
            )
        ).scalars()
    )
    return [
        PublicIdentityProvider(id=row.id, name=row.name, slug=row.slug, protocol=row.protocol)
        for row in rows
    ]


async def _start(
    session: AsyncSession,
    settings: Settings,
    request: Request,
    provider: IdentityProvider,
    payload: SsoStartRequest,
    *,
    purpose: str,
    initiated_by_user_id: uuid.UUID | None,
) -> SsoStartResponse:
    base = sso.public_base_url(settings, str(request.base_url))
    state_row, state, nonce, verifier = sso.new_protocol_state(
        settings,
        provider,
        protocol=provider.protocol,
        purpose=purpose,
        return_path=payload.return_path,
        initiated_by_user_id=initiated_by_user_id,
    )
    session.add(state_row)
    await session.flush()
    if provider.protocol == IdentityProviderProtocol.OIDC:
        if not nonce or not verifier or not provider.oidc_metadata_json:
            raise _error("OIDC provider has not been validated", 409)
        url = sso.oidc_authorization_url(
            provider,
            dict(provider.oidc_metadata_json),
            redirect_uri=f"{base}/api/v1/sso/oidc/{provider.id}/callback",
            state=state,
            nonce=nonce,
            verifier=verifier,
        )
    else:
        auth = sso.saml_auth(
            settings,
            provider,
            base_url=base,
            path=f"/api/v1/sso/saml/{provider.id}/start",
        )
        url = str(auth.login(return_to=state))
        state_row.request_id = auth.get_last_request_id()
    return SsoStartResponse(authorization_url=url, expires_at=state_row.expires_at)


@router.post(
    "/sso/providers/{provider_id}/start",
    response_model=SsoStartResponse,
    summary="Start a public SSO login",
)
async def start_login(
    provider_id: uuid.UUID,
    payload: SsoStartRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SsoStartResponse:
    provider = await _public_provider(session, provider_id)
    return await _start(
        session,
        settings,
        request,
        provider,
        payload,
        purpose="login",
        initiated_by_user_id=None,
    )


@router.post(
    "/identity/providers/{provider_id}/test",
    response_model=SsoStartResponse,
    summary="Start an administrator test login",
)
async def start_test_login(
    provider_id: uuid.UUID,
    payload: SsoStartRequest,
    request: Request,
    identity: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SsoStartResponse:
    actor = identity.user
    provider = await _public_provider(session, provider_id, allow_disabled_test_for=actor)
    return await _start(
        session,
        settings,
        request,
        provider,
        payload,
        purpose="test",
        initiated_by_user_id=actor.id,
    )


async def _finish_login(
    session: AsyncSession,
    settings: Settings,
    context: RequestContext,
    provider: IdentityProvider,
    state_row: Any,
    claims: dict[str, Any],
    *,
    protocol: str,
    base_url: str,
) -> RedirectResponse:
    if state_row.purpose == "test":
        initiated = await session.get(User, state_row.initiated_by_user_id)
        subject = str(claims.get("sub") or "")
        existing_link = await session.scalar(
            select(ExternalIdentityLink).where(
                ExternalIdentityLink.identity_provider_id == provider.id,
                ExternalIdentityLink.subject == subject,
            )
        )
        email = str(claims.get("email") or "").strip().lower()
        if (
            initiated is None
            or initiated.organization_id != provider.organization_id
            or initiated.role != UserRole.ADMINISTRATOR
            or not initiated.is_active
            or (existing_link is not None and existing_link.user_id != initiated.id)
            or (existing_link is None and email != initiated.email)
        ):
            raise sso.SsoError(
                "The administrator test must return the same active administrator account"
            )
    user = await sso.resolve_sso_user(session, provider, claims)
    if state_row.purpose == "test" and (
        state_row.initiated_by_user_id != user.id or user.role != UserRole.ADMINISTRATOR
    ):
        raise sso.SsoError(
            "The administrator test must return the same active administrator account"
        )
    organization = await session.get(Organization, provider.organization_id)
    if organization is None:
        raise _error("Identity provider organization is unavailable", 401)
    raw_amr = claims.get("amr")
    amr: list[Any] = raw_amr if isinstance(raw_amr, list) else []
    methods = [protocol, *[str(value)[:64] for value in amr]]
    user_session, refresh = await create_session(
        session,
        user=user,
        org=organization,
        master_secret=settings.require_secret_key(),
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        device_name=f"{provider.name} SSO",
        trust_device=False,
        authentication_methods=list(dict.fromkeys(methods)),
        mfa_authenticated=sso.sso_has_mfa(claims),
    )
    sso.mark_successful_test(session, provider, state_row)
    _record(
        session,
        context,
        user,
        "identity.sso_login_succeeded",
        provider,
        session_id=str(user_session.id),
        protocol=protocol,
        test_login=state_row.purpose == "test",
    )
    response = RedirectResponse(
        url=f"{base_url}{state_row.return_path}",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    _set_refresh_cookie(response, settings, refresh.secret, user_session.absolute_expires_at)
    return response


@router.get(
    "/sso/oidc/{provider_id}/callback",
    response_class=RedirectResponse,
    summary="Complete OIDC Authorization Code + PKCE login",
)
async def oidc_callback(
    provider_id: uuid.UUID,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
    code: Annotated[str, Query(min_length=1, max_length=4096)],
    state: Annotated[str, Query(min_length=16, max_length=1024)],
) -> RedirectResponse:
    provider = await session.get(IdentityProvider, provider_id)
    if provider is None or provider.protocol != IdentityProviderProtocol.OIDC:
        raise _error("Identity provider is unavailable", 404)
    provider_org_id = provider.organization_id
    provider_object_id = provider.id
    try:
        state_row = await sso.consume_protocol_state(session, state, IdentityProviderProtocol.OIDC)
        if state_row.identity_provider_id != provider.id:
            raise sso.SsoError("SSO state does not belong to this provider")
        await session.commit()  # state stays single-use across every later failure
        if state_row.purpose == "login":
            await _public_provider(session, provider.id)
        base = sso.public_base_url(settings, str(request.base_url))
        claims = await sso.exchange_oidc_code(
            settings,
            provider,
            state_row,
            code=code,
            redirect_uri=f"{base}/api/v1/sso/oidc/{provider.id}/callback",
        )
        return await _finish_login(
            session,
            settings,
            context,
            provider,
            state_row,
            claims,
            protocol="oidc",
            base_url=base,
        )
    except (sso.SsoError, httpx.HTTPError) as exc:
        await session.rollback()
        record_audit(
            session,
            action="identity.sso_login_failed",
            actor_type=ActorType.SYSTEM,
            organization_id=provider_org_id,
            target_type="identity_provider",
            target_id=provider_object_id,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            request_id=context.request_id,
            metadata={"protocol": "oidc"},
        )
        await session.commit()
        raise _error("SSO login could not be completed", 401) from exc


@router.get(
    "/sso/saml/{provider_id}/metadata",
    response_class=Response,
    summary="SAML service-provider metadata",
)
async def saml_metadata(
    provider_id: uuid.UUID,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    provider = await session.get(IdentityProvider, provider_id)
    if provider is None or provider.protocol != IdentityProviderProtocol.SAML:
        raise _error("Identity provider is unavailable", 404)
    base = sso.public_base_url(settings, str(request.base_url))
    try:
        metadata = sso.sp_metadata(settings, provider, base_url=base)
    except sso.SsoError as exc:
        raise _error("SAML metadata is unavailable", 404) from exc
    return Response(content=metadata, media_type="application/samlmetadata+xml")


@router.post(
    "/sso/saml/{provider_id}/acs",
    response_class=RedirectResponse,
    summary="Complete a signed SAML response",
)
async def saml_acs(
    provider_id: uuid.UUID,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> RedirectResponse:
    provider = await session.get(IdentityProvider, provider_id)
    if provider is None or provider.protocol != IdentityProviderProtocol.SAML:
        raise _error("Identity provider is unavailable", 404)
    provider_org_id = provider.organization_id
    provider_object_id = provider.id
    body = await request.body()
    if len(body) > 2_000_000:
        raise _error("SAML response is too large", 413)
    try:
        values = {
            key: items[0]
            for key, items in parse_qs(body.decode("utf-8"), keep_blank_values=True).items()
            if items
        }
    except UnicodeDecodeError as exc:
        raise _error("SAML response encoding is invalid") from exc
    relay_state = values.get("RelayState", "")
    try:
        state_row = await sso.consume_protocol_state(
            session, relay_state, IdentityProviderProtocol.SAML
        )
        if state_row.identity_provider_id != provider.id:
            raise sso.SsoError("SSO state does not belong to this provider")
        await session.commit()
        if state_row.purpose == "login":
            await _public_provider(session, provider.id)
        base = sso.public_base_url(settings, str(request.base_url))
        auth = sso.saml_auth(
            settings,
            provider,
            base_url=base,
            path=f"/api/v1/sso/saml/{provider.id}/acs",
            post_data=values,
        )
        auth.process_response(request_id=state_row.request_id)
        if auth.get_errors() or not auth.is_authenticated():
            raise sso.SsoError("SAML response validation failed")
        await sso.record_saml_identifiers(
            session,
            provider,
            [auth.get_last_message_id(), auth.get_last_assertion_id()],
        )
        attributes = auth.get_attributes()

        def first(*names: str) -> str | None:
            for name in names:
                raw = attributes.get(name)
                if isinstance(raw, list) and raw:
                    return str(raw[0])
            return None

        groups: list[str] = []
        for name in ("groups", "group", "memberOf"):
            raw = attributes.get(name)
            if isinstance(raw, list):
                groups.extend(str(value) for value in raw)
        contexts = [str(value) for value in auth.get_last_authn_contexts() or []]
        strong = any(
            marker in value.lower()
            for value in contexts
            for marker in ("multifactor", "time-sync-token", "smartcard", "otp")
        )
        email = first(
            "email",
            "mail",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        )
        claims: dict[str, Any] = {
            "sub": auth.get_nameid(),
            "email": email,
            "email_verified": bool(email),
            "name": first(
                "displayName",
                "name",
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
            ),
            "groups": groups,
            "amr": ["mfa"] if strong else ["saml"],
        }
        return await _finish_login(
            session,
            settings,
            context,
            provider,
            state_row,
            claims,
            protocol="saml",
            base_url=base,
        )
    except sso.SsoError as exc:
        await session.rollback()
        record_audit(
            session,
            action="identity.sso_login_failed",
            actor_type=ActorType.SYSTEM,
            organization_id=provider_org_id,
            target_type="identity_provider",
            target_id=provider_object_id,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            request_id=context.request_id,
            metadata={"protocol": "saml"},
        )
        await session.commit()
        raise _error("SSO login could not be completed", 401) from exc
