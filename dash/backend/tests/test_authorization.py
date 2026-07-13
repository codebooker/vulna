"""Phase 39 granular authorization and service-principal security coverage."""

from __future__ import annotations

import json
import uuid

import pytest
from app.models.audit import AuditEvent
from app.models.authorization import ApiToken, AuthorizationRole, ScopedGrant
from app.models.enums import (
    ActorType,
    GrantScopeType,
    PrincipalType,
    SiteAccessMode,
    UserRole,
)
from app.models.organization import Organization
from app.models.site import Site
from app.models.user import User
from app.services import authorization
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import UserFactory, auth_headers

pytestmark = pytest.mark.release_gate


async def _create_role(
    client: AsyncClient,
    headers: dict[str, str],
    *,
    key: str,
    permissions: list[str],
) -> dict[str, object]:
    response = await client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "key": key,
            "name": key.replace("_", " ").title(),
            "permission_keys": permissions,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _create_service(
    client: AsyncClient, headers: dict[str, str], name: str = "Inventory robot"
) -> dict[str, object]:
    response = await client.post(
        "/api/v1/service-accounts",
        headers=headers,
        json={"name": name, "description": "Read-only automation"},
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _grant(
    client: AsyncClient,
    headers: dict[str, str],
    *,
    principal_type: PrincipalType,
    principal_id: str,
    role_id: str,
    scope_type: GrantScopeType,
    scope_id: str,
) -> dict[str, object]:
    response = await client.post(
        "/api/v1/grants",
        headers=headers,
        json={
            "principal_type": principal_type.value,
            "principal_id": principal_id,
            "role_id": role_id,
            "scope_type": scope_type.value,
            "scope_id": scope_id,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _issue_service_token(
    client: AsyncClient,
    headers: dict[str, str],
    service_id: str,
    *,
    restrictions: list[str] | None = None,
) -> dict[str, object]:
    response = await client.post(
        f"/api/v1/service-accounts/{service_id}/tokens",
        headers=headers,
        json={
            "name": "automation",
            "expires_in_days": 30,
            "ip_restrictions": restrictions or [],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _bearer(secret: object) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


async def test_permission_catalogue_and_custom_role_preserve_legacy_shape(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    organization: Organization,
    db_session: AsyncSession,
) -> None:
    viewer = await make_user(UserRole.VIEWER)
    catalogue = await client.get("/api/v1/permissions", headers=auth_headers(viewer))
    assert catalogue.status_code == 200
    keys = {value["key"] for value in catalogue.json()}
    assert {"roles.manage", "sites.read", "audit.read", "tokens.self"} <= keys

    denied = await client.get("/api/v1/audit", headers=auth_headers(viewer))
    assert denied.status_code == 403
    assert (await client.get("/api/v1/users", headers=auth_headers(viewer))).status_code == 403
    assert (await client.get("/api/v1/roles", headers=auth_headers(viewer))).status_code == 403
    role = await _create_role(
        client, admin_headers, key="audit_reader", permissions=["audit.read"]
    )
    await _grant(
        client,
        admin_headers,
        principal_type=PrincipalType.USER,
        principal_id=str(viewer.id),
        role_id=str(role["id"]),
        scope_type=GrantScopeType.ORGANIZATION,
        scope_id=str(organization.id),
    )
    await db_session.refresh(viewer)

    allowed = await client.get("/api/v1/audit", headers=auth_headers(viewer))
    assert allowed.status_code == 200
    me = await client.get("/api/v1/auth/me", headers=auth_headers(viewer))
    assert me.json()["role"] == UserRole.VIEWER.value
    assert "audit.read" in me.json()["permissions"]


async def test_auditor_retains_audit_access_without_inheriting_admin_directories(
    client: AsyncClient,
    make_user: UserFactory,
) -> None:
    auditor = await make_user(UserRole.AUDITOR)
    headers = auth_headers(auditor)

    assert (await client.get("/api/v1/audit", headers=headers)).status_code == 200
    assert (await client.get("/api/v1/users", headers=headers)).status_code == 403
    assert (await client.get("/api/v1/roles", headers=headers)).status_code == 403


async def test_custom_org_grant_cannot_promote_assigned_compatibility_access(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    organization: Organization,
    db_session: AsyncSession,
) -> None:
    viewer = await make_user(UserRole.VIEWER)
    site_response = await client.post(
        "/api/v1/sites", headers=admin_headers, json={"name": "Assigned", "code": "A"}
    )
    assert site_response.status_code == 201
    site_id = site_response.json()["id"]
    assignment = await client.put(
        f"/api/v1/users/{viewer.id}/site-access",
        headers=admin_headers,
        json={"mode": SiteAccessMode.ASSIGNED.value, "site_ids": [site_id]},
    )
    assert assignment.status_code == 200, assignment.text

    role = await _create_role(
        client, admin_headers, key="assigned_auditor", permissions=["audit.read"]
    )
    await _grant(
        client,
        admin_headers,
        principal_type=PrincipalType.USER,
        principal_id=str(viewer.id),
        role_id=str(role["id"]),
        scope_type=GrantScopeType.ORGANIZATION,
        scope_id=str(organization.id),
    )
    await db_session.refresh(viewer)
    assert viewer.site_access_mode == SiteAccessMode.ASSIGNED

    # A later lifecycle synchronization must retain the site-scoped Viewer
    # compatibility grant instead of widening it to the organization.
    await authorization.sync_user_compatibility_grants(db_session, viewer)
    await db_session.commit()
    scopes = list(
        (
            await db_session.execute(
                select(ScopedGrant.scope_type, ScopedGrant.scope_id)
                .join(AuthorizationRole, AuthorizationRole.id == ScopedGrant.role_id)
                .where(
                    ScopedGrant.user_id == viewer.id,
                    AuthorizationRole.compatibility_role == UserRole.VIEWER,
                )
            )
        ).all()
    )
    assert scopes == [(GrantScopeType.SITE, uuid.UUID(site_id))]


async def test_site_scoped_service_token_filters_resources_and_cannot_cross_org(
    client: AsyncClient,
    admin_headers: dict[str, str],
    organization: Organization,
    db_session: AsyncSession,
) -> None:
    north = await client.post(
        "/api/v1/sites", headers=admin_headers, json={"name": "North", "code": "N"}
    )
    south = await client.post(
        "/api/v1/sites", headers=admin_headers, json={"name": "South", "code": "S"}
    )
    assert north.status_code == south.status_code == 201
    role = await _create_role(
        client, admin_headers, key="site_reader", permissions=["sites.read"]
    )
    service = await _create_service(client, admin_headers)
    await _grant(
        client,
        admin_headers,
        principal_type=PrincipalType.SERVICE_ACCOUNT,
        principal_id=str(service["id"]),
        role_id=str(role["id"]),
        scope_type=GrantScopeType.SITE,
        scope_id=north.json()["id"],
    )
    asset_role = await _create_role(
        client, admin_headers, key="asset_reader", permissions=["assets.read"]
    )
    await _grant(
        client,
        admin_headers,
        principal_type=PrincipalType.SERVICE_ACCOUNT,
        principal_id=str(service["id"]),
        role_id=str(asset_role["id"]),
        scope_type=GrantScopeType.SITE,
        scope_id=south.json()["id"],
    )
    issued = await _issue_service_token(client, admin_headers, str(service["id"]))
    token_headers = _bearer(issued["token"])

    listing = await client.get("/api/v1/sites", headers=token_headers)
    assert listing.status_code == 200
    assert [value["id"] for value in listing.json()["items"]] == [north.json()["id"]]
    assert (await client.get("/api/v1/relays", headers=token_headers)).status_code == 403
    assert (
        await client.get("/api/v1/networking/status", headers=token_headers)
    ).status_code == 403
    profile = await client.get("/api/v1/auth/me", headers=token_headers)
    assert profile.status_code == 200
    assert profile.json()["principal_type"] == PrincipalType.SERVICE_ACCOUNT.value
    assert profile.json()["email"] is None
    assert profile.json()["permissions"] == ["assets.read", "sites.read"]

    foreign_org = Organization(name="Foreign", slug="foreign", default_timezone="UTC")
    db_session.add(foreign_org)
    await db_session.flush()
    foreign_site = Site(
        organization_id=foreign_org.id,
        name="Foreign site",
        code="F",
        timezone="UTC",
    )
    db_session.add(foreign_site)
    await db_session.commit()
    assert str(foreign_site.id) not in json.dumps(listing.json())

    foreign_grant = await client.post(
        "/api/v1/grants",
        headers=admin_headers,
        json={
            "principal_type": PrincipalType.SERVICE_ACCOUNT.value,
            "principal_id": service["id"],
            "role_id": role["id"],
            "scope_type": GrantScopeType.SITE.value,
            "scope_id": str(foreign_site.id),
        },
    )
    assert foreign_grant.status_code == 422
    assert str(organization.id) != str(foreign_org.id)


async def test_service_tokens_are_one_time_hashed_ip_bound_rotatable_and_revocable(
    client: AsyncClient,
    admin_headers: dict[str, str],
    organization: Organization,
    db_session: AsyncSession,
) -> None:
    role = await _create_role(
        client,
        admin_headers,
        key="relay_operator",
        permissions=["relays.read", "relays.manage"],
    )
    service = await _create_service(client, admin_headers, "Relay robot")
    await _grant(
        client,
        admin_headers,
        principal_type=PrincipalType.SERVICE_ACCOUNT,
        principal_id=str(service["id"]),
        role_id=str(role["id"]),
        scope_type=GrantScopeType.ORGANIZATION,
        scope_id=str(organization.id),
    )
    issued = await _issue_service_token(
        client,
        admin_headers,
        str(service["id"]),
        restrictions=["127.0.0.0/8"],
    )
    secret = str(issued["token"])
    assert secret.startswith("vapi_")
    stored = await db_session.get(ApiToken, uuid.UUID(str(issued["id"])))
    assert stored is not None
    assert stored.token_hash == authorization.hash_api_token(secret)
    assert secret not in stored.token_hash

    listed = await client.get(
        f"/api/v1/service-accounts/{service['id']}/tokens", headers=admin_headers
    )
    assert listed.status_code == 200
    assert "token" not in listed.json()[0]
    assert listed.json()[0]["has_secret"] is True

    action = await client.post(
        "/api/v1/relays/settings", headers=_bearer(secret), json={"enabled": False}
    )
    assert action.status_code == 200, action.text
    audit = await db_session.scalar(
        select(AuditEvent)
        .where(AuditEvent.action == "relay.mode_disabled")
        .order_by(AuditEvent.created_at.desc())
    )
    assert audit is not None
    assert audit.actor_type == ActorType.SERVICE_ACCOUNT
    assert audit.actor_id == uuid.UUID(str(service["id"]))
    assert secret not in json.dumps(audit.metadata_json)

    rotated = await client.post(
        f"/api/v1/service-accounts/{service['id']}/tokens/{issued['id']}/rotate",
        headers=admin_headers,
        json={"expires_in_days": 15},
    )
    assert rotated.status_code == 200, rotated.text
    replacement = rotated.json()["token"]
    assert replacement != secret
    assert (await client.get("/api/v1/auth/me", headers=_bearer(secret))).status_code == 401
    assert (
        await client.get("/api/v1/auth/me", headers=_bearer(replacement))
    ).status_code == 200

    revoked = await client.delete(
        f"/api/v1/service-accounts/{service['id']}/tokens/{rotated.json()['id']}",
        headers=admin_headers,
    )
    assert revoked.status_code == 204
    assert (
        await client.get("/api/v1/auth/me", headers=_bearer(replacement))
    ).status_code == 401

    denied = await _issue_service_token(
        client,
        admin_headers,
        str(service["id"]),
        restrictions=["203.0.113.0/24"],
    )
    assert (
        await client.get("/api/v1/auth/me", headers=_bearer(denied["token"]))
    ).status_code == 401


async def test_personal_token_rotation_and_service_account_suspension_revoke_access(
    client: AsyncClient,
    admin_headers: dict[str, str],
    admin: User,
    organization: Organization,
) -> None:
    personal = await client.post(
        "/api/v1/tokens",
        headers=admin_headers,
        json={"name": "CLI", "expires_in_days": 7},
    )
    assert personal.status_code == 201, personal.text
    original = personal.json()["token"]
    assert (await client.get("/api/v1/auth/me", headers=_bearer(original))).status_code == 200
    rotated = await client.post(
        f"/api/v1/tokens/{personal.json()['id']}/rotate",
        headers=admin_headers,
        json={"expires_in_days": 7},
    )
    assert rotated.status_code == 200
    assert (await client.get("/api/v1/auth/me", headers=_bearer(original))).status_code == 401
    replacement = rotated.json()["token"]

    service = await _create_service(client, admin_headers, "Disposable robot")
    role = await _create_role(
        client, admin_headers, key="system_reader", permissions=["system.read"]
    )
    await _grant(
        client,
        admin_headers,
        principal_type=PrincipalType.SERVICE_ACCOUNT,
        principal_id=str(service["id"]),
        role_id=str(role["id"]),
        scope_type=GrantScopeType.ORGANIZATION,
        scope_id=str(organization.id),
    )
    issued = await _issue_service_token(client, admin_headers, str(service["id"]))
    suspended = await client.delete(
        f"/api/v1/service-accounts/{service['id']}", headers=admin_headers
    )
    assert suspended.status_code == 204
    assert (
        await client.get("/api/v1/auth/me", headers=_bearer(issued["token"]))
    ).status_code == 401

    login = await client.post(
        "/api/v1/auth/login",
        json={"email": "disposable-robot@example.com", "password": "irrelevant"},
    )
    assert login.status_code == 401
    revoked = await client.delete(
        f"/api/v1/tokens/{rotated.json()['id']}", headers=admin_headers
    )
    assert revoked.status_code == 204
    assert (
        await client.get("/api/v1/auth/me", headers=_bearer(replacement))
    ).status_code == 401
    assert admin.role == UserRole.ADMINISTRATOR


async def test_last_active_administrator_grant_cannot_be_removed(
    client: AsyncClient,
    admin_headers: dict[str, str],
    admin: User,
    db_session: AsyncSession,
) -> None:
    await authorization.sync_user_compatibility_grants(
        db_session, admin, created_by_user_id=admin.id
    )
    await db_session.commit()
    grant = await db_session.scalar(
        select(ScopedGrant)
        .join(AuthorizationRole, AuthorizationRole.id == ScopedGrant.role_id)
        .where(
            ScopedGrant.user_id == admin.id,
            AuthorizationRole.compatibility_role == UserRole.ADMINISTRATOR,
        )
    )
    assert grant is not None
    response = await client.delete(f"/api/v1/grants/{grant.id}", headers=admin_headers)
    assert response.status_code == 409
    assert "last active administrator" in response.text


async def test_demo_reset_never_seeds_or_deletes_service_principals(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    service = await _create_service(client, admin_headers, "Persistent automation")
    assert (await client.post("/api/v1/demo/enable", headers=admin_headers)).status_code == 200
    assert (await client.post("/api/v1/demo/disable", headers=admin_headers)).status_code == 200
    listing = await client.get("/api/v1/service-accounts", headers=admin_headers)
    assert listing.status_code == 200
    assert [value["id"] for value in listing.json()] == [service["id"]]


async def test_phase39_public_openapi_interfaces(client: AsyncClient) -> None:
    schema = (await client.get("/openapi.json")).json()
    paths = schema["paths"]
    for path in (
        "/api/v1/permissions",
        "/api/v1/roles",
        "/api/v1/grants",
        "/api/v1/service-accounts",
        "/api/v1/tokens",
        "/api/v1/authorization/effective",
    ):
        assert path in paths
