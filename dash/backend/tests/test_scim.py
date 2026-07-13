"""Phase 38 SCIM 2.0 protocol, isolation, and access-mapping coverage."""

from __future__ import annotations

import uuid

import pytest
from app.models.asset_context import AssetGroup
from app.models.enums import (
    AccountStatus,
    AssetGroupType,
    AuthenticationSource,
    SiteAccessMode,
    UserRole,
)
from app.models.organization import Organization
from app.models.scim import (
    ScimGroup,
    ScimProvisioningLog,
    ScimToken,
)
from app.models.site import Site
from app.models.user import User
from app.models.user_lifecycle import UserSiteAssignment
from app.services import scim
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

pytestmark = pytest.mark.release_gate

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"


async def _issue_token(
    client: AsyncClient, admin_headers: dict[str, str], name: str = "Directory sync"
) -> tuple[str, uuid.UUID]:
    response = await client.post(
        "/api/v1/scim/tokens",
        json={"name": name, "expires_in_days": 30},
        headers=admin_headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["token"], uuid.UUID(response.json()["id"])


def _scim_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/scim+json"}


async def _create_scim_user(
    client: AsyncClient,
    token: str,
    *,
    email: str = "provisioned@example.com",
    external_id: str = "directory-user-1",
    active: bool = True,
) -> dict[str, object]:
    response = await client.post(
        "/scim/v2/Users",
        headers=_scim_headers(token),
        json={
            "schemas": [USER_SCHEMA],
            "externalId": external_id,
            "userName": email,
            "displayName": "Provisioned User",
            "active": active,
            "password": "must-never-be-stored",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


async def test_scim_token_is_disclosed_once_hashed_and_rotatable(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    secret, token_id = await _issue_token(client, admin_headers)
    assert secret.startswith("vscim_")
    stored = await db_session.get(ScimToken, token_id)
    assert stored is not None
    assert stored.token_hash == scim.hash_token(secret)
    assert secret not in stored.token_hash

    listed = await client.get("/api/v1/scim/tokens", headers=admin_headers)
    assert listed.status_code == 200
    assert "token" not in listed.json()[0]
    assert listed.json()[0]["has_secret"] is True

    rotated = await client.post(f"/api/v1/scim/tokens/{token_id}/rotate", headers=admin_headers)
    assert rotated.status_code == 200
    replacement = rotated.json()["token"]
    assert replacement != secret
    assert (
        await client.get("/scim/v2/ServiceProviderConfig", headers=_scim_headers(secret))
    ).status_code == 401
    assert (
        await client.get("/scim/v2/ServiceProviderConfig", headers=_scim_headers(replacement))
    ).status_code == 200


async def test_discovery_resources_and_standard_error_shape(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    token, _ = await _issue_token(client, admin_headers)
    headers = _scim_headers(token)
    config = await client.get("/scim/v2/ServiceProviderConfig", headers=headers)
    assert config.status_code == 200
    assert config.headers["content-type"].startswith("application/scim+json")
    assert config.json()["patch"]["supported"] is True
    assert config.json()["bulk"]["supported"] is False

    resource_types = await client.get("/scim/v2/ResourceTypes", headers=headers)
    assert {value["id"] for value in resource_types.json()["Resources"]} == {
        "User",
        "Group",
    }
    schemas = await client.get("/scim/v2/Schemas", headers=headers)
    assert {value["id"] for value in schemas.json()["Resources"]} == {
        USER_SCHEMA,
        GROUP_SCHEMA,
    }

    invalid = await client.get(
        '/scim/v2/Users?filter=userName%20eq%20"unterminated', headers=headers
    )
    assert invalid.status_code == 400
    assert invalid.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert invalid.json()["scimType"] == "invalidFilter"
    assert invalid.headers["content-type"].startswith("application/scim+json")


async def test_users_support_filter_pagination_patch_and_preserved_deprovisioning(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    token, _ = await _issue_token(client, admin_headers)
    first = await _create_scim_user(client, token)
    second = await _create_scim_user(
        client,
        token,
        email="second@example.com",
        external_id="directory-user-2",
    )
    assert first["meta"]["resourceType"] == "User"  # type: ignore[index]

    filtered = await client.get(
        '/scim/v2/Users?filter=userName%20sw%20"provisioned"&startIndex=1&count=1',
        headers=_scim_headers(token),
    )
    assert filtered.status_code == 200
    assert filtered.json()["totalResults"] == 1
    assert filtered.json()["itemsPerPage"] == 1
    assert filtered.json()["Resources"][0]["id"] == first["id"]

    searched = await client.post(
        "/scim/v2/Users/.search",
        headers=_scim_headers(token),
        json={"filter": 'externalId eq "directory-user-2"', "count": 10},
    )
    assert searched.status_code == 200
    assert searched.json()["Resources"][0]["id"] == second["id"]

    patched = await client.patch(
        f"/scim/v2/Users/{first['id']}",
        headers=_scim_headers(token),
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [
                {"op": "replace", "path": "displayName", "value": "Updated Name"},
                {"op": "replace", "path": "active", "value": False},
            ],
        },
    )
    assert patched.status_code == 200
    assert patched.json()["displayName"] == "Updated Name"
    assert patched.json()["active"] is False
    user = await db_session.get(User, uuid.UUID(str(first["id"])))
    assert user is not None
    assert user.account_status == AccountStatus.DEACTIVATED
    assert user.authentication_source == AuthenticationSource.SCIM
    assert user.hashed_password is None

    deleted = await client.delete(f"/scim/v2/Users/{second['id']}", headers=_scim_headers(token))
    assert deleted.status_code == 204
    preserved = await db_session.get(User, uuid.UUID(str(second["id"])))
    assert preserved is not None and preserved.account_status == AccountStatus.DEACTIVATED


async def test_scim_hides_and_cannot_claim_local_users(
    client: AsyncClient,
    admin_headers: dict[str, str],
    admin: User,
) -> None:
    token, _ = await _issue_token(client, admin_headers)
    listing = await client.get("/scim/v2/Users", headers=_scim_headers(token))
    assert listing.status_code == 200
    assert listing.json()["totalResults"] == 0
    assert (
        await client.get(f"/scim/v2/Users/{admin.id}", headers=_scim_headers(token))
    ).status_code == 404
    conflict = await client.post(
        "/scim/v2/Users",
        headers=_scim_headers(token),
        json={"schemas": [USER_SCHEMA], "userName": admin.email},
    )
    assert conflict.status_code == 409
    assert conflict.json()["scimType"] == "uniqueness"


async def test_groups_patch_members_and_map_role_and_site_immediately(
    client: AsyncClient,
    admin_headers: dict[str, str],
    organization: Organization,
    db_session: AsyncSession,
) -> None:
    site = Site(
        organization_id=organization.id,
        name="HQ",
        code="hq",
        timezone="UTC",
    )
    db_session.add(site)
    await db_session.commit()
    await db_session.refresh(site)
    token, _ = await _issue_token(client, admin_headers)
    user = await _create_scim_user(client, token)
    created = await client.post(
        "/scim/v2/Groups",
        headers=_scim_headers(token),
        json={
            "schemas": [GROUP_SCHEMA],
            "displayName": "Security Operators",
            "externalId": "directory-group-1",
            "members": [{"value": user["id"], "type": "User"}],
        },
    )
    assert created.status_code == 201, created.text
    group_id = created.json()["id"]

    preview = await client.post(
        f"/api/v1/scim/groups/{group_id}/mapping/preview",
        headers=admin_headers,
        json={
            "role": "security_operator",
            "grants_all_sites": False,
            "site_ids": [str(site.id)],
        },
    )
    assert preview.status_code == 200
    assert preview.json()["affected_users"] == 1
    assert preview.json()["users"][0]["role"] == "security_operator"

    mapped = await client.put(
        f"/api/v1/scim/groups/{group_id}/mapping",
        headers=admin_headers,
        json={
            "role": "security_operator",
            "grants_all_sites": False,
            "site_ids": [str(site.id)],
        },
    )
    assert mapped.status_code == 200, mapped.text
    provisioned = await db_session.get(User, uuid.UUID(str(user["id"])))
    await db_session.refresh(provisioned)
    assert provisioned is not None
    assert provisioned.role == UserRole.SECURITY_OPERATOR
    assert provisioned.site_access_mode == SiteAccessMode.ASSIGNED
    assignment = await db_session.scalar(
        select(UserSiteAssignment).where(UserSiteAssignment.user_id == provisioned.id)
    )
    assert assignment is not None and assignment.site_id == site.id

    removed = await client.patch(
        f"/scim/v2/Groups/{group_id}",
        headers=_scim_headers(token),
        json={
            "schemas": [PATCH_SCHEMA],
            "Operations": [
                {
                    "op": "remove",
                    "path": f'members[value eq "{user["id"]}"]',
                }
            ],
        },
    )
    assert removed.status_code == 200, removed.text
    await db_session.refresh(provisioned)
    assert provisioned.role == UserRole.VIEWER
    assert (
        await db_session.scalar(
            select(UserSiteAssignment).where(UserSiteAssignment.user_id == provisioned.id)
        )
    ) is None


async def test_group_membership_rejects_local_and_foreign_users(
    client: AsyncClient,
    admin_headers: dict[str, str],
    admin: User,
) -> None:
    token, _ = await _issue_token(client, admin_headers)
    response = await client.post(
        "/scim/v2/Groups",
        headers=_scim_headers(token),
        json={
            "schemas": [GROUP_SCHEMA],
            "displayName": "Unsafe Group",
            "members": [{"value": str(admin.id)}],
        },
    )
    assert response.status_code == 400
    assert response.json()["scimType"] == "invalidValue"


async def test_token_and_resources_are_strictly_organization_isolated(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    token, _ = await _issue_token(client, admin_headers)
    created = await _create_scim_user(client, token)

    other = Organization(name="Other", slug="other", default_timezone="UTC")
    db_session.add(other)
    await db_session.flush()
    generated = scim.generate_token()
    foreign_token = ScimToken(
        organization_id=other.id,
        name="Other directory",
        token_hash=generated.token_hash,
        token_prefix=generated.token_prefix,
        expires_at=scim.utcnow().replace(year=scim.utcnow().year + 1),
    )
    db_session.add(foreign_token)
    await db_session.commit()

    foreign_list = await client.get("/scim/v2/Users", headers=_scim_headers(generated.secret))
    assert foreign_list.status_code == 200
    assert foreign_list.json()["totalResults"] == 0
    assert (
        await client.get(f"/scim/v2/Users/{created['id']}", headers=_scim_headers(generated.secret))
    ).status_code == 404


async def test_provisioning_logs_are_sanitized_and_failures_are_recorded(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    token, token_id = await _issue_token(client, admin_headers)
    await _create_scim_user(client, token)
    failed = await client.get(
        '/scim/v2/Users?filter=unknown%20bad%20"value"',
        headers={**_scim_headers(token), "X-Request-ID": "scim-test-request"},
    )
    assert failed.status_code == 400

    logs = await client.get("/api/v1/scim/logs", headers=admin_headers)
    assert logs.status_code == 200
    assert logs.json()["total"] >= 2
    assert any(value["succeeded"] is False for value in logs.json()["items"])
    serialized = logs.text.lower()
    assert token.lower() not in serialized
    assert "must-never-be-stored" not in serialized
    stored = list(
        (
            await db_session.execute(
                select(ScimProvisioningLog).where(ScimProvisioningLog.token_id == token_id)
            )
        ).scalars()
    )
    assert stored and all(token not in str(value.changes_json) for value in stored)


async def test_asset_group_mapping_targets_are_exposed_and_validated_in_phase40(
    client: AsyncClient,
    admin_headers: dict[str, str],
    organization: Organization,
    db_session: AsyncSession,
) -> None:
    asset_group = AssetGroup(
        organization_id=organization.id,
        name="Production assets",
        group_type=AssetGroupType.STATIC,
        priority=10,
    )
    db_session.add(asset_group)
    await db_session.flush()
    group = ScimGroup(
        organization_id=organization.id,
        display_name="Future Assets",
        asset_group_targets_json=[{"asset_group_id": str(asset_group.id)}],
    )
    db_session.add(group)
    await db_session.commit()
    admin_view = await client.get("/api/v1/scim/groups", headers=admin_headers)
    assert admin_view.status_code == 200
    mapping = next(value for value in admin_view.json() if value["id"] == str(group.id))
    assert mapping["asset_group_ids"] == [str(asset_group.id)]
    exported = await client.get("/api/v1/portability/export", headers=admin_headers)
    assert exported.status_code == 200
    exported_group = next(
        value for value in exported.json()["scim_groups"] if value["id"] == str(group.id)
    )
    assert exported_group["asset_group_ids"] == [str(asset_group.id)]

    invalid = await client.put(
        f"/api/v1/scim/groups/{group.id}/mapping",
        json={"asset_group_ids": [str(uuid.uuid4())]},
        headers=admin_headers,
    )
    assert invalid.status_code == 422
    deleted = await client.delete(f"/api/v1/asset-groups/{asset_group.id}", headers=admin_headers)
    assert deleted.status_code == 204
    after_delete = await client.get("/api/v1/scim/groups", headers=admin_headers)
    cleaned_mapping = next(value for value in after_delete.json() if value["id"] == str(group.id))
    assert cleaned_mapping["asset_group_ids"] == []


async def test_scim_openapi_and_capability_status_are_additive(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    schema = (await client.get("/openapi.json")).json()
    assert "/scim/v2/Users" in schema["paths"]
    assert "/scim/v2/Groups" in schema["paths"]
    assert "/api/v1/scim/tokens" in schema["paths"]
    capabilities = (
        await client.get("/api/v1/system/capabilities", headers=admin_headers)
    ).json()
    scim_status = next(value for value in capabilities["capabilities"] if value["key"] == "scim")
    assert scim_status["status"] == "available"
    assert scim_status["production_ready"] is False
