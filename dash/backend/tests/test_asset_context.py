"""Phase 40 asset context, grouping, ownership, and isolation coverage."""

from __future__ import annotations

import uuid

import pytest
from app.models.asset import Asset
from app.models.asset_context import (
    AssetGroup,
    AssetGroupMembership,
    AssetTagAssignment,
    DepartmentOwner,
)
from app.models.audit import AuditEvent
from app.models.enums import (
    AssetGroupType,
    AssetMembershipSource,
    AssetTagSource,
    AssetType,
    FindingType,
    OwnershipSource,
    Severity,
    UserRole,
)
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.site import Site
from app.models.user import User
from app.services import asset_context
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import UserFactory

pytestmark = pytest.mark.release_gate


async def _inventory(
    session: AsyncSession, organization: Organization
) -> tuple[Site, Asset, Asset]:
    site = Site(
        organization_id=organization.id,
        name="Main",
        code=f"MAIN-{uuid.uuid4().hex[:6]}",
        timezone="UTC",
    )
    session.add(site)
    await session.flush()
    production = Asset(
        organization_id=organization.id,
        site_id=site.id,
        canonical_name="payments-api",
        asset_type=AssetType.SERVER,
        operating_system="Linux",
        manufacturer="Example",
    )
    development = Asset(
        organization_id=organization.id,
        site_id=site.id,
        canonical_name="payments-dev",
        asset_type=AssetType.SERVER,
        operating_system="Linux",
        manufacturer="Example",
    )
    session.add_all([production, development])
    await session.commit()
    return site, production, development


async def test_context_tags_dynamic_groups_filters_and_bulk_edit(
    client: AsyncClient,
    admin_headers: dict[str, str],
    admin: User,
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    site, production, development = await _inventory(db_session, organization)

    tag_response = await client.post(
        "/api/v1/asset-tags",
        json={"name": "Payment Tier", "color": "#3366ff"},
        headers=admin_headers,
    )
    assert tag_response.status_code == 201, tag_response.text
    tag = tag_response.json()
    assigned = await client.put(
        f"/api/v1/assets/{production.id}/tags/{tag['id']}", headers=admin_headers
    )
    assert assigned.status_code == 201

    context_response = await client.patch(
        f"/api/v1/assets/{production.id}/context",
        json={
            "department": "Finance",
            "environment": "production",
            "criticality": "mission_critical",
            "data_classification": "restricted",
            "internet_exposed": True,
            "context_json": {"cost_center": "FIN-42"},
        },
        headers=admin_headers,
    )
    assert context_response.status_code == 200, context_response.text
    cannot_clear_required_context = await client.patch(
        f"/api/v1/assets/{production.id}/context",
        json={"environment": None},
        headers=admin_headers,
    )
    assert cannot_clear_required_context.status_code == 422

    rule = {
        "all": [
            {"field": "environment", "operator": "eq", "value": "production"},
            {"field": "tag", "operator": "eq", "value": "payment tier"},
        ]
    }
    preview = await client.post(
        "/api/v1/asset-groups/preview",
        json={"rule_json": rule, "site_id": str(site.id)},
        headers=admin_headers,
    )
    assert preview.status_code == 200, preview.text
    assert [row["asset_id"] for row in preview.json()["matches"]] == [str(production.id)]
    assert preview.json()["matches"][0]["explanation"]["matched"] is True

    group_response = await client.post(
        "/api/v1/asset-groups",
        json={
            "name": "Production payments",
            "group_type": "dynamic",
            "site_id": str(site.id),
            "rule_json": rule,
            "priority": 100,
        },
        headers=admin_headers,
    )
    assert group_response.status_code == 201, group_response.text
    group = group_response.json()
    assert group["member_count"] == 1

    filtered = await client.get(
        "/api/v1/assets",
        params={
            "tag_id": tag["id"],
            "group_id": group["id"],
            "department": "finance",
            "environment": "production",
            "criticality": "mission_critical",
            "internet_exposed": "true",
        },
        headers=admin_headers,
    )
    assert filtered.status_code == 200, filtered.text
    assert [row["id"] for row in filtered.json()["items"]] == [str(production.id)]
    assert filtered.json()["items"][0]["tags"][0]["name"] == "Payment Tier"
    assert filtered.json()["items"][0]["group_ids"] == [group["id"]]

    disabled = await client.patch(
        f"/api/v1/asset-groups/{group['id']}",
        json={"enabled": False},
        headers=admin_headers,
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["member_count"] == 0
    disabled_filter = await client.get(
        "/api/v1/assets", params={"group_id": group["id"]}, headers=admin_headers
    )
    assert disabled_filter.status_code == 200
    assert disabled_filter.json()["total"] == 0

    static_group = await client.post(
        "/api/v1/asset-groups",
        json={
            "name": "Review queue",
            "group_type": "static",
            "site_id": str(site.id),
            "priority": 10,
        },
        headers=admin_headers,
    )
    assert static_group.status_code == 201
    bulk = await client.post(
        "/api/v1/assets/bulk",
        json={
            "asset_ids": [str(production.id), str(development.id)],
            "context": {"business_function": "Payments"},
            "add_static_group_ids": [static_group.json()["id"]],
        },
        headers=admin_headers,
    )
    assert bulk.status_code == 200, bulk.text
    assert bulk.json() == {
        "updated_assets": 2,
        "tags_added": 0,
        "tags_removed": 0,
        "memberships_added": 2,
        "memberships_removed": 0,
    }

    organization_id = organization.id
    site_id = site.id
    db_session.expire_all()
    audit_actions = set(
        (
            await db_session.execute(
                select(AuditEvent.action).where(AuditEvent.organization_id == organization_id)
            )
        ).scalars()
    )
    assert {
        "asset_tag.created",
        "asset.tag_assigned",
        "asset.context_updated",
        "asset_group.created",
        "asset_group.updated",
        "asset.bulk_updated",
    } <= audit_actions

    unsafe = await client.post(
        "/api/v1/asset-groups/preview",
        json={
            "site_id": str(site_id),
            "rule_json": {
                "field": "canonical_name",
                "operator": "regex",
                "value": ".*",
            },
        },
        headers=admin_headers,
    )
    assert unsafe.status_code == 422


async def test_group_owner_ties_are_rejected_before_configuration(
    client: AsyncClient,
    admin_headers: dict[str, str],
    admin: User,
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    site, _, _ = await _inventory(db_session, organization)
    owner_id = str(admin.id)
    first = await client.post(
        "/api/v1/asset-groups",
        json={
            "name": "Owner A",
            "group_type": "static",
            "site_id": str(site.id),
            "priority": 50,
            "owner_user_id": owner_id,
        },
        headers=admin_headers,
    )
    assert first.status_code == 201, first.text
    tied = await client.post(
        "/api/v1/asset-groups",
        json={
            "name": "Owner B",
            "group_type": "static",
            "site_id": str(site.id),
            "priority": 50,
            "owner_user_id": owner_id,
        },
        headers=admin_headers,
    )
    assert tied.status_code == 422
    assert "priority conflicts" in tied.json()["detail"]


async def test_ownership_precedence_and_history(
    db_session: AsyncSession,
    organization: Organization,
    make_user: UserFactory,
) -> None:
    explicit_finding_owner = await make_user(UserRole.REMEDIATION_OWNER)
    explicit_asset_owner = await make_user(UserRole.SECURITY_OPERATOR)
    group_owner = await make_user(UserRole.SECURITY_OPERATOR)
    site_owner = await make_user(UserRole.SECURITY_OPERATOR)
    department_owner = await make_user(UserRole.SECURITY_OPERATOR)
    site, asset, _ = await _inventory(db_session, organization)
    asset.department = "Finance"
    site.owner_user_id = site_owner.id
    department = DepartmentOwner(
        organization_id=organization.id,
        department="Finance",
        department_key="finance",
        owner_user_id=department_owner.id,
    )
    group = AssetGroup(
        organization_id=organization.id,
        site_id=site.id,
        name="Finance servers",
        group_type=AssetGroupType.STATIC,
        priority=25,
        owner_user_id=group_owner.id,
    )
    db_session.add_all([department, group])
    await db_session.flush()
    db_session.add(
        AssetGroupMembership(
            organization_id=organization.id,
            group_id=group.id,
            asset_id=asset.id,
            source=AssetMembershipSource.STATIC,
            explanation_json={"reason": "test"},
        )
    )
    finding = Finding(
        organization_id=organization.id,
        site_id=site.id,
        asset_id=asset.id,
        scanner_name="test",
        canonical_finding_key=uuid.uuid4().hex,
        finding_type=FindingType.VULNERABILITY,
        title="Test finding",
        severity=Severity.HIGH,
        owner_user_id=explicit_finding_owner.id,
    )
    db_session.add(finding)
    await db_session.flush()

    asset.owner_user_id = explicit_asset_owner.id
    result = await asset_context.resolve_ownership(db_session, asset, finding=finding)
    assert result.source == OwnershipSource.EXPLICIT_FINDING
    assert result.owner_user_id == explicit_finding_owner.id

    finding.owner_user_id = None
    result = await asset_context.resolve_ownership(db_session, asset, finding=finding)
    assert result.source == OwnershipSource.EXPLICIT_ASSET
    assert result.owner_user_id == explicit_asset_owner.id

    asset.owner_user_id = None
    result = await asset_context.resolve_ownership(db_session, asset)
    assert result.source == OwnershipSource.GROUP
    assert result.owner_user_id == group_owner.id
    assert await asset_context.record_ownership_snapshot(db_session, result) is not None
    assert await asset_context.record_ownership_snapshot(db_session, result) is None

    await db_session.delete(group)
    await db_session.flush()
    result = await asset_context.resolve_ownership(db_session, asset)
    assert result.source == OwnershipSource.SITE
    assert result.owner_user_id == site_owner.id

    site.owner_user_id = None
    result = await asset_context.resolve_ownership(db_session, asset)
    assert result.source == OwnershipSource.DEPARTMENT
    assert result.owner_user_id == department_owner.id

    await db_session.delete(department)
    await db_session.flush()
    result = await asset_context.resolve_ownership(db_session, asset)
    assert result.source == OwnershipSource.UNASSIGNED
    assert result.owner_user_id is None


async def test_asset_context_does_not_cross_organizations(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    foreign_org = Organization(name="Foreign", slug=f"foreign-{uuid.uuid4().hex[:8]}")
    db_session.add(foreign_org)
    await db_session.flush()
    foreign_site = Site(
        organization_id=foreign_org.id,
        name="Foreign",
        code="FOREIGN",
        timezone="UTC",
    )
    db_session.add(foreign_site)
    await db_session.flush()
    foreign_asset = Asset(
        organization_id=foreign_org.id,
        site_id=foreign_site.id,
        canonical_name="foreign-host",
        asset_type=AssetType.SERVER,
    )
    db_session.add(foreign_asset)
    await db_session.commit()

    ownership = await client.get(
        f"/api/v1/assets/{foreign_asset.id}/ownership", headers=admin_headers
    )
    assert ownership.status_code == 404
    filtered = await client.get(
        "/api/v1/assets", params={"q": "foreign-host"}, headers=admin_headers
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 0


async def test_asset_deletion_is_permissioned_scoped_idempotent_and_audited(
    client: AsyncClient,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
    db_session: AsyncSession,
    organization: Organization,
) -> None:
    site, first, second = await _inventory(db_session, organization)
    organization_id = organization.id
    first_id = first.id
    third = Asset(
        organization_id=organization.id,
        site_id=site.id,
        canonical_name="payments-worker",
        asset_type=AssetType.SERVER,
    )
    foreign_org = Organization(name="Foreign delete", slug=f"delete-{uuid.uuid4().hex[:8]}")
    db_session.add_all([third, foreign_org])
    await db_session.flush()
    foreign_site = Site(
        organization_id=foreign_org.id,
        name="Foreign delete",
        code=f"DELETE-{uuid.uuid4().hex[:6]}",
        timezone="UTC",
    )
    db_session.add(foreign_site)
    await db_session.flush()
    foreign_asset = Asset(
        organization_id=foreign_org.id,
        site_id=foreign_site.id,
        canonical_name="foreign-delete-target",
        asset_type=AssetType.SERVER,
    )
    db_session.add(foreign_asset)
    await db_session.commit()
    foreign_asset_id = foreign_asset.id

    denied = await client.delete(f"/api/v1/assets/{first.id}", headers=viewer_headers)
    assert denied.status_code == 403
    still_present = await client.get(f"/api/v1/assets/{first.id}", headers=admin_headers)
    assert still_present.status_code == 200

    deleted = await client.delete(f"/api/v1/assets/{first.id}", headers=admin_headers)
    assert deleted.status_code == 204
    missing = await client.get(f"/api/v1/assets/{first.id}", headers=admin_headers)
    assert missing.status_code == 404

    cross_org = await client.post(
        "/api/v1/assets/bulk-delete",
        json={"asset_ids": [str(second.id), str(foreign_asset.id)]},
        headers=admin_headers,
    )
    assert cross_org.status_code == 200
    assert cross_org.json() == {"deleted_assets": 1, "skipped_assets": 1}
    deleted_accessible = await client.get(f"/api/v1/assets/{second.id}", headers=admin_headers)
    assert deleted_accessible.status_code == 404

    bulk = await client.post(
        "/api/v1/assets/bulk-delete",
        json={"asset_ids": [str(second.id), str(third.id), str(second.id)]},
        headers=admin_headers,
    )
    assert bulk.status_code == 200, bulk.text
    assert bulk.json() == {"deleted_assets": 1, "skipped_assets": 1}

    remaining = await client.get("/api/v1/assets", headers=admin_headers)
    assert remaining.status_code == 200
    assert remaining.json()["total"] == 0

    db_session.expire_all()
    audits = list(
        (
            await db_session.execute(
                select(AuditEvent).where(
                    AuditEvent.organization_id == organization_id,
                    AuditEvent.action.in_(["asset.deleted", "asset.bulk_deleted"]),
                )
            )
        ).scalars()
    )
    assert {event.action for event in audits} == {"asset.deleted", "asset.bulk_deleted"}
    single_audit = next(event for event in audits if event.action == "asset.deleted")
    assert single_audit.target_id == str(first_id)
    assert single_audit.metadata_json["canonical_name"] == "payments-api"
    bulk_audits = [event for event in audits if event.action == "asset.bulk_deleted"]
    assert len(bulk_audits) == 2
    assert {
        (event.metadata_json["deleted_assets"], event.metadata_json["skipped_assets"])
        for event in bulk_audits
    } == {(1, 1)}
    assert all(
        str(foreign_asset_id) not in event.metadata_json["asset_ids"] for event in bulk_audits
    )


async def test_asset_management_requires_permission(
    client: AsyncClient, viewer_headers: dict[str, str]
) -> None:
    listing = await client.get("/api/v1/asset-tags", headers=viewer_headers)
    assert listing.status_code == 200
    denied = await client.post(
        "/api/v1/asset-tags", json={"name": "Forbidden"}, headers=viewer_headers
    )
    assert denied.status_code == 403


def test_rule_ast_is_bounded_and_never_accepts_expressions() -> None:
    with pytest.raises(asset_context.AssetContextError, match="Unsupported"):
        asset_context.validate_rule({"field": "__class__", "operator": "eq", "value": "anything"})
    with pytest.raises(asset_context.AssetContextError, match="Unsupported"):
        asset_context.validate_rule(
            {"field": "canonical_name", "operator": "eval", "value": "1 + 1"}
        )
    with pytest.raises(asset_context.AssetContextError, match="scalar JSON"):
        asset_context.validate_rule(
            {"field": "status", "operator": "in", "value": [{"nested": "value"}]}
        )
    with pytest.raises(asset_context.AssetContextError, match="limited"):
        asset_context.validate_rule(
            {
                "field": "canonical_name",
                "operator": "eq",
                "value": "x" * (asset_context.MAX_RULE_VALUE_LENGTH + 1),
            }
        )
    too_deep: dict[str, object] = {
        "field": "status",
        "operator": "eq",
        "value": "active",
    }
    for _ in range(asset_context.MAX_RULE_DEPTH + 1):
        too_deep = {"not": too_deep}
    with pytest.raises(asset_context.AssetContextError, match="depth"):
        asset_context.validate_rule(too_deep)


async def test_phase40_capability_is_available_but_not_production_ready(
    client: AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    response = await client.get("/api/v1/system/capabilities", headers=admin_headers)
    assert response.status_code == 200
    capability = next(
        value for value in response.json()["capabilities"] if value["key"] == "asset_groups"
    )
    assert capability == {
        "key": "asset_groups",
        "name": "Asset groups and ownership",
        "status": "available",
        "production_ready": False,
    }
    schema = (await client.get("/openapi.json")).json()
    for path in (
        "/api/v1/assets/bulk",
        "/api/v1/assets/{asset_id}/context",
        "/api/v1/assets/{asset_id}/ownership",
        "/api/v1/asset-tags",
        "/api/v1/asset-groups",
        "/api/v1/asset-groups/preview",
        "/api/v1/department-owners",
    ):
        assert path in schema["paths"]


async def test_legacy_tag_projection_updates_without_overwriting_metadata(
    db_session: AsyncSession, organization: Organization
) -> None:
    _, asset, _ = await _inventory(db_session, organization)
    asset.metadata_json = {"scanner": {"source": "nmap"}}
    tag = await asset_context.ensure_tag(db_session, organization.id, "Legacy-Compatible")
    _, created = await asset_context.assign_tag(
        db_session,
        asset,
        tag,
        source=AssetTagSource.MIGRATED,
        metadata={"legacy_value": "Legacy-Compatible"},
    )
    assert created is True
    assert asset.tags_json == ["Legacy-Compatible"]
    assert asset.metadata_json == {"scanner": {"source": "nmap"}}
    assignment = await db_session.scalar(
        select(AssetTagAssignment).where(AssetTagAssignment.asset_id == asset.id)
    )
    assert assignment is not None
    assert assignment.metadata_json == {"legacy_value": "Legacy-Compatible"}
