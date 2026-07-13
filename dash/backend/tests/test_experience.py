"""Phase 33 experience profiles: isolation, auditing, and presentation-only safety."""

from __future__ import annotations

import pytest
from app.auth.password import hash_password
from app.core.config import Settings
from app.models.audit import AuditEvent
from app.models.enums import ExperienceProfile, UserRole
from app.models.onboarding import OnboardingState
from app.models.organization import Organization
from app.models.user import User
from app.services.bootstrap import ensure_default_organization
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import auth_headers

pytestmark = pytest.mark.release_gate


async def test_capability_matrix_is_public_and_conservative(client: AsyncClient) -> None:
    response = await client.get("/api/v1/system/capabilities")
    assert response.status_code == 200
    body = response.json()
    assert body["production_ready"] is False
    assert {item["status"] for item in body["capabilities"]} == {
        "available",
        "planned",
    }
    assert all(item["production_ready"] is False for item in body["capabilities"])
    identity = next(
        item for item in body["capabilities"] if item["key"] == "identity_lifecycle"
    )
    assert identity["status"] == "available"


async def test_phase33_interfaces_are_in_openapi(client: AsyncClient) -> None:
    schema = (await client.get("/openapi.json")).json()
    for path in (
        "/api/v1/organizations/current/experience",
        "/api/v1/organizations/current/experience/preview",
        "/api/v1/onboarding/profile-plan",
        "/api/v1/system/capabilities",
    ):
        assert path in schema["paths"]


async def test_bootstrap_profile_seeds_only_a_new_organization(
    db_session: AsyncSession,
) -> None:
    seeded = await ensure_default_organization(
        db_session,
        Settings(default_org_slug="seeded-profile", deployment_profile="enterprise"),
    )
    assert seeded.experience_profile == ExperienceProfile.ENTERPRISE
    await db_session.commit()

    existing = await ensure_default_organization(
        db_session,
        Settings(default_org_slug="seeded-profile", deployment_profile="custom"),
    )
    assert existing.id == seeded.id
    assert existing.experience_profile == ExperienceProfile.ENTERPRISE


async def test_small_business_visibility_does_not_disable_routes(
    client: AsyncClient,
    viewer_headers: dict[str, str],
) -> None:
    response = await client.get(
        "/api/v1/organizations/current/experience", headers=viewer_headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["experience_profile"] == "small_business"
    assert body["route_visibility"]["assets"] is True
    assert body["route_visibility"]["pentest"] is False
    assert all(capability["production_ready"] is False for capability in body["capabilities"])

    # Hidden means absent from navigation only. The authenticated API remains
    # live and applies its ordinary role/scope authorization.
    direct = await client.get("/api/v1/feeds/health", headers=viewer_headers)
    assert direct.status_code != 404


async def test_profile_update_requires_admin_and_preserves_configuration(
    client: AsyncClient,
    db_session: AsyncSession,
    organization: Organization,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    organization.settings_json = {"privacy": {"telemetry": False}}
    organization.retention_policy_json = {"raw_artifact_days": 45}
    await db_session.commit()

    payload = {"experience_profile": "enterprise", "feature_overrides": {}}
    denied = await client.patch(
        "/api/v1/organizations/current/experience",
        json=payload,
        headers=viewer_headers,
    )
    assert denied.status_code == 403

    preview = await client.post(
        "/api/v1/organizations/current/experience/preview",
        json=payload,
        headers=admin_headers,
    )
    assert preview.status_code == 200
    assert "pentest" in preview.json()["changed_routes"]

    updated = await client.patch(
        "/api/v1/organizations/current/experience",
        json=payload,
        headers=admin_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["route_visibility"]["pentest"] is True

    await db_session.refresh(organization)
    assert organization.experience_profile == ExperienceProfile.ENTERPRISE
    assert organization.settings_json == {"privacy": {"telemetry": False}}
    assert organization.retention_policy_json == {"raw_artifact_days": 45}

    event = await db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "organization.experience_profile_updated"
        )
    )
    assert event is not None
    assert event.metadata_json["old_profile"] == "small_business"
    assert event.metadata_json["new_profile"] == "enterprise"


async def test_custom_overrides_are_allowlisted(
    client: AsyncClient,
    admin_headers: dict[str, str],
) -> None:
    valid = await client.patch(
        "/api/v1/organizations/current/experience",
        json={
            "experience_profile": "custom",
            "feature_overrides": {"pentest": False, "changes": False},
        },
        headers=admin_headers,
    )
    assert valid.status_code == 200
    assert valid.json()["route_visibility"]["pentest"] is False

    invalid = await client.post(
        "/api/v1/organizations/current/experience/preview",
        json={
            "experience_profile": "custom",
            "feature_overrides": {"disable_security": True},
        },
        headers=admin_headers,
    )
    assert invalid.status_code == 422


async def test_profile_plan_is_advisory_and_stored_per_profile(
    client: AsyncClient,
    db_session: AsyncSession,
    organization: Organization,
    admin_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    denied = await client.get("/api/v1/onboarding/profile-plan", headers=viewer_headers)
    assert denied.status_code == 403

    saved = await client.put(
        "/api/v1/onboarding/profile-plan",
        json={"answers": {"asset_count": 650, "ticketing": True}},
        headers=admin_headers,
    )
    assert saved.status_code == 200
    body = saved.json()
    assert any(item["status"] == "planned" for item in body["recommendations"])
    assert any(item["status"] == "available" for item in body["recommendations"])

    state = await db_session.scalar(
        select(OnboardingState).where(
            OnboardingState.organization_id == organization.id
        )
    )
    assert state is not None
    assert state.extra_json["profile_plans"]["small_business"]["answers"][
        "asset_count"
    ] == 650
    # Planning never applies a policy or feature configuration.
    await db_session.refresh(organization)
    assert organization.settings_json == {}
    assert organization.feature_overrides_json == {}


async def test_experience_is_organization_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    admin_headers: dict[str, str],
) -> None:
    other_org = Organization(
        name="Other Org",
        slug="other-org",
        experience_profile=ExperienceProfile.CUSTOM,
        feature_overrides_json={"pentest": False},
    )
    db_session.add(other_org)
    await db_session.flush()
    other_user = User(
        organization_id=other_org.id,
        email="other-admin@example.com",
        full_name="Other Admin",
        hashed_password=hash_password("other secure passphrase"),
        role=UserRole.ADMINISTRATOR,
        is_active=True,
    )
    db_session.add(other_user)
    await db_session.commit()

    changed = await client.patch(
        "/api/v1/organizations/current/experience",
        json={"experience_profile": "enterprise", "feature_overrides": {}},
        headers=admin_headers,
    )
    assert changed.status_code == 200

    isolated = await client.get(
        "/api/v1/organizations/current/experience", headers=auth_headers(other_user)
    )
    assert isolated.status_code == 200
    assert isolated.json()["experience_profile"] == "custom"
    assert isolated.json()["route_visibility"]["pentest"] is False
