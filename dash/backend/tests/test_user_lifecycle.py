"""Phase 34 user lifecycle, token, isolation, and site-scope acceptance tests."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs

import pytest
from app.auth.password import verify_password
from app.core.config import get_settings
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.enums import AccountStatus, SiteAccessMode, UserRole
from app.models.organization import Organization
from app.models.site import Site
from app.models.user import User
from app.models.user_lifecycle import (
    PasswordResetToken,
    UserInvitation,
    UserLifecycleEvent,
    UserSiteAssignment,
)
from app.services.account_tokens import AccountTokenPurpose, hash_account_token
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import TEST_PASSWORD, UserFactory, auth_headers

pytestmark = pytest.mark.release_gate


def test_account_token_purposes_have_distinct_hkdf_contexts() -> None:
    master = get_settings().require_secret_key()
    secret = "vui_shared-secret-material-for-context-test"
    invitation_hash = hash_account_token(
        secret, master_secret=master, purpose=AccountTokenPurpose.INVITATION
    )
    reset_hash = hash_account_token(
        secret, master_secret=master, purpose=AccountTokenPurpose.PASSWORD_RESET
    )
    assert invitation_hash != reset_hash


def _secret_from_link(link: str) -> str:
    fragment = link.split("#", maxsplit=1)[1]
    query = fragment.split("?", maxsplit=1)[1]
    return parse_qs(query)["token"][0]


async def test_phase34_interfaces_are_in_openapi(client: AsyncClient) -> None:
    paths = (await client.get("/openapi.json")).json()["paths"]
    for path in (
        "/api/v1/users",
        "/api/v1/users/{user_id}",
        "/api/v1/users/{user_id}/status",
        "/api/v1/users/{user_id}/site-access",
        "/api/v1/users/{user_id}/invitation",
        "/api/v1/users/{user_id}/password-reset",
        "/api/v1/users/{user_id}/lifecycle",
        "/api/v1/users/{user_id}/login-history",
        "/api/v1/auth/invitations/accept",
        "/api/v1/auth/password-resets/complete",
    ):
        assert path in paths


async def _site(
    client: AsyncClient, headers: dict[str, str], name: str, code: str
) -> dict[str, str]:
    response = await client.post(
        "/api/v1/sites", json={"name": name, "code": code}, headers=headers
    )
    assert response.status_code == 201
    return response.json()


async def test_invitation_is_hashed_single_use_and_user_sets_the_password(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    site = await _site(client, admin_headers, "North", "NORTH")
    created = await client.post(
        "/api/v1/users",
        json={
            "email": " Invitee@Example.com ",
            "full_name": "Invitee",
            "role": "viewer",
            "site_access_mode": "assigned",
            "site_ids": [site["id"]],
        },
        headers=admin_headers,
    )
    assert created.status_code == 201
    body = created.json()
    assert body["email"] == "invitee@example.com"
    assert body["account_status"] == "invited"
    assert body["is_active"] is False
    assert body["site_ids"] == [site["id"]]
    secret = _secret_from_link(body["invitation_url"])

    user = await db_session.scalar(select(User).where(User.email == "invitee@example.com"))
    assert user is not None and user.hashed_password is None
    invitation = await db_session.scalar(
        select(UserInvitation).where(UserInvitation.user_id == user.id)
    )
    assert invitation is not None
    assert invitation.token_hash != secret
    assert secret not in json.dumps(invitation.__dict__, default=str)

    denied = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "not-yet-a-password"},
    )
    assert denied.status_code == 401

    accepted = await client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": secret, "password": "new secure invitation passphrase"},
    )
    assert accepted.status_code == 200
    assert accepted.json() == {"status": "accepted"}
    reused = await client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": secret, "password": "another secure passphrase"},
    )
    assert reused.status_code == 400

    await db_session.refresh(user)
    await db_session.refresh(invitation)
    assert user.account_status == AccountStatus.ACTIVE
    assert user.is_active is True
    assert verify_password("new secure invitation passphrase", user.hashed_password)
    assert invitation.consumed_at is not None
    login = await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "new secure invitation passphrase"},
    )
    assert login.status_code == 200

    listed = await client.get("/api/v1/users", headers=admin_headers)
    serialized = json.dumps(listed.json()).lower()
    assert secret.lower() not in serialized
    assert "token_hash" not in serialized
    assert "hashed_password" not in serialized


async def test_admin_permanent_password_creation_is_refused(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    response = await client.post(
        "/api/v1/users",
        json={"email": "legacy@example.com", "password": "abcdefghijkl"},
        headers=admin_headers,
    )
    assert response.status_code == 422
    assert "cannot assign permanent passwords" in response.json()["detail"]


async def test_expired_invitation_is_rejected_and_reissue_replaces_it(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    created = await client.post(
        "/api/v1/users",
        json={"email": "expired-invite@example.com"},
        headers=admin_headers,
    )
    user_id = created.json()["id"]
    original_secret = _secret_from_link(created.json()["invitation_url"])
    original = await db_session.scalar(
        select(UserInvitation).where(UserInvitation.user_id == uuid.UUID(user_id))
    )
    assert original is not None
    original.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()

    expired = await client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": original_secret, "password": "expired secure passphrase"},
    )
    assert expired.status_code == 400

    replacement = await client.post(
        f"/api/v1/users/{user_id}/invitation", headers=admin_headers
    )
    assert replacement.status_code == 200
    replacement_secret = _secret_from_link(replacement.json()["invitation_url"])
    assert replacement_secret != original_secret
    await db_session.refresh(original)
    assert original.revoked_at is not None
    accepted = await client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": replacement_secret, "password": "replacement secure passphrase"},
    )
    assert accepted.status_code == 200


async def test_password_reset_rotates_auth_version_and_is_single_use(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="reset@example.com")
    old_headers = auth_headers(user)
    issued = await client.post(
        f"/api/v1/users/{user.id}/password-reset", headers=admin_headers
    )
    assert issued.status_code == 200
    secret = _secret_from_link(issued.json()["reset_url"])
    stored = await db_session.scalar(
        select(PasswordResetToken).where(PasswordResetToken.user_id == user.id)
    )
    assert stored is not None and stored.token_hash != secret

    complete = await client.post(
        "/api/v1/auth/password-resets/complete",
        json={"token": secret, "password": "replacement secure passphrase"},
    )
    assert complete.status_code == 200
    assert (
        await client.post(
            "/api/v1/auth/password-resets/complete",
            json={"token": secret, "password": "another secure passphrase"},
        )
    ).status_code == 400
    assert (await client.get("/api/v1/auth/me", headers=old_headers)).status_code == 401
    assert (
        await client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": TEST_PASSWORD},
        )
    ).status_code == 401
    assert (
        await client.post(
            "/api/v1/auth/login",
            json={"email": user.email, "password": "replacement secure passphrase"},
        )
    ).status_code == 200


async def test_deactivation_is_soft_immediate_and_revokes_available_credentials(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="retain@example.com")
    user.recovery_codes_json = ["opaque-hash"]
    await db_session.commit()
    access = auth_headers(user)
    reset = await client.post(
        f"/api/v1/users/{user.id}/password-reset", headers=admin_headers
    )
    reset_secret = _secret_from_link(reset.json()["reset_url"])

    deleted = await client.delete(f"/api/v1/users/{user.id}", headers=admin_headers)
    assert deleted.status_code == 204
    assert (await client.get("/api/v1/auth/me", headers=access)).status_code == 401
    await db_session.refresh(user)
    assert user.account_status == AccountStatus.DEACTIVATED
    assert user.is_active is False
    assert user.recovery_codes_json == []
    assert await db_session.get(User, user.id) is user
    stored_reset = await db_session.scalar(
        select(PasswordResetToken).where(PasswordResetToken.user_id == user.id)
    )
    assert stored_reset is not None and stored_reset.revoked_at is not None
    assert (
        await client.post(
            "/api/v1/auth/password-resets/complete",
            json={"token": reset_secret, "password": "unused secure passphrase"},
        )
    ).status_code == 400


async def test_self_deactivation_and_self_role_change_are_refused(
    client: AsyncClient, admin: User, admin_headers: dict[str, str]
) -> None:
    status_response = await client.put(
        f"/api/v1/users/{admin.id}/status",
        json={"status": "deactivated", "reason": "unsafe"},
        headers=admin_headers,
    )
    assert status_response.status_code == 400
    role_response = await client.patch(
        f"/api/v1/users/{admin.id}",
        json={"role": "viewer"},
        headers=admin_headers,
    )
    assert role_response.status_code == 400


async def test_role_and_site_access_changes_revoke_existing_tokens(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    site = await _site(client, admin_headers, "Scoped", "SCOPED")
    user = await make_user(email="access-version@example.com")
    before_role_change = auth_headers(user)
    changed_role = await client.patch(
        f"/api/v1/users/{user.id}",
        json={"role": "security_operator"},
        headers=admin_headers,
    )
    assert changed_role.status_code == 200
    assert (await client.get("/api/v1/auth/me", headers=before_role_change)).status_code == 401

    await db_session.refresh(user)
    before_site_change = auth_headers(user)
    changed_sites = await client.put(
        f"/api/v1/users/{user.id}/site-access",
        json={
            "mode": "assigned",
            "site_ids": [site["id"]],
            "reason": "limit to operating site",
        },
        headers=admin_headers,
    )
    assert changed_sites.status_code == 200
    assert (await client.get("/api/v1/auth/me", headers=before_site_change)).status_code == 401


async def test_assigned_site_scope_filters_list_detail_search_and_dashboard(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    north = await _site(client, admin_headers, "North", "N")
    south = await _site(client, admin_headers, "South", "S")
    viewer = await make_user(email="scoped@example.com")
    viewer.site_access_mode = SiteAccessMode.ASSIGNED
    db_session.add(
        UserSiteAssignment(
            organization_id=viewer.organization_id,
            user_id=viewer.id,
            site_id=uuid.UUID(north["id"]),
            assigned_by_user_id=None,
        )
    )
    db_session.add_all(
        [
            Asset(
                organization_id=viewer.organization_id,
                site_id=uuid.UUID(north["id"]),
                canonical_name="north-server",
            ),
            Asset(
                organization_id=viewer.organization_id,
                site_id=uuid.UUID(south["id"]),
                canonical_name="south-server",
            ),
        ]
    )
    await db_session.commit()
    headers = auth_headers(viewer)

    sites = (await client.get("/api/v1/sites", headers=headers)).json()["items"]
    assert [site["id"] for site in sites] == [north["id"]]
    assert (
        await client.get(f"/api/v1/sites/{south['id']}", headers=headers)
    ).status_code == 404
    assets = (await client.get("/api/v1/assets?limit=200", headers=headers)).json()[
        "items"
    ]
    assert [asset["canonical_name"] for asset in assets] == ["north-server"]
    search = (await client.get("/api/v1/search?q=server", headers=headers)).json()
    assert [asset["label"] for asset in search["assets"]] == ["north-server"]
    summary = (await client.get("/api/v1/dashboard/summary", headers=headers)).json()
    assert summary["unassessed"]["stale_assets"] == 1


async def test_site_assignment_rejects_foreign_site_without_losing_existing_scope(
    client: AsyncClient,
    admin: User,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    owned = await _site(client, admin_headers, "Owned", "OWN")
    viewer = await make_user(email="assignment@example.com")
    viewer.site_access_mode = SiteAccessMode.ASSIGNED
    original = UserSiteAssignment(
        organization_id=admin.organization_id,
        user_id=viewer.id,
        site_id=uuid.UUID(owned["id"]),
        assigned_by_user_id=admin.id,
    )
    foreign_org = Organization(name="Foreign", slug="foreign-sites")
    db_session.add(foreign_org)
    await db_session.flush()
    foreign = Site(organization_id=foreign_org.id, name="Foreign", code="F")
    db_session.add_all([original, foreign])
    await db_session.commit()

    response = await client.put(
        f"/api/v1/users/{viewer.id}/site-access",
        json={"mode": "assigned", "site_ids": [str(foreign.id)]},
        headers=admin_headers,
    )
    assert response.status_code == 422
    assignments = list(
        (
            await db_session.execute(
                select(UserSiteAssignment).where(UserSiteAssignment.user_id == viewer.id)
            )
        ).scalars()
    )
    assert [assignment.site_id for assignment in assignments] == [uuid.UUID(owned["id"])]


async def test_foreign_user_records_are_non_disclosing(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    foreign_org = Organization(name="Foreign users", slug="foreign-users")
    db_session.add(foreign_org)
    await db_session.flush()
    foreign_user = User(
        organization_id=foreign_org.id,
        email="foreign@example.com",
        hashed_password=None,
        role=UserRole.VIEWER,
        is_active=False,
        account_status=AccountStatus.INVITED,
    )
    db_session.add(foreign_user)
    await db_session.commit()

    for suffix in ("", "/lifecycle", "/login-history"):
        response = await client.get(
            f"/api/v1/users/{foreign_user.id}{suffix}", headers=admin_headers
        )
        assert response.status_code == 404


async def test_lifecycle_and_login_history_are_org_scoped_and_audited(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="history@example.com")
    await client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": TEST_PASSWORD},
    )
    await client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": "wrong"}
    )
    changed = await client.put(
        f"/api/v1/users/{user.id}/status",
        json={"status": "suspended", "reason": "investigation"},
        headers=admin_headers,
    )
    assert changed.status_code == 200
    lifecycle = await client.get(
        f"/api/v1/users/{user.id}/lifecycle", headers=admin_headers
    )
    assert lifecycle.status_code == 200
    assert lifecycle.json()["items"][0]["event_type"] == "user.suspended"
    logins = await client.get(
        f"/api/v1/users/{user.id}/login-history", headers=admin_headers
    )
    assert {item["outcome"] for item in logins.json()["items"]} == {
        "succeeded",
        "failed",
    }
    actions = set((await db_session.execute(select(AuditEvent.action))).scalars())
    assert "user.suspended" in actions
    events = list(
        (
            await db_session.execute(
                select(UserLifecycleEvent).where(UserLifecycleEvent.user_id == user.id)
            )
        ).scalars()
    )
    assert events and events[-1].reason == "investigation"
