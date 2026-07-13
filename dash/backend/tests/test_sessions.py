"""Phase 35 revocable session and rotating refresh-token acceptance tests."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.api.v1.auth import _set_refresh_cookie
from app.auth.dependencies import get_authenticated_identity
from app.auth.tokens import create_access_token, decode_access_token
from app.core.config import Settings, get_settings
from app.models.audit import AuditEvent
from app.models.enums import AccountStatus, UserRole
from app.models.organization import Organization
from app.models.session import SessionRefreshToken, UserSession
from app.models.user import User
from app.services.account_tokens import AccountTokenPurpose, hash_account_token
from app.services.sessions import REFRESH_COOKIE_NAME
from fastapi import HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import TEST_PASSWORD, UserFactory

pytestmark = pytest.mark.release_gate


async def _login(
    client: AsyncClient,
    user: User,
    *,
    trust_device: bool = False,
    device_name: str = "Test browser",
) -> tuple[str, str]:
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": user.email,
            "password": TEST_PASSWORD,
            "trust_device": trust_device,
            "device_name": device_name,
        },
        headers={"User-Agent": "Phase35Test/1.0"},
    )
    assert response.status_code == 200
    assert response.json()["expires_in"] == 15 * 60
    access = response.json()["access_token"]
    refresh = client.cookies.get(REFRESH_COOKIE_NAME)
    assert refresh is not None
    return access, refresh


async def test_login_creates_hashed_server_session_and_secure_cookie_metadata(
    client: AsyncClient,
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="session-login@example.com")
    access, refresh = await _login(client, user, trust_device=True)
    claims = decode_access_token(get_settings(), access)
    assert claims["sid"]
    assert claims["ver"] == user.auth_version
    assert claims["exp"] - claims["iat"] == 15 * 60

    stored_session = await db_session.get(UserSession, uuid.UUID(claims["sid"]))
    assert stored_session is not None
    assert stored_session.device_name == "Test browser"
    assert stored_session.user_agent == "Phase35Test/1.0"
    assert stored_session.source_ip == "127.0.0.1"
    assert stored_session.trusted_until is not None
    assert aware_delta(stored_session.trusted_until, stored_session.authenticated_at).days == 30
    stored_token = await db_session.scalar(
        select(SessionRefreshToken).where(
            SessionRefreshToken.session_id == stored_session.id
        )
    )
    assert stored_token is not None
    assert stored_token.token_hash != refresh
    assert refresh not in json.dumps(stored_token.__dict__, default=str)
    expected = hash_account_token(
        refresh,
        master_secret=get_settings().require_secret_key(),
        purpose=AccountTokenPurpose.SESSION_REFRESH,
    )
    assert stored_token.token_hash == expected


def aware_delta(later: datetime, earlier: datetime) -> timedelta:
    if later.tzinfo is None:
        later = later.replace(tzinfo=UTC)
    if earlier.tzinfo is None:
        earlier = earlier.replace(tzinfo=UTC)
    return later - earlier


def test_refresh_cookie_flags_are_environment_appropriate() -> None:
    expires = datetime.now(UTC) + timedelta(days=1)
    production = Response()
    _set_refresh_cookie(
        production,
        Settings(env="production", secret_key="production-test-secret"),
        "vsr_secret",
        expires,
    )
    header = production.headers["set-cookie"].lower()
    assert "httponly" in header and "samesite=lax" in header and "secure" in header

    development = Response()
    _set_refresh_cookie(
        development,
        Settings(env="development", secret_key="development-test-secret"),
        "vsr_secret",
        expires,
    )
    assert "secure" not in development.headers["set-cookie"].lower()


async def test_refresh_rotates_once_and_reuse_revokes_the_entire_family(
    client: AsyncClient,
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="rotation@example.com")
    _, first_refresh = await _login(client, user)
    rotated = await client.post("/api/v1/auth/refresh")
    assert rotated.status_code == 200
    rotated_access = rotated.json()["access_token"]
    second_refresh = client.cookies.get(REFRESH_COOKIE_NAME)
    assert second_refresh and second_refresh != first_refresh

    tokens = list(
        (
            await db_session.execute(
                select(SessionRefreshToken).order_by(SessionRefreshToken.created_at)
            )
        ).scalars()
    )
    assert len(tokens) == 2
    assert tokens[0].used_at is not None
    assert tokens[0].replaced_by_token_id == tokens[1].id

    client.cookies.clear()
    client.cookies.set(REFRESH_COOKIE_NAME, first_refresh, path="/api/v1/auth")
    replay = await client.post("/api/v1/auth/refresh")
    assert replay.status_code == 401
    assert "max-age=0" in replay.headers["set-cookie"].lower()
    stored_session = await db_session.get(UserSession, tokens[0].session_id)
    assert stored_session is not None
    await db_session.refresh(stored_session)
    assert stored_session.revoked_at is not None
    assert stored_session.revocation_reason == "refresh token reuse detected"
    assert (
        await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {rotated_access}"},
        )
    ).status_code == 401
    reuse_audit = await db_session.scalar(
        select(AuditEvent).where(AuditEvent.action == "auth.refresh_reuse_detected")
    )
    assert reuse_audit is not None


async def test_idle_and_absolute_expiry_stop_access_immediately(
    client: AsyncClient,
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="expiry@example.com")
    access, _ = await _login(client, user)
    claims = decode_access_token(get_settings(), access)
    stored = await db_session.get(UserSession, uuid.UUID(claims["sid"]))
    assert stored is not None
    stored.idle_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()
    assert (
        await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}
        )
    ).status_code == 401
    refresh = await client.post("/api/v1/auth/refresh")
    assert refresh.status_code == 401
    await db_session.refresh(stored)
    assert stored.revoked_at is not None


async def test_runtime_rejects_legacy_stateless_access_tokens(
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="legacy-session-token@example.com")
    production = Settings(
        env="production",
        secret_key="phase35-production-test-secret-long-enough",
    )
    legacy = create_access_token(
        production,
        user_id=user.id,
        role=user.role.value,
        organization_id=user.organization_id,
        auth_version=user.auth_version,
    )
    with pytest.raises(HTTPException) as denied:
        await get_authenticated_identity(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=legacy),
            db_session,
            production,
        )
    assert denied.value.status_code == 401


async def test_logout_and_logout_all_revoke_server_state_and_clear_cookie(
    client: AsyncClient,
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="logout-sessions@example.com")
    first_access, _ = await _login(client, user, device_name="First")
    first_logout = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {first_access}"},
    )
    assert first_logout.status_code == 204
    assert "max-age=0" in first_logout.headers["set-cookie"].lower()
    assert (
        await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {first_access}"},
        )
    ).status_code == 401

    second_access, _ = await _login(client, user, device_name="Second")
    third_access, _ = await _login(client, user, device_name="Third")
    all_logout = await client.post(
        "/api/v1/auth/logout-all",
        headers={"Authorization": f"Bearer {third_access}"},
    )
    assert all_logout.status_code == 204
    for access in (second_access, third_access):
        assert (
            await client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {access}"},
            )
        ).status_code == 401
    rows = list(
        (
            await db_session.execute(
                select(UserSession).where(UserSession.user_id == user.id)
            )
        ).scalars()
    )
    assert rows and all(row.revoked_at is not None for row in rows)


async def test_user_and_administrator_can_revoke_sessions_immediately(
    client: AsyncClient,
    make_user: UserFactory,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="revoke-device@example.com")
    access, _ = await _login(client, user)
    headers = {"Authorization": f"Bearer {access}"}
    sessions = await client.get("/api/v1/auth/sessions", headers=headers)
    assert sessions.status_code == 200
    session_id = sessions.json()[0]["id"]
    assert sessions.json()[0]["current"] is True
    assert sessions.json()[0]["active"] is True

    listed_by_admin = await client.get(
        f"/api/v1/users/{user.id}/sessions", headers=admin_headers
    )
    assert listed_by_admin.status_code == 200
    revoked = await client.delete(
        f"/api/v1/users/{user.id}/sessions/{session_id}?reason=incident",
        headers=admin_headers,
    )
    assert revoked.status_code == 204
    assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401
    stored = await db_session.get(UserSession, uuid.UUID(session_id))
    assert stored is not None and stored.revocation_reason == "incident"


async def test_concurrent_limit_revokes_oldest_session(
    client: AsyncClient,
    make_user: UserFactory,
    organization: Organization,
    db_session: AsyncSession,
) -> None:
    organization.settings_json = {"session_policy": {"max_concurrent_sessions": 2}}
    user = await make_user(email="limit@example.com")
    accesses: list[str] = []
    for device in ("First", "Second", "Third"):
        access, _ = await _login(client, user, device_name=device)
        accesses.append(access)
    sessions = list(
        (
            await db_session.execute(
                select(UserSession)
                .where(UserSession.user_id == user.id)
                .order_by(UserSession.created_at)
            )
        ).scalars()
    )
    assert len(sessions) == 3
    assert sessions[0].revocation_reason == "concurrent session limit"
    assert (
        await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {accesses[0]}"},
        )
    ).status_code == 401
    assert (
        await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {accesses[-1]}"},
        )
    ).status_code == 200


async def test_reauthentication_and_policy_are_configurable_and_audited(
    client: AsyncClient,
    admin: User,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    defaults = await client.get(
        "/api/v1/organizations/current/session-policy", headers=admin_headers
    )
    assert defaults.json() == {
        "idle_timeout_hours": 12,
        "absolute_lifetime_days": 30,
        "privileged_window_minutes": 15,
        "max_concurrent_sessions": 10,
        "trusted_device_days": 30,
    }
    updated = await client.patch(
        "/api/v1/organizations/current/session-policy",
        json={"privileged_window_minutes": 20, "max_concurrent_sessions": 3},
        headers=admin_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["privileged_window_minutes"] == 20

    access, _ = await _login(client, admin)
    reauth = await client.post(
        "/api/v1/auth/reauthenticate",
        json={"password": TEST_PASSWORD},
        headers={"Authorization": f"Bearer {access}"},
    )
    assert reauth.status_code == 200
    start = datetime.fromisoformat(reauth.json()["authenticated_at"])
    end = datetime.fromisoformat(reauth.json()["privileged_until"])
    assert end - start == timedelta(minutes=20)
    event = await db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "organization.session_policy_updated"
        )
    )
    assert event is not None
    assert event.metadata_json["old"]["privileged_window_minutes"] == 15
    reauth_event = await db_session.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "auth.reauthentication_succeeded"
        )
    )
    assert reauth_event is not None


async def test_role_change_revokes_real_server_session(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    db_session: AsyncSession,
) -> None:
    user = await make_user(email="session-role-change@example.com")
    access, _ = await _login(client, user)
    changed = await client.patch(
        f"/api/v1/users/{user.id}",
        json={"role": "security_operator"},
        headers=admin_headers,
    )
    assert changed.status_code == 200
    assert (
        await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}
        )
    ).status_code == 401
    session_row = await db_session.scalar(
        select(UserSession).where(UserSession.user_id == user.id)
    )
    assert session_row is not None and session_row.revocation_reason == "role changed"


async def test_foreign_admin_cannot_inspect_or_revoke_sessions(
    client: AsyncClient,
    admin_headers: dict[str, str],
    db_session: AsyncSession,
) -> None:
    foreign_org = Organization(name="Session foreign", slug="session-foreign")
    db_session.add(foreign_org)
    await db_session.flush()
    foreign_user = User(
        organization_id=foreign_org.id,
        email="foreign-session@example.com",
        hashed_password=None,
        role=UserRole.VIEWER,
        is_active=False,
        account_status=AccountStatus.INVITED,
    )
    db_session.add(foreign_user)
    await db_session.commit()
    assert (
        await client.get(
            f"/api/v1/users/{foreign_user.id}/sessions", headers=admin_headers
        )
    ).status_code == 404


async def test_phase35_interfaces_are_in_openapi(client: AsyncClient) -> None:
    paths = (await client.get("/openapi.json")).json()["paths"]
    for path in (
        "/api/v1/auth/refresh",
        "/api/v1/auth/logout",
        "/api/v1/auth/logout-all",
        "/api/v1/auth/sessions",
        "/api/v1/auth/sessions/{session_id}",
        "/api/v1/auth/reauthenticate",
        "/api/v1/users/{user_id}/sessions",
        "/api/v1/users/{user_id}/sessions/{session_id}",
        "/api/v1/organizations/current/session-policy",
    ):
        assert path in paths
