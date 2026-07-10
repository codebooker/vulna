"""Authentication endpoint tests."""

from __future__ import annotations

from app.models.audit import AuditEvent
from app.models.enums import UserRole
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import TEST_PASSWORD, UserFactory, auth_headers


async def test_login_succeeds_with_valid_credentials(
    client: AsyncClient, make_user: UserFactory
) -> None:
    user = await make_user(UserRole.ADMINISTRATOR, email="admin@example.com")
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["expires_in"] > 0
    # The token authenticates against /me.
    me = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["email"] == "admin@example.com"
    assert me.json()["role"] == UserRole.ADMINISTRATOR.value
    assert user.id is not None


async def test_login_is_case_insensitive_on_email(
    client: AsyncClient, make_user: UserFactory
) -> None:
    await make_user(email="mixed@example.com")
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "MIXED@example.com", "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200


async def test_login_fails_with_wrong_password(
    client: AsyncClient, make_user: UserFactory
) -> None:
    await make_user(email="user@example.com")
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "wrong-password"},
    )
    assert resp.status_code == 401


async def test_login_fails_for_unknown_user(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "whatever-1234"},
    )
    assert resp.status_code == 401


async def test_inactive_user_cannot_login(
    client: AsyncClient, make_user: UserFactory
) -> None:
    await make_user(email="inactive@example.com", is_active=False)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "inactive@example.com", "password": TEST_PASSWORD},
    )
    assert resp.status_code == 401


async def test_me_requires_authentication(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


async def test_me_rejects_garbage_token(client: AsyncClient) -> None:
    resp = await client.get(
        "/api/v1/auth/me", headers={"Authorization": "Bearer not.a.jwt"}
    )
    assert resp.status_code == 401


async def test_deactivated_user_token_is_rejected(
    client: AsyncClient, make_user: UserFactory, db_session: AsyncSession
) -> None:
    user = await make_user(email="soon-inactive@example.com")
    headers = auth_headers(user)
    # Deactivate the user after the token was issued.
    user.is_active = False
    db_session.add(user)
    await db_session.commit()

    resp = await client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 401


async def test_login_records_audit_events(
    client: AsyncClient, make_user: UserFactory, db_session: AsyncSession
) -> None:
    await make_user(email="audited@example.com")
    await client.post(
        "/api/v1/auth/login",
        json={"email": "audited@example.com", "password": TEST_PASSWORD},
    )
    await client.post(
        "/api/v1/auth/login",
        json={"email": "audited@example.com", "password": "nope"},
    )
    result = await db_session.execute(select(AuditEvent.action))
    actions = {row[0] for row in result.all()}
    assert "auth.login_succeeded" in actions
    assert "auth.login_failed" in actions
