"""Authorization (RBAC) negative tests.

Acceptance criterion: unauthorized users receive 403. Unauthenticated users
receive 401.
"""

from __future__ import annotations

import pytest

# Release-blocking: security-critical regression (Phase 32).
pytestmark = pytest.mark.release_gate

import pytest
from app.models.enums import UserRole
from httpx import AsyncClient

from tests.conftest import UserFactory, auth_headers

# Endpoints that require the Administrator role for mutation.
_ADMIN_ONLY_CREATE = [
    ("/api/v1/sites", {"name": "S", "code": "S1"}),
    ("/api/v1/users", {"email": "x@example.com", "password": "abcdefghijkl"}),
]


@pytest.mark.parametrize("path,payload", _ADMIN_ONLY_CREATE)
async def test_non_admin_cannot_create(
    client: AsyncClient, make_user: UserFactory, path: str, payload: dict[str, object]
) -> None:
    operator = await make_user(UserRole.SECURITY_OPERATOR)
    resp = await client.post(path, json=payload, headers=auth_headers(operator))
    assert resp.status_code == 403


@pytest.mark.parametrize("path,payload", _ADMIN_ONLY_CREATE)
async def test_unauthenticated_cannot_create(
    client: AsyncClient, path: str, payload: dict[str, object]
) -> None:
    resp = await client.post(path, json=payload)
    assert resp.status_code == 401


async def test_viewer_can_read_sites(
    client: AsyncClient, make_user: UserFactory
) -> None:
    viewer = await make_user(UserRole.VIEWER)
    resp = await client.get("/api/v1/sites", headers=auth_headers(viewer))
    assert resp.status_code == 200


async def test_operator_cannot_create_scope(
    client: AsyncClient, make_user: UserFactory
) -> None:
    operator = await make_user(UserRole.SECURITY_OPERATOR)
    resp = await client.post(
        "/api/v1/scopes",
        json={
            "site_id": "00000000-0000-0000-0000-000000000000",
            "name": "n",
            "cidr": "10.0.0.0/24",
        },
        headers=auth_headers(operator),
    )
    assert resp.status_code == 403


async def test_viewer_cannot_read_audit_log(
    client: AsyncClient, make_user: UserFactory
) -> None:
    viewer = await make_user(UserRole.VIEWER)
    resp = await client.get("/api/v1/audit", headers=auth_headers(viewer))
    assert resp.status_code == 403


async def test_auditor_can_read_audit_log(
    client: AsyncClient, make_user: UserFactory
) -> None:
    auditor = await make_user(UserRole.AUDITOR)
    resp = await client.get("/api/v1/audit", headers=auth_headers(auditor))
    assert resp.status_code == 200
