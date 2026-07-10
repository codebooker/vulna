"""Network-scope API tests: CRUD, validation, overlap, approval, and audit."""

from __future__ import annotations

from app.models.audit import AuditEvent
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def _create_site(client: AsyncClient, headers: dict[str, str], code: str = "S1") -> str:
    resp = await client.post(
        "/api/v1/sites", json={"name": "Site", "code": code}, headers=headers
    )
    assert resp.status_code == 201
    return resp.json()["id"]


async def test_create_scope_normalizes_and_audits(
    client: AsyncClient, admin_headers: dict[str, str], db_session: AsyncSession
) -> None:
    site_id = await _create_site(client, admin_headers)
    resp = await client.post(
        "/api/v1/scopes",
        json={"site_id": site_id, "name": "LAN", "cidr": "10.20.0.5/24"},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    scope = resp.json()
    assert scope["cidr"] == "10.20.0.0/24"  # host bits normalized away
    assert scope["policy_version"] == 1

    result = await db_session.execute(
        select(AuditEvent.action).where(AuditEvent.action == "scope.created")
    )
    assert result.first() is not None


async def test_create_scope_rejects_default_route(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    site_id = await _create_site(client, admin_headers)
    resp = await client.post(
        "/api/v1/scopes",
        json={"site_id": site_id, "name": "all", "cidr": "0.0.0.0/0"},
        headers=admin_headers,
    )
    assert resp.status_code == 422


async def test_create_scope_denies_public_by_default(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    site_id = await _create_site(client, admin_headers)
    resp = await client.post(
        "/api/v1/scopes",
        json={"site_id": site_id, "name": "pub", "cidr": "8.8.8.0/24"},
        headers=admin_headers,
    )
    assert resp.status_code == 422


async def test_create_scope_allows_public_when_opted_in(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    site_id = await _create_site(client, admin_headers)
    resp = await client.post(
        "/api/v1/scopes",
        json={
            "site_id": site_id,
            "name": "pub",
            "cidr": "8.8.8.0/24",
            "allow_public_addresses": True,
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201


async def test_overlapping_scope_is_rejected(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    site_id = await _create_site(client, admin_headers)
    first = await client.post(
        "/api/v1/scopes",
        json={"site_id": site_id, "name": "big", "cidr": "10.0.0.0/16"},
        headers=admin_headers,
    )
    assert first.status_code == 201
    overlap = await client.post(
        "/api/v1/scopes",
        json={"site_id": site_id, "name": "small", "cidr": "10.0.1.0/24"},
        headers=admin_headers,
    )
    assert overlap.status_code == 409


async def test_scope_for_missing_site_returns_404(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    resp = await client.post(
        "/api/v1/scopes",
        json={
            "site_id": "00000000-0000-0000-0000-000000000000",
            "name": "x",
            "cidr": "10.0.0.0/24",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 404


async def test_update_scope_bumps_policy_version_and_audits(
    client: AsyncClient, admin_headers: dict[str, str], db_session: AsyncSession
) -> None:
    site_id = await _create_site(client, admin_headers)
    created = await client.post(
        "/api/v1/scopes",
        json={"site_id": site_id, "name": "LAN", "cidr": "10.20.0.0/24"},
        headers=admin_headers,
    )
    scope_id = created.json()["id"]

    updated = await client.patch(
        f"/api/v1/scopes/{scope_id}",
        json={"cidr": "10.21.0.0/24"},
        headers=admin_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["cidr"] == "10.21.0.0/24"
    assert updated.json()["policy_version"] == 2

    result = await db_session.execute(
        select(AuditEvent.action).where(AuditEvent.action == "scope.updated")
    )
    assert result.first() is not None


async def test_approve_scope_records_approver(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    site_id = await _create_site(client, admin_headers)
    created = await client.post(
        "/api/v1/scopes",
        json={"site_id": site_id, "name": "LAN", "cidr": "10.20.0.0/24"},
        headers=admin_headers,
    )
    scope_id = created.json()["id"]
    approved = await client.post(f"/api/v1/scopes/{scope_id}/approve", headers=admin_headers)
    assert approved.status_code == 200
    assert approved.json()["approved_by"] is not None
    assert approved.json()["approved_at"] is not None


async def test_delete_scope(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    site_id = await _create_site(client, admin_headers)
    created = await client.post(
        "/api/v1/scopes",
        json={"site_id": site_id, "name": "LAN", "cidr": "10.20.0.0/24"},
        headers=admin_headers,
    )
    scope_id = created.json()["id"]
    deleted = await client.delete(f"/api/v1/scopes/{scope_id}", headers=admin_headers)
    assert deleted.status_code == 204
    gone = await client.get(f"/api/v1/scopes/{scope_id}", headers=admin_headers)
    assert gone.status_code == 404
