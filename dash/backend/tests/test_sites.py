"""Site CRUD tests, including audit-event creation."""

from __future__ import annotations

from app.models.audit import AuditEvent
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


async def test_site_crud_lifecycle(
    client: AsyncClient, admin_headers: dict[str, str], db_session: AsyncSession
) -> None:
    # Create
    resp = await client.post(
        "/api/v1/sites",
        json={"name": "HQ", "code": "HQ", "tags": ["primary"]},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    site = resp.json()
    site_id = site["id"]
    assert site["name"] == "HQ"
    assert site["tags"] == ["primary"]

    # Read (list + get)
    listed = await client.get("/api/v1/sites", headers=admin_headers)
    assert listed.status_code == 200
    assert listed.json()["total"] == 1

    fetched = await client.get(f"/api/v1/sites/{site_id}", headers=admin_headers)
    assert fetched.status_code == 200
    assert fetched.json()["code"] == "HQ"

    # Update
    updated = await client.patch(
        f"/api/v1/sites/{site_id}",
        json={"description": "Head office"},
        headers=admin_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["description"] == "Head office"

    # Delete
    deleted = await client.delete(f"/api/v1/sites/{site_id}", headers=admin_headers)
    assert deleted.status_code == 204

    gone = await client.get(f"/api/v1/sites/{site_id}", headers=admin_headers)
    assert gone.status_code == 404

    # Audit events recorded for each mutation.
    result = await db_session.execute(select(AuditEvent.action))
    actions = [row[0] for row in result.all()]
    assert "site.created" in actions
    assert "site.updated" in actions
    assert "site.deleted" in actions


async def test_duplicate_site_code_conflicts(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    first = await client.post(
        "/api/v1/sites", json={"name": "A", "code": "DUP"}, headers=admin_headers
    )
    assert first.status_code == 201
    second = await client.post(
        "/api/v1/sites", json={"name": "B", "code": "DUP"}, headers=admin_headers
    )
    assert second.status_code == 409


async def test_get_missing_site_returns_404(
    client: AsyncClient, admin_headers: dict[str, str]
) -> None:
    resp = await client.get(
        "/api/v1/sites/00000000-0000-0000-0000-000000000000", headers=admin_headers
    )
    assert resp.status_code == 404
