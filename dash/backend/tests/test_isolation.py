"""Cross-organization isolation tests (build plan Section 27.3)."""

from __future__ import annotations

from app.auth.password import hash_password
from app.models.enums import UserRole
from app.models.organization import Organization
from app.models.site import Site
from app.models.user import User
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import auth_headers


async def test_user_cannot_read_other_orgs_site(
    client: AsyncClient, db_session: AsyncSession, admin_headers: dict[str, str]
) -> None:
    # A second organization with its own site and admin.
    other_org = Organization(name="Other", slug="other-org")
    db_session.add(other_org)
    await db_session.flush()
    other_site = Site(organization_id=other_org.id, name="Other HQ", code="OHQ")
    other_admin = User(
        organization_id=other_org.id,
        email="other-admin@example.com",
        hashed_password=hash_password("password-1234-strong"),
        role=UserRole.ADMINISTRATOR,
    )
    db_session.add_all([other_site, other_admin])
    await db_session.commit()
    await db_session.refresh(other_site)

    # The first org's admin must not be able to read the other org's site.
    resp = await client.get(f"/api/v1/sites/{other_site.id}", headers=admin_headers)
    assert resp.status_code == 404

    # And the other org's admin sees only their own site in the list.
    other_list = await client.get("/api/v1/sites", headers=auth_headers(other_admin))
    assert other_list.status_code == 200
    codes = {item["code"] for item in other_list.json()["items"]}
    assert codes == {"OHQ"}
