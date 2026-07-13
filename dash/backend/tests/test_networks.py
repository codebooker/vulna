"""Networks: CRUD, scout binding, and the policy union (incl. cross-site)."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

import pytest
from app.core.config import get_settings
from app.models.probe import Probe
from app.services.policy import build_policy_document
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]


async def _approved_probe(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory,
    site_code: str, name: str,
) -> dict[str, str]:
    probe = await enroll_probe(site_code=site_code, probe_name=name)
    await client.post(f"/api/v1/probes/{probe['probe_id']}/approve", headers=admin_headers)
    return probe


async def test_network_crud_and_ranges_and_scouts(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _approved_probe(client, admin_headers, enroll_probe, "ORL", "orlando-scout")
    site_id = probe["site_id"]

    created = await client.post(
        "/api/v1/networks",
        json={
            "site_id": site_id,
            "name": "Orlando LAN",
            "ranges": [{"cidr": "10.2.0.0/16"}],
            "scouts": [{"probe_id": probe["probe_id"], "is_primary": True}],
        },
        headers=admin_headers,
    )
    assert created.status_code == 201, created.text
    net = created.json()
    assert net["name"] == "Orlando LAN"
    assert [r["cidr"] for r in net["ranges"]] == ["10.2.0.0/16"]
    assert net["scouts"][0]["is_primary"] is True
    assert net["scouts"][0]["probe_name"] == "orlando-scout"

    # Add a second range; overlap is rejected.
    add = await client.post(
        f"/api/v1/networks/{net['id']}/ranges",
        json={"cidr": "10.2.50.0/24"},
        headers=admin_headers,
    )
    assert add.status_code == 409  # 10.2.50.0/24 overlaps 10.2.0.0/16

    add2 = await client.post(
        f"/api/v1/networks/{net['id']}/ranges",
        json={"cidr": "10.3.0.0/24"},
        headers=admin_headers,
    )
    assert add2.status_code == 200
    assert {r["cidr"] for r in add2.json()["ranges"]} == {"10.2.0.0/16", "10.3.0.0/24"}


async def test_deleting_a_network_frees_its_ranges(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    # Reproduces the field report: after deleting a network, its CIDR must not keep
    # blocking a new (overlapping) range as an invisible orphaned scope.
    probe = await _approved_probe(client, admin_headers, enroll_probe, "SAV", "savannah-scout")
    site_id = probe["site_id"]

    created = await client.post(
        "/api/v1/networks",
        json={"site_id": site_id, "name": "Temp LAN", "ranges": [{"cidr": "10.1.1.0/24"}]},
        headers=admin_headers,
    )
    assert created.status_code == 201, created.text
    net_id = created.json()["id"]

    # While it exists, an overlapping range in the same site is rejected.
    blocked = await client.post(
        "/api/v1/networks",
        json={"site_id": site_id, "name": "Single Host", "ranges": [{"cidr": "10.1.1.253/32"}]},
        headers=admin_headers,
    )
    assert blocked.status_code == 409

    # Delete the network — the range must go with it.
    deleted = await client.delete(f"/api/v1/networks/{net_id}", headers=admin_headers)
    assert deleted.status_code == 204

    # Now the formerly-overlapping range can be added; no zombie is left behind.
    freed = await client.post(
        "/api/v1/networks",
        json={"site_id": site_id, "name": "Single Host", "ranges": [{"cidr": "10.1.1.253/32"}]},
        headers=admin_headers,
    )
    assert freed.status_code == 201, freed.text
    assert [r["cidr"] for r in freed.json()["ranges"]] == ["10.1.1.253/32"]


async def test_probe_policy_includes_bound_network_ranges(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    probe = await _approved_probe(client, admin_headers, enroll_probe, "ORL2", "orl2")
    net = (
        await client.post(
            "/api/v1/networks",
            json={
                "site_id": probe["site_id"],
                "name": "Orlando",
                "ranges": [{"cidr": "10.2.0.0/16"}],
                "scouts": [{"probe_id": probe["probe_id"], "is_primary": True}],
            },
            headers=admin_headers,
        )
    ).json()
    assert net["id"]

    probe_obj = await db_session.get(Probe, uuid.UUID(probe["probe_id"]))
    policy = await build_policy_document(db_session, probe_obj, get_settings())
    assert "10.2.0.0/16" in policy["approved_cidrs"]


async def test_scout_can_scan_another_sites_network_over_sdwan(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    # Houston scout, Salisbury network under a different site — bound across the
    # SD-WAN. The Houston scout's policy must include the Salisbury ranges even
    # though they belong to another site.
    houston = await _approved_probe(client, admin_headers, enroll_probe, "HOU", "houston")
    salisbury = await _approved_probe(client, admin_headers, enroll_probe, "SBY", "salisbury")

    net = (
        await client.post(
            "/api/v1/networks",
            json={
                "site_id": salisbury["site_id"],
                "name": "Salisbury LAN",
                "ranges": [{"cidr": "10.9.0.0/16"}],
                "scouts": [{"probe_id": salisbury["probe_id"], "is_primary": True}],
            },
            headers=admin_headers,
        )
    ).json()

    # Also bind the Houston scout (non-primary) to the Salisbury network.
    bound = await client.post(
        f"/api/v1/networks/{net['id']}/scouts",
        json={"probe_id": houston["probe_id"], "is_primary": False},
        headers=admin_headers,
    )
    assert bound.status_code == 200
    # Binding a second primary would demote the first; here we kept it non-primary.
    primaries = [s for s in bound.json()["scouts"] if s["is_primary"]]
    assert len(primaries) == 1 and str(primaries[0]["probe_id"]) == salisbury["probe_id"]

    houston_obj = await db_session.get(Probe, uuid.UUID(houston["probe_id"]))
    policy = await build_policy_document(db_session, houston_obj, get_settings())
    assert "10.9.0.0/16" in policy["approved_cidrs"]


async def test_scope_convenience_is_backed_by_a_default_network(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    # The legacy /scopes endpoint is retired to a convenience: creating a scope
    # makes a per-site default network, binds the site's probe, and policy comes
    # only from networks.
    probe = await _approved_probe(client, admin_headers, enroll_probe, "LEG", "leg")
    scope = await client.post(
        "/api/v1/scopes",
        json={"site_id": probe["site_id"], "name": "lan", "cidr": "10.20.0.0/24"},
        headers=admin_headers,
    )
    assert scope.status_code == 201

    nets = (await client.get("/api/v1/networks", headers=admin_headers)).json()
    default = [n for n in nets if n["site_id"] == probe["site_id"]]
    assert len(default) == 1
    assert "10.20.0.0/24" in [r["cidr"] for r in default[0]["ranges"]]
    assert probe["probe_id"] in [s["probe_id"] for s in default[0]["scouts"]]

    probe_obj = await db_session.get(Probe, uuid.UUID(probe["probe_id"]))
    policy = await build_policy_document(db_session, probe_obj, get_settings())
    assert "10.20.0.0/24" in policy["approved_cidrs"]


async def test_probe_with_no_network_has_empty_scope(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    # No standalone-scope fallback anymore: an unbound probe scans nothing.
    probe = await _approved_probe(client, admin_headers, enroll_probe, "EMPTY", "empty")
    probe_obj = await db_session.get(Probe, uuid.UUID(probe["probe_id"]))
    policy = await build_policy_document(db_session, probe_obj, get_settings())
    assert policy["approved_cidrs"] == []


async def test_cross_site_job_attributed_to_network_site(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    from app.core.config import get_settings
    from app.models.enums import JobMode
    from app.models.scan_job import ScanJob
    from app.services.jobs import create_scan_job

    # A Houston scout bound to a Salisbury network: a job it runs must be
    # attributed to the SALISBURY site (where the assets live), not Houston.
    houston = await _approved_probe(client, admin_headers, enroll_probe, "HOU2", "hou2")
    salisbury = await _approved_probe(client, admin_headers, enroll_probe, "SBY2", "sby2")
    net = (
        await client.post(
            "/api/v1/networks",
            json={
                "site_id": salisbury["site_id"],
                "name": "Salisbury",
                "ranges": [{"cidr": "10.9.0.0/16"}],
                "scouts": [{"probe_id": houston["probe_id"], "is_primary": True}],
            },
            headers=admin_headers,
        )
    ).json()

    houston_probe = await db_session.get(Probe, uuid.UUID(houston["probe_id"]))
    job = await create_scan_job(
        db_session, houston_probe, get_settings(),
        targets=["10.9.0.0/24"], mode=JobMode.VULNERABILITY_ASSESSMENT,
        created_by=None, network_id=uuid.UUID(net["id"]),
    )
    reloaded = await db_session.get(ScanJob, job.id)
    assert str(reloaded.site_id) == salisbury["site_id"]  # not Houston
    assert str(reloaded.site_id) != houston["site_id"]


async def test_db_rejects_two_active_jobs_per_network(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session: AsyncSession,
) -> None:
    from app.core.config import get_settings
    from app.models.enums import JobMode
    from app.services.jobs import JobValidationError, create_scan_job

    # The per-network lock is also enforced at the DB level (partial unique index),
    # so even a race that slips past the app-level check cannot create a second
    # active job for the same network. create_scan_job inserts inside a SAVEPOINT and
    # surfaces the constraint as a graceful JobValidationError (not an IntegrityError
    # that would poison the surrounding transaction / roll back a scheduler sweep).
    probe = await _approved_probe(client, admin_headers, enroll_probe, "RACE", "race")
    net = (
        await client.post(
            "/api/v1/networks",
            json={
                "site_id": probe["site_id"],
                "name": "Race",
                "ranges": [{"cidr": "10.50.0.0/24"}],
                "scouts": [{"probe_id": probe["probe_id"], "is_primary": True}],
            },
            headers=admin_headers,
        )
    ).json()
    probe_obj = await db_session.get(Probe, uuid.UUID(probe["probe_id"]))
    net_id = uuid.UUID(net["id"])

    await create_scan_job(
        db_session, probe_obj, get_settings(),
        targets=["10.50.0.0/24"], mode=JobMode.VULNERABILITY_ASSESSMENT,
        created_by=None, network_id=net_id,
    )
    with pytest.raises(JobValidationError, match="already under test"):
        await create_scan_job(
            db_session, probe_obj, get_settings(),
            targets=["10.50.0.0/24"], mode=JobMode.VULNERABILITY_ASSESSMENT,
            created_by=None, network_id=net_id,
        )
    # The savepoint kept the surrounding transaction usable after the rejection:
    # a normal query still works (an IntegrityError would have poisoned it).
    assert await db_session.get(Probe, probe_obj.id) is not None


async def test_networks_require_admin(
    client: AsyncClient, viewer_headers: dict[str, str], admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
) -> None:
    probe = await enroll_probe(site_code="V", probe_name="v")
    r = await client.post(
        "/api/v1/networks",
        json={"site_id": probe["site_id"], "name": "x"},
        headers=viewer_headers,
    )
    assert r.status_code == 403
