"""Safe demo mode (Phase 30).

Demo mode seeds a self-contained "Demo Environment" site with sample assets,
services, and findings so the interface can be evaluated **without scanning
anything**. It is safe by construction:

* All sample hosts use **reserved documentation address ranges** (RFC 5737:
  ``198.51.100.0/24`` and ``203.0.113.0/24``), never a routable target.
* While demo mode is on, creating a real scan job is refused, so the demo can
  never contact an arbitrary target.

Disabling demo mode removes the seeded data. The demo flag lives in the
organization's ``settings_json`` (no schema change).
"""

from __future__ import annotations

import hashlib
import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.models.asset import Asset
from app.models.change_event import ChangeEvent
from app.models.enums import (
    AssetStatus,
    AssetType,
    ChangeEventType,
    FindingStatus,
    FindingType,
    ServiceState,
    ServiceTransport,
    Severity,
    ValidationStatus,
)
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.service import Service
from app.models.site import Site
from app.services import risk

DEMO_SITE_CODE = "__demo__"
DEMO_FLAG = "demo_mode"


def is_demo_mode(org: Organization) -> bool:
    return bool((org.settings_json or {}).get(DEMO_FLAG))


def _set_flag(org: Organization, on: bool) -> None:
    settings = dict(org.settings_json or {})
    settings[DEMO_FLAG] = on
    org.settings_json = settings
    flag_modified(org, "settings_json")


def _key(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


async def status(session: AsyncSession, org: Organization) -> dict[str, object]:
    site = await _demo_site(session, org.id)
    return {"demo_mode": is_demo_mode(org), "seeded": site is not None}


async def enable_demo(session: AsyncSession, org: Organization) -> dict[str, object]:
    """Turn on demo mode and seed sample data (idempotent)."""
    _set_flag(org, True)
    site = await _demo_site(session, org.id)
    if site is not None:
        return {"demo_mode": True, "seeded": True, "created": False}

    site = Site(
        organization_id=org.id,
        name="Demo Environment",
        code=DEMO_SITE_CODE,
        description="Sample data for evaluating Vulna. No real scanning occurs.",
    )
    session.add(site)
    await session.flush()

    # Two sample hosts on documentation address ranges.
    web = Asset(
        organization_id=org.id, site_id=site.id, canonical_name="198.51.100.10",
        asset_type=AssetType.SERVER, status=AssetStatus.ACTIVE,
        metadata_json={"hostname": "web.demo.invalid", "demo": True},
    )
    printer = Asset(
        organization_id=org.id, site_id=site.id, canonical_name="203.0.113.20",
        asset_type=AssetType.PRINTER, status=AssetStatus.ACTIVE,
        metadata_json={"hostname": "printer.demo.invalid", "demo": True},
    )
    session.add_all([web, printer])
    await session.flush()

    tcp = ServiceTransport.TCP
    open_ = ServiceState.OPEN
    session.add_all([
        Service(asset_id=web.id, transport=tcp, port=443, state=open_),
        Service(asset_id=web.id, transport=tcp, port=22, state=open_),
        Service(asset_id=printer.id, transport=tcp, port=9100, state=open_),
    ])

    findings = [
        Finding(
            organization_id=org.id, site_id=site.id, asset_id=web.id, scanner_name="demo",
            canonical_finding_key=_key(str(web.id), "tls-weak"),
            finding_type=FindingType.WEAK_PROTOCOL, title="TLS 1.0 enabled",
            severity=Severity.MEDIUM, validation_status=ValidationStatus.LIKELY,
            status=FindingStatus.NEW,
        ),
        Finding(
            organization_id=org.id, site_id=site.id, asset_id=web.id, scanner_name="demo",
            canonical_finding_key=_key(str(web.id), "cve-critical"),
            finding_type=FindingType.VULNERABILITY, title="Outdated web framework (sample CVE)",
            severity=Severity.CRITICAL, validation_status=ValidationStatus.LIKELY,
            status=FindingStatus.NEW, known_exploited=True, cve_ids_json=["CVE-2026-0001"],
        ),
        Finding(
            organization_id=org.id, site_id=site.id, asset_id=printer.id, scanner_name="demo",
            canonical_finding_key=_key(str(printer.id), "exposed"),
            finding_type=FindingType.EXPOSED_SERVICE, title="Printer admin exposed",
            severity=Severity.HIGH, validation_status=ValidationStatus.UNVALIDATED,
            status=FindingStatus.NEW,
        ),
    ]
    session.add_all(findings)
    await session.flush()
    for finding in findings:
        await risk.score_finding(session, finding)
    session.add(
        ChangeEvent(
            organization_id=org.id, site_id=site.id, asset_id=web.id,
            event_type=ChangeEventType.NEW_PORT_OPENED, severity="info",
            summary="Port 443/tcp opened on 198.51.100.10",
            after_json={"port": 443},
        )
    )
    return {"demo_mode": True, "seeded": True, "created": True}


async def disable_demo(session: AsyncSession, org: Organization) -> dict[str, object]:
    """Turn off demo mode and remove the seeded sample data."""
    _set_flag(org, False)
    site = await _demo_site(session, org.id)
    if site is None:
        return {"demo_mode": False, "seeded": False}

    # Delete dependents first (portable across SQLite/Postgres regardless of FK
    # cascade configuration), then the site.
    await session.execute(delete(Finding).where(Finding.site_id == site.id))
    await session.execute(delete(ChangeEvent).where(ChangeEvent.site_id == site.id))
    asset_ids = (
        await session.execute(select(Asset.id).where(Asset.site_id == site.id))
    ).scalars().all()
    if asset_ids:
        await session.execute(delete(Service).where(Service.asset_id.in_(asset_ids)))
    await session.execute(delete(Asset).where(Asset.site_id == site.id))
    await session.execute(delete(Site).where(Site.id == site.id))
    return {"demo_mode": False, "seeded": False}


async def _demo_site(session: AsyncSession, org_id: uuid.UUID) -> Site | None:
    site: Site | None = await session.scalar(
        select(Site).where(Site.organization_id == org_id, Site.code == DEMO_SITE_CODE)
    )
    return site
