"""Complete, versioned data export and import validation (Phase 31).

An operator owns their data and can take it with them. :func:`build_export`
produces a versioned, checksummed JSON bundle of an organization's
non-secret data — organization, sites, scopes, Scouts, assets, services,
findings, reports (metadata), and remediation history. The bundle can be
validated independently against the published schema and its checksum.

:func:`validate_import` treats a bundle as **untrusted**: it checks the schema
version, recomputes the checksum, and confirms internal ownership consistency and
reports conflicts. It never applies anything and never touches trust roots,
privileged users, or signing keys — data portability must not become a
cross-organization authorization bypass. The actual move to another host is a
backup/restore (see the migration plan), which preserves CA and Scout identity.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.finding_note import FindingNote
from app.models.network_scope import NetworkScope
from app.models.organization import Organization
from app.models.probe import Probe
from app.models.report import Report
from app.models.risk_acceptance import RiskAcceptance
from app.models.service import Service
from app.models.site import Site

EXPORT_SCHEMA_VERSION = "1"
CHECKSUM_FIELD = "checksum"


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic bytes for checksumming (excludes the checksum field)."""
    body = {k: v for k, v in payload.items() if k != CHECKSUM_FIELD}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()


def checksum(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


async def build_export(
    session: AsyncSession, org_id: uuid.UUID, now: datetime | None = None
) -> dict[str, Any]:
    """Build the org-scoped export bundle with a SHA-256 checksum."""
    now = now or datetime.now(UTC)
    org = await session.get(Organization, org_id)
    if org is None:
        raise ValueError("organization not found")

    bundle: dict[str, Any] = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "exported_at": now.isoformat(),
        "organization": {
            "id": str(org.id), "name": org.name, "slug": org.slug,
            "default_timezone": org.default_timezone,
            "experience_profile": org.experience_profile.value,
            "feature_overrides": org.feature_overrides_json,
        },
        "sites": await _sites(session, org_id),
        "network_scopes": await _scopes(session, org_id),
        "scouts": await _scouts(session, org_id),
        "assets": await _assets(session, org_id),
        "services": await _services(session, org_id),
        "findings": await _findings(session, org_id),
        "reports": await _reports(session, org_id),
        "risk_acceptances": await _risk_acceptances(session, org_id),
        "finding_notes": await _finding_notes(session, org_id),
    }
    bundle[CHECKSUM_FIELD] = checksum(bundle)
    return bundle


async def _sites(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (await session.execute(select(Site).where(Site.organization_id == org_id))).scalars()
    return [
        {"id": str(s.id), "name": s.name, "code": s.code, "description": s.description,
         "tags": s.tags}
        for s in rows
    ]


async def _scopes(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(NetworkScope).where(NetworkScope.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(x.id), "site_id": str(x.site_id), "name": x.name, "cidr": x.cidr,
            "enabled": x.enabled, "allow_public_addresses": x.allow_public_addresses,
            "approved_at": _iso(x.approved_at), "expires_at": _iso(x.expires_at),
            "maximum_hosts": x.maximum_hosts,
            "maximum_packets_per_second": x.maximum_packets_per_second,
            "maximum_concurrency": x.maximum_concurrency,
        }
        for x in rows
    ]


async def _scouts(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    # Non-secret Scout metadata only: never keys, tokens, or certificates.
    rows = (await session.execute(select(Probe).where(Probe.organization_id == org_id))).scalars()
    return [
        {
            "id": str(p.id), "name": p.name, "status": p.status.value,
            "certificate_fingerprint": p.certificate_fingerprint,
            "agent_version": p.agent_version, "last_seen_at": _iso(p.last_seen_at),
        }
        for p in rows
    ]


async def _assets(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (await session.execute(select(Asset).where(Asset.organization_id == org_id))).scalars()
    return [
        {
            "id": str(a.id), "site_id": str(a.site_id), "canonical_name": a.canonical_name,
            "asset_type": a.asset_type.value, "status": a.status.value,
            "metadata": a.metadata_json,
        }
        for a in rows
    ]


async def _services(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(Service).join(Asset, Asset.id == Service.asset_id).where(
                Asset.organization_id == org_id
            )
        )
    ).scalars()
    return [
        {"id": str(s.id), "asset_id": str(s.asset_id), "transport": s.transport.value,
         "port": s.port, "state": s.state.value}
        for s in rows
    ]


async def _findings(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(Finding).where(Finding.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(f.id), "site_id": str(f.site_id),
            "asset_id": str(f.asset_id) if f.asset_id else None,
            "scanner_name": f.scanner_name, "canonical_finding_key": f.canonical_finding_key,
            "finding_type": f.finding_type.value, "title": f.title,
            "severity": f.severity.value, "status": f.status.value,
            "cve_ids": f.cve_ids_json, "known_exploited": f.known_exploited,
        }
        for f in rows
    ]


async def _reports(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    # Report metadata + integrity hash only — never the report file bytes.
    rows = (await session.execute(select(Report).where(Report.organization_id == org_id))).scalars()
    return [
        {
            "id": str(r.id), "report_type": r.report_type.value, "format": r.format.value,
            "status": r.status.value, "sha256": r.sha256, "size_bytes": r.size_bytes,
            "created_at": _iso(r.created_at),
        }
        for r in rows
    ]


async def _risk_acceptances(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(RiskAcceptance).where(RiskAcceptance.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(x.id), "finding_id": str(x.finding_id), "reason": x.reason,
            "status": x.status.value, "expires_at": _iso(x.expires_at),
        }
        for x in rows
    ]


async def _finding_notes(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(FindingNote).join(Finding, Finding.id == FindingNote.finding_id).where(
                Finding.organization_id == org_id
            )
        )
    ).scalars()
    return [
        {"id": str(n.id), "finding_id": str(n.finding_id), "body": n.body,
         "created_at": _iso(n.created_at)}
        for n in rows
    ]


# --------------------------------------------------------------------------- #
# Import validation (untrusted; never applies)
# --------------------------------------------------------------------------- #


def validate_import(payload: dict[str, Any], *, expected_org_id: uuid.UUID) -> dict[str, Any]:
    """Validate an export bundle without applying it.

    Checks the schema version, recomputes the checksum, and confirms the bundle is
    internally consistent. If ``expected_org_id`` differs from the bundle's
    organization it is reported as a conflict — importing another organization's
    data is refused, so portability cannot become a cross-org authorization bypass.
    """
    errors: list[str] = []
    warnings: list[str] = []

    version = payload.get("schema_version")
    if version != EXPORT_SCHEMA_VERSION:
        errors.append(
            f"Unsupported schema_version '{version}'; this build reads '{EXPORT_SCHEMA_VERSION}'."
        )

    provided = payload.get(CHECKSUM_FIELD)
    checksum_ok = isinstance(provided, str) and provided == checksum(payload)
    if not checksum_ok:
        errors.append("Checksum does not match the bundle contents.")

    org = payload.get("organization") or {}
    org_id = org.get("id")
    if not org_id:
        errors.append("Bundle has no organization id.")
    elif str(org_id) != str(expected_org_id):
        errors.append(
            "Bundle belongs to a different organization; cross-organization import is refused."
        )

    # Referential sanity: every asset references a site present in the bundle.
    site_ids = {s.get("id") for s in payload.get("sites", [])}
    for a in payload.get("assets", []):
        if a.get("site_id") not in site_ids:
            warnings.append(f"Asset {a.get('id')} references a site not in the bundle.")

    counts = {
        key: len(payload.get(key, []))
        for key in ("sites", "assets", "services", "findings", "reports")
    }
    return {
        "valid": not errors,
        "schema_version": version,
        "checksum_ok": checksum_ok,
        "errors": errors,
        "warnings": warnings,
        "counts": counts,
    }
