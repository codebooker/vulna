"""Ingest parsed scanner results into the asset/service inventory.

Discovered hosts are matched to existing assets by identifier (IP first, then
MAC) so repeated scans update an asset rather than creating a duplicate. Raw
scanner output is retained verbatim as a scan artifact.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset, AssetIdentifier
from app.models.change_event import ChangeEvent
from app.models.enums import (
    AssetStatus,
    AssetType,
    ChangeEventType,
    IdentifierType,
    ServiceState,
)
from app.models.scan_artifact import ScanArtifact
from app.models.scan_job import ScanJob
from app.models.service import Service
from app.services import asset_context
from app.services.evidence_crypto import encrypt_evidence
from app.services.nmap_parser import ParsedHost, ParsedService, parse_nmap_xml


@dataclass
class IngestSummary:
    """Counts describing what an ingestion produced."""

    hosts_seen: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    services_upserted: int = 0
    change_events: int = 0


def store_scan_artifact(
    session: AsyncSession,
    *,
    job: ScanJob,
    probe_id: uuid.UUID | None,
    stage: str,
    scanner: str,
    raw: bytes,
    content_type: str,
    master_key: str | None = None,
) -> None:
    """Persist raw scanner output as a scan artifact, encrypted at rest when a
    master key is configured. The sha256/size describe the plaintext output."""
    stored, encrypted = encrypt_evidence(raw, master_key)
    session.add(
        ScanArtifact(
            scan_job_id=job.id,
            probe_id=probe_id,
            stage=stage,
            scanner_name=scanner,
            content_type=content_type,
            sha256=hashlib.sha256(raw).hexdigest(),
            size_bytes=len(raw),
            raw_output=stored,
            encrypted=encrypted,
        )
    )


async def _find_asset_by_identifier(
    session: AsyncSession,
    org_id: uuid.UUID,
    site_id: uuid.UUID,
    identifier_type: IdentifierType,
    value: str,
) -> Asset | None:
    result = await session.execute(
        select(Asset)
        .join(AssetIdentifier, AssetIdentifier.asset_id == Asset.id)
        .where(
            Asset.organization_id == org_id,
            Asset.site_id == site_id,
            AssetIdentifier.identifier_type == identifier_type,
            AssetIdentifier.identifier_value == value,
        )
    )
    return result.scalars().first()


async def _upsert_identifier(
    session: AsyncSession,
    asset_id: uuid.UUID,
    identifier_type: IdentifierType,
    value: str | None,
    confidence: int,
    now: datetime,
) -> None:
    if not value:
        return
    existing = await session.scalar(
        select(AssetIdentifier).where(
            AssetIdentifier.asset_id == asset_id,
            AssetIdentifier.identifier_type == identifier_type,
            AssetIdentifier.identifier_value == value,
        )
    )
    if existing is not None:
        existing.last_seen_at = now
        return
    session.add(
        AssetIdentifier(
            asset_id=asset_id,
            identifier_type=identifier_type,
            identifier_value=value,
            confidence=confidence,
            first_seen_at=now,
            last_seen_at=now,
        )
    )


async def _upsert_service(
    session: AsyncSession, asset_id: uuid.UUID, parsed: ParsedService, now: datetime
) -> None:
    existing = await session.scalar(
        select(Service).where(
            Service.asset_id == asset_id,
            Service.transport == parsed.transport,
            Service.port == parsed.port,
        )
    )
    if existing is None:
        session.add(
            Service(
                asset_id=asset_id,
                transport=parsed.transport,
                port=parsed.port,
                state=parsed.state,
                service_name=parsed.service_name,
                product=parsed.product,
                version=parsed.version,
                cpe=parsed.cpe,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        return
    existing.state = parsed.state
    existing.service_name = parsed.service_name or existing.service_name
    existing.product = parsed.product or existing.product
    existing.version = parsed.version or existing.version
    existing.cpe = parsed.cpe or existing.cpe
    existing.last_seen_at = now


def _classify_hostname(name: str) -> IdentifierType:
    return IdentifierType.FQDN if "." in name else IdentifierType.HOSTNAME


def _record_change(
    session: AsyncSession,
    job: ScanJob,
    asset: Asset,
    event_type: ChangeEventType,
    summary_text: str,
    *,
    before: dict[str, object] | None = None,
    after: dict[str, object] | None = None,
    severity: str = "info",
) -> None:
    session.add(
        ChangeEvent(
            organization_id=job.organization_id,
            site_id=job.site_id,
            asset_id=asset.id,
            scan_job_id=job.id,
            event_type=event_type,
            severity=severity,
            summary=summary_text,
            before_json=before or {},
            after_json=after or {},
        )
    )


async def _detect_service_changes(
    session: AsyncSession,
    job: ScanJob,
    asset: Asset,
    host: ParsedHost,
    now: datetime,
    summary: IngestSummary,
) -> None:
    """Record port-open/close and version-change events vs the asset's current state."""
    current = (
        (await session.execute(select(Service).where(Service.asset_id == asset.id))).scalars().all()
    )
    before = {(s.transport, s.port): s for s in current}
    after = {(s.transport, s.port): s for s in host.services}

    for (transport, port), parsed in after.items():
        existing = before.get((transport, port))
        if existing is None or existing.state != ServiceState.OPEN:
            _record_change(
                session,
                job,
                asset,
                ChangeEventType.NEW_PORT_OPENED,
                f"Port {port}/{transport.value} opened on {asset.canonical_name}",
                after={"port": port, "transport": transport.value, "service": parsed.service_name},
            )
            summary.change_events += 1
        elif (existing.product, existing.version) != (parsed.product, parsed.version) and (
            parsed.product or parsed.version
        ):
            _record_change(
                session,
                job,
                asset,
                ChangeEventType.SERVICE_VERSION_CHANGED,
                f"Service on {port}/{transport.value} changed on {asset.canonical_name}",
                before={"product": existing.product, "version": existing.version},
                after={"product": parsed.product, "version": parsed.version},
            )
            summary.change_events += 1

    for (transport, port), existing in before.items():
        if (transport, port) not in after and existing.state == ServiceState.OPEN:
            _record_change(
                session,
                job,
                asset,
                ChangeEventType.PORT_CLOSED,
                f"Port {port}/{transport.value} closed on {asset.canonical_name}",
                before={"port": port, "transport": transport.value},
            )
            summary.change_events += 1
            existing.state = ServiceState.CLOSED
            existing.last_seen_at = now


async def _ingest_host(
    session: AsyncSession, job: ScanJob, host: ParsedHost, now: datetime, summary: IngestSummary
) -> None:
    asset: Asset | None = None
    if host.ip:
        asset = await _find_asset_by_identifier(
            session, job.organization_id, job.site_id, IdentifierType.IP_ADDRESS, host.ip
        )
    if asset is None and host.mac:
        asset = await _find_asset_by_identifier(
            session, job.organization_id, job.site_id, IdentifierType.MAC_ADDRESS, host.mac
        )

    if asset is None:
        canonical = (
            (host.hostnames[0] if host.hostnames else None) or host.ip or host.mac or "unknown"
        )
        asset = Asset(
            organization_id=job.organization_id,
            site_id=job.site_id,
            canonical_name=canonical,
            asset_type=AssetType.UNKNOWN,
            status=AssetStatus.ACTIVE,
            first_seen_at=now,
        )
        session.add(asset)
        summary.assets_created += 1
        await session.flush()
        _record_change(
            session,
            job,
            asset,
            ChangeEventType.ASSET_DISCOVERED,
            f"Asset {asset.canonical_name} discovered",
            after={"ip": host.ip, "mac": host.mac, "hostnames": host.hostnames},
        )
        summary.change_events += 1
    else:
        summary.assets_updated += 1
        # Compare this scan against the asset's current services before upserting.
        await _detect_service_changes(session, job, asset, host, now, summary)

    asset.last_seen_at = now
    asset.last_assessed_at = now
    asset.status = AssetStatus.ACTIVE
    if host.operating_system:
        asset.operating_system = host.operating_system
    if host.mac_vendor and not asset.manufacturer:
        asset.manufacturer = host.mac_vendor
    await session.flush()

    await _upsert_identifier(session, asset.id, IdentifierType.IP_ADDRESS, host.ip, 90, now)
    await _upsert_identifier(session, asset.id, IdentifierType.MAC_ADDRESS, host.mac, 95, now)
    for name in host.hostnames:
        await _upsert_identifier(session, asset.id, _classify_hostname(name), name, 60, now)

    for parsed_service in host.services:
        await _upsert_service(session, asset.id, parsed_service, now)
        summary.services_upserted += 1
    await asset_context.refresh_dynamic_memberships_for_asset(session, asset, now=now)
    ownership = await asset_context.resolve_ownership(session, asset)
    await asset_context.record_ownership_snapshot(session, ownership)


async def ingest_nmap_result(
    session: AsyncSession,
    *,
    job: ScanJob,
    xml_bytes: bytes,
    probe_id: uuid.UUID | None,
    stage: str = "discovery",
    scanner: str = "nmap",
    master_key: str | None = None,
) -> IngestSummary:
    """Retain the raw output, parse it, and upsert assets/services for a job."""
    store_scan_artifact(
        session,
        job=job,
        probe_id=probe_id,
        stage=stage,
        scanner=scanner,
        raw=xml_bytes,
        content_type="application/xml",
        master_key=master_key,
    )
    hosts = parse_nmap_xml(xml_bytes)
    now = datetime.now(UTC)
    summary = IngestSummary(hosts_seen=len(hosts))
    for host in hosts:
        await _ingest_host(session, job, host, now, summary)
    return summary
