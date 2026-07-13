"""Defensive software inventory ingestion and provider-neutral EOL evaluation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.enums import EolStatus, SoftwareChangeType, SoftwareInventorySource
from app.models.scan_job import ScanJob
from app.models.software import (
    EolIntelligenceRecord,
    EolOverride,
    SoftwareInventoryHistory,
    SoftwareInventoryItem,
)

_MAX_PACKAGES = 50_000


class SoftwareInventoryError(ValueError):
    """Collector output cannot be ingested safely."""


class EolProvider(Protocol):
    """Adapter contract for optional online or offline EOL intelligence."""

    name: str

    async def fetch(self) -> list[dict[str, Any]]: ...


@dataclass(frozen=True)
class InventorySummary:
    packages_seen: int = 0
    packages_added: int = 0
    packages_updated: int = 0
    packages_removed: int = 0


@dataclass(frozen=True)
class EolEvaluation:
    status: EolStatus
    eol_date: date | None
    source: str
    source_url: str | None = None
    overridden: bool = False


def _text(value: Any, *, field: str, maximum: int, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str):
        raise SoftwareInventoryError(f"{field} must be text")
    value = value.strip()
    if required and not value:
        raise SoftwareInventoryError(f"{field} is required")
    if len(value) > maximum:
        raise SoftwareInventoryError(f"{field} exceeds {maximum} characters")
    return value or None


def _date(value: Any) -> date | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise SoftwareInventoryError("install_date must be an ISO date")
    try:
        return date.fromisoformat(value[:10])
    except ValueError as exc:
        raise SoftwareInventoryError("install_date must be an ISO date") from exc


def parse_inventory(raw: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SoftwareInventoryError("inventory result is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise SoftwareInventoryError("inventory result must be an object")
    packages = payload.get("packages")
    if not isinstance(packages, list):
        raise SoftwareInventoryError("inventory packages must be a list")
    if len(packages) > _MAX_PACKAGES:
        raise SoftwareInventoryError(f"inventory exceeds {_MAX_PACKAGES} packages")
    operating_system = payload.get("operating_system")
    if not isinstance(operating_system, dict):
        operating_system = {}

    parsed: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in packages:
        if not isinstance(row, dict):
            raise SoftwareInventoryError("each inventory package must be an object")
        name = _text(row.get("name"), field="name", maximum=512, required=True)
        version = _text(row.get("version"), field="version", maximum=255, required=True)
        architecture = _text(
            row.get("architecture") or "unknown",
            field="architecture",
            maximum=64,
            required=True,
        )
        if name is None or version is None or architecture is None:
            raise SoftwareInventoryError("package identity is incomplete")
        package_key = str(row.get("package_key") or name).strip().casefold()
        if not package_key or len(package_key) > 512:
            raise SoftwareInventoryError("package_key is invalid")
        identity = (package_key, architecture.casefold())
        if identity in seen:
            continue
        seen.add(identity)
        parsed.append(
            {
                "name": name,
                "package_key": package_key,
                "version": version,
                "architecture": architecture,
                "publisher": _text(row.get("publisher"), field="publisher", maximum=255),
                "product_key": _text(row.get("product_key"), field="product_key", maximum=255),
                "install_date": _date(row.get("install_date")),
            }
        )
    return operating_system, parsed


async def ingest_inventory(
    session: AsyncSession,
    *,
    job: ScanJob,
    raw: bytes,
    source: SoftwareInventorySource,
    now: datetime | None = None,
) -> InventorySummary:
    if job.asset_id is None:
        raise SoftwareInventoryError("authenticated inventory job has no asset")
    asset = await session.scalar(
        select(Asset).where(
            Asset.id == job.asset_id,
            Asset.organization_id == job.organization_id,
            Asset.site_id == job.site_id,
        )
    )
    if asset is None:
        raise SoftwareInventoryError("authenticated inventory asset no longer exists")
    operating_system, packages = parse_inventory(raw)
    now = now or datetime.now(UTC)
    os_name = _text(operating_system.get("name"), field="operating_system.name", maximum=255)
    os_version = _text(
        operating_system.get("version"), field="operating_system.version", maximum=128
    )
    if os_name:
        asset.operating_system = f"{os_name} {os_version}".strip()

    existing = list(
        (
            await session.execute(
                select(SoftwareInventoryItem).where(
                    SoftwareInventoryItem.organization_id == job.organization_id,
                    SoftwareInventoryItem.asset_id == asset.id,
                    SoftwareInventoryItem.source == source,
                    SoftwareInventoryItem.removed_at.is_(None),
                )
            )
        ).scalars()
    )
    by_identity = {(row.package_key, row.architecture.casefold()): row for row in existing}
    observed: set[tuple[str, str]] = set()
    added = updated = 0
    for package in packages:
        identity = (package["package_key"], package["architecture"].casefold())
        observed.add(identity)
        item = by_identity.get(identity)
        change = SoftwareChangeType.OBSERVED
        previous_version: str | None = None
        if item is None:
            item = SoftwareInventoryItem(
                organization_id=job.organization_id,
                site_id=job.site_id,
                asset_id=asset.id,
                source=source,
                first_seen_at=now,
                last_seen_at=now,
                metadata_json={},
                **package,
            )
            session.add(item)
            await session.flush()
            change = SoftwareChangeType.ADDED
            added += 1
        else:
            previous_version = item.version
            if item.version != package["version"]:
                change = SoftwareChangeType.VERSION_CHANGED
                updated += 1
            item.name = package["name"]
            item.version = package["version"]
            item.publisher = package["publisher"]
            item.product_key = package["product_key"]
            item.install_date = package["install_date"]
            item.last_seen_at = now
        session.add(
            SoftwareInventoryHistory(
                organization_id=job.organization_id,
                site_id=job.site_id,
                asset_id=asset.id,
                software_item_id=item.id,
                scan_job_id=job.id,
                change_type=change,
                previous_version=previous_version,
                observed_version=item.version,
                observation_json={
                    "source": source.value,
                    "package_key": item.package_key,
                    "architecture": item.architecture,
                },
            )
        )

    removed = 0
    for item in existing:
        identity = (item.package_key, item.architecture.casefold())
        if identity in observed:
            continue
        item.removed_at = now
        removed += 1
        session.add(
            SoftwareInventoryHistory(
                organization_id=job.organization_id,
                site_id=job.site_id,
                asset_id=asset.id,
                software_item_id=item.id,
                scan_job_id=job.id,
                change_type=SoftwareChangeType.REMOVED,
                previous_version=item.version,
                observed_version=None,
                observation_json={"source": source.value},
            )
        )
    asset.last_assessed_at = now
    return InventorySummary(len(packages), added, updated, removed)


async def evaluate_eol(
    session: AsyncSession,
    item: SoftwareInventoryItem,
    *,
    now: datetime | None = None,
) -> EolEvaluation:
    now = now or datetime.now(UTC)
    override = await session.scalar(
        select(EolOverride)
        .where(
            EolOverride.organization_id == item.organization_id,
            EolOverride.software_item_id == item.id,
            EolOverride.active.is_(True),
        )
        .order_by(EolOverride.created_at.desc())
    )
    if override is not None:
        expires = override.expires_at
        if expires is None or (expires if expires.tzinfo else expires.replace(tzinfo=UTC)) > now:
            return EolEvaluation(
                override.status, override.eol_date, "manual_override", overridden=True
            )

    if not item.product_key:
        return EolEvaluation(EolStatus.UNKNOWN, None, "none")
    records = list(
        (
            await session.execute(
                select(EolIntelligenceRecord)
                .where(EolIntelligenceRecord.product_key == item.product_key)
                .order_by(EolIntelligenceRecord.version_prefix.desc())
            )
        ).scalars()
    )
    for record in records:
        if record.version_prefix and not item.version.startswith(record.version_prefix):
            continue
        status = record.status
        if record.eol_date is not None and record.eol_date < now.date():
            status = EolStatus.END_OF_LIFE
        return EolEvaluation(status, record.eol_date, record.provider, record.source_url)
    return EolEvaluation(EolStatus.UNKNOWN, None, "none")
