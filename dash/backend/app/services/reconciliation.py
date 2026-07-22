"""Deterministic, explainable, and reversible inventory reconciliation."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.asset import Asset, AssetIdentifier
from app.models.enums import (
    AssetStatus,
    AssetType,
    IdentifierType,
    InventoryAssetState,
    ReconciliationStatus,
)
from app.models.passive_inventory import (
    AssetInventoryState,
    AssetObservation,
    AssetSourceLink,
    InventoryLifecycleEvent,
    ReconciliationCandidate,
)

AUTO_MERGE_THRESHOLD = 95.0
REVIEW_THRESHOLD = 70.0
IDENTIFIER_WEIGHTS: dict[IdentifierType, float] = {
    IdentifierType.AGENT_ID: 100.0,
    IdentifierType.CLOUD_INSTANCE_ID: 100.0,
    IdentifierType.SSH_HOST_KEY: 100.0,
    IdentifierType.TLS_CERT_FINGERPRINT: 100.0,
    IdentifierType.SNMP_ENGINE_ID: 100.0,
    IdentifierType.MAC_ADDRESS: 95.0,
    IdentifierType.FQDN: 85.0,
    IdentifierType.SMB_NAME: 80.0,
    IdentifierType.HOSTNAME: 75.0,
    IdentifierType.IP_ADDRESS: 60.0,
}
IMMUTABLE_TYPES = frozenset(
    {
        IdentifierType.AGENT_ID,
        IdentifierType.CLOUD_INSTANCE_ID,
        IdentifierType.SSH_HOST_KEY,
        IdentifierType.TLS_CERT_FINGERPRINT,
        IdentifierType.SNMP_ENGINE_ID,
        IdentifierType.MAC_ADDRESS,
    }
)


class ReconciliationError(ValueError):
    """The requested reconciliation transition is unsafe or invalid."""


def _later(first: datetime, second: datetime) -> datetime:
    def comparable(value: datetime) -> datetime:
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    return first if comparable(first) >= comparable(second) else second


def _same_moment(first: datetime | None, second: datetime | None) -> bool:
    if first is None or second is None:
        return first is second
    normalized_first = first if first.tzinfo else first.replace(tzinfo=UTC)
    normalized_second = second if second.tzinfo else second.replace(tzinfo=UTC)
    return normalized_first == normalized_second


def normalize_identifiers(raw: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Validate and canonicalize source identifiers without executable rules."""

    result: list[dict[str, str]] = []
    seen: set[tuple[IdentifierType, str]] = set()
    if not isinstance(raw, list) or len(raw) > 50:
        raise ReconciliationError("identifiers must be a list with at most 50 entries")
    for item in raw:
        if not isinstance(item, dict):
            raise ReconciliationError("each identifier must be an object")
        try:
            kind = IdentifierType(str(item.get("type", "")))
        except ValueError as exc:
            raise ReconciliationError("identifier type is not supported") from exc
        value = str(item.get("value", "")).strip().lower()
        if not value or len(value) > 255:
            raise ReconciliationError("identifier values must contain 1-255 characters")
        key = (kind, value)
        if key not in seen:
            result.append({"type": kind.value, "value": value})
            seen.add(key)
    if not result:
        raise ReconciliationError("at least one stable identifier is required")
    return result


def _identifier_map(raw: list[dict[str, Any]]) -> dict[IdentifierType, set[str]]:
    result: dict[IdentifierType, set[str]] = {}
    for item in normalize_identifiers(raw):
        result.setdefault(IdentifierType(item["type"]), set()).add(item["value"])
    return result


def score_asset(
    observation_identifiers: list[dict[str, Any]], asset: Asset
) -> tuple[float, list[dict[str, Any]], list[dict[str, Any]]]:
    """Return exact-match score, reasons, and immutable-identifier conflicts."""

    observed = _identifier_map(observation_identifiers)
    existing: dict[IdentifierType, set[str]] = {}
    for identifier in asset.identifiers:
        existing.setdefault(identifier.identifier_type, set()).add(
            identifier.identifier_value.strip().lower()
        )
    reasons: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    score = 0.0
    for kind, values in observed.items():
        matches = values & existing.get(kind, set())
        if matches:
            contribution = IDENTIFIER_WEIGHTS[kind]
            score = max(score, contribution)
            reasons.append(
                {
                    "identifier_type": kind.value,
                    "match": sorted(matches),
                    "contribution": contribution,
                }
            )
        elif kind in IMMUTABLE_TYPES and existing.get(kind):
            conflicts.append(
                {
                    "identifier_type": kind.value,
                    "observed": sorted(values),
                    "existing": sorted(existing[kind]),
                }
            )
    return score, reasons, conflicts


async def _set_lifecycle(
    session: AsyncSession,
    asset: Asset,
    state: InventoryAssetState,
    *,
    reason: str,
    observation: AssetObservation | None,
    now: datetime,
) -> AssetInventoryState:
    lifecycle = await session.scalar(
        select(AssetInventoryState).where(AssetInventoryState.asset_id == asset.id)
    )
    previous = lifecycle.state if lifecycle is not None else None
    if lifecycle is None:
        lifecycle = AssetInventoryState(
            organization_id=asset.organization_id,
            site_id=asset.site_id,
            asset_id=asset.id,
            state=state,
            expected=False,
            discovered_at=now,
            assessed_at=asset.last_assessed_at,
            last_observed_at=now,
            stale_after_days=30,
        )
        session.add(lifecycle)
    else:
        lifecycle.state = state
        lifecycle.last_observed_at = now
        lifecycle.missing_since = None
        lifecycle.discovered_at = lifecycle.discovered_at or now
        if asset.last_assessed_at is not None:
            lifecycle.assessed_at = asset.last_assessed_at
    if previous != state:
        session.add(
            InventoryLifecycleEvent(
                organization_id=asset.organization_id,
                site_id=asset.site_id,
                asset_id=asset.id,
                previous_state=previous,
                new_state=state,
                reason=reason,
                source_observation_id=observation.id if observation else None,
                metadata_json={},
            )
        )
    return lifecycle


async def _create_asset_from_observation(
    session: AsyncSession, observation: AssetObservation, *, now: datetime
) -> Asset:
    attrs = observation.attributes_json
    name = str(
        attrs.get("canonical_name")
        or attrs.get("hostname")
        or attrs.get("name")
        or observation.source_record_id
    ).strip()[:255]
    try:
        asset_type = AssetType(str(attrs.get("asset_type", AssetType.UNKNOWN.value)))
    except ValueError:
        asset_type = AssetType.UNKNOWN
    asset = Asset(
        organization_id=observation.organization_id,
        site_id=observation.site_id,
        canonical_name=name or f"source-{observation.id}",
        asset_type=asset_type,
        status=AssetStatus.ACTIVE,
        operating_system=(
            str(attrs["operating_system"])[:255] if attrs.get("operating_system") else None
        ),
        manufacturer=(str(attrs["manufacturer"])[:255] if attrs.get("manufacturer") else None),
        identity_confidence=70,
        first_seen_at=observation.observed_at,
        last_seen_at=observation.observed_at,
        metadata_json={"passive_source": True},
    )
    session.add(asset)
    await session.flush()
    for item in normalize_identifiers(observation.identifiers_json):
        session.add(
            AssetIdentifier(
                asset_id=asset.id,
                identifier_type=IdentifierType(item["type"]),
                identifier_value=item["value"],
                confidence=int(IDENTIFIER_WEIGHTS[IdentifierType(item["type"])]),
                first_seen_at=observation.observed_at,
                last_seen_at=observation.observed_at,
            )
        )
    await _link_observation(session, observation, asset, now=now)
    await _set_lifecycle(
        session,
        asset,
        InventoryAssetState.DISCOVERED,
        reason="new passive source identity",
        observation=observation,
        now=now,
    )
    return asset


async def _link_observation(
    session: AsyncSession, observation: AssetObservation, asset: Asset, *, now: datetime
) -> AssetSourceLink:
    link = await session.scalar(
        select(AssetSourceLink).where(
            AssetSourceLink.connector_id == observation.connector_id,
            AssetSourceLink.source_record_id == observation.source_record_id,
        )
    )
    if link is None:
        link = AssetSourceLink(
            organization_id=observation.organization_id,
            site_id=observation.site_id,
            connector_id=observation.connector_id,
            source_record_id=observation.source_record_id,
            asset_id=asset.id,
            first_observed_at=observation.observed_at,
            last_observed_at=observation.observed_at,
            identifiers_json=observation.identifiers_json,
        )
        session.add(link)
    else:
        link.asset_id = asset.id
        link.last_observed_at = _later(link.last_observed_at, observation.observed_at)
        link.identifiers_json = observation.identifiers_json
    observation.matched_asset_id = asset.id
    asset.last_seen_at = _later(asset.last_seen_at or now, observation.observed_at)
    return link


async def _merge_observation_identifiers(
    session: AsyncSession, observation: AssetObservation, asset: Asset
) -> dict[str, list[dict[str, Any]]]:
    existing = {
        (row.identifier_type, row.identifier_value.strip().lower()): row
        for row in (
            (
                await session.execute(
                    select(AssetIdentifier).where(AssetIdentifier.asset_id == asset.id)
                )
            )
            .scalars()
            .all()
        )
    }
    changes: dict[str, list[dict[str, Any]]] = {"added": [], "updated": []}
    for item in normalize_identifiers(observation.identifiers_json):
        kind = IdentifierType(item["type"])
        key = (kind, item["value"])
        if row := existing.get(key):
            prior_last_seen_at = row.last_seen_at
            row.last_seen_at = (
                _later(row.last_seen_at, observation.observed_at)
                if row.last_seen_at
                else observation.observed_at
            )
            if not _same_moment(prior_last_seen_at, row.last_seen_at):
                changes["updated"].append(
                    {
                        "identifier_type": kind.value,
                        "identifier_value": item["value"],
                        "prior_last_seen_at": (
                            prior_last_seen_at.isoformat() if prior_last_seen_at else None
                        ),
                    }
                )
            continue
        session.add(
            AssetIdentifier(
                asset_id=asset.id,
                identifier_type=kind,
                identifier_value=item["value"],
                confidence=int(IDENTIFIER_WEIGHTS[kind]),
                first_seen_at=observation.observed_at,
                last_seen_at=observation.observed_at,
            )
        )
        changes["added"].append({"identifier_type": kind.value, "identifier_value": item["value"]})
    return changes


async def merge_candidate(
    session: AsyncSession,
    candidate: ReconciliationCandidate,
    *,
    status: ReconciliationStatus,
    actor_user_id: uuid.UUID | None,
    now: datetime,
) -> None:
    if candidate.status not in (ReconciliationStatus.PENDING,):
        raise ReconciliationError("reconciliation candidate is no longer pending")
    if candidate.conflicts_json:
        raise ReconciliationError("conflicting immutable identifiers block this merge")
    observation = await session.get(AssetObservation, candidate.observation_id)
    asset = await session.scalar(
        select(Asset)
        .options(selectinload(Asset.identifiers))
        .where(Asset.id == candidate.candidate_asset_id)
    )
    if observation is None or asset is None:
        raise ReconciliationError("reconciliation source no longer exists")
    if observation.organization_id != asset.organization_id or observation.site_id != asset.site_id:
        raise ReconciliationError("reconciliation source and asset scopes do not match")
    current_score, _, current_conflicts = score_asset(observation.identifiers_json, asset)
    if current_conflicts:
        raise ReconciliationError("conflicting immutable identifiers block this merge")
    if current_score < REVIEW_THRESHOLD:
        raise ReconciliationError("reconciliation candidate no longer meets the review threshold")
    prior_link = await session.scalar(
        select(AssetSourceLink).where(
            AssetSourceLink.connector_id == observation.connector_id,
            AssetSourceLink.source_record_id == observation.source_record_id,
        )
    )
    prior_asset_last_seen_at = asset.last_seen_at
    snapshot = {
        "version": 1,
        "observation_id": str(observation.id),
        "prior_matched_asset_id": (
            str(observation.matched_asset_id) if observation.matched_asset_id else None
        ),
        "prior_source_link": (
            {
                "asset_id": str(prior_link.asset_id),
                "identifiers": prior_link.identifiers_json,
                "first_observed_at": prior_link.first_observed_at.isoformat(),
                "last_observed_at": prior_link.last_observed_at.isoformat(),
            }
            if prior_link
            else None
        ),
        "prior_asset_last_seen_at": (
            prior_asset_last_seen_at.isoformat() if prior_asset_last_seen_at else None
        ),
    }
    await _link_observation(session, observation, asset, now=now)
    snapshot["asset_identifier_changes"] = await _merge_observation_identifiers(
        session, observation, asset
    )
    candidate.merge_snapshot_json = snapshot
    await session.flush()
    await _set_lifecycle(
        session,
        asset,
        InventoryAssetState.ASSESSED if asset.last_assessed_at else InventoryAssetState.DISCOVERED,
        reason="passive observation reconciled",
        observation=observation,
        now=now,
    )
    candidate.status = status
    candidate.decided_by_user_id = actor_user_id
    candidate.decided_at = now


async def reconcile_observation(
    session: AsyncSession, observation: AssetObservation, *, now: datetime | None = None
) -> list[ReconciliationCandidate]:
    """Score exact identifiers and apply only an unambiguous >=95 merge."""

    now = now or datetime.now(UTC)
    identifiers = normalize_identifiers(observation.identifiers_json)
    predicates = [
        (AssetIdentifier.identifier_type == IdentifierType(item["type"]))
        & (func.lower(AssetIdentifier.identifier_value) == item["value"])
        for item in identifiers
    ]
    assets = (
        (
            await session.execute(
                select(Asset)
                .join(AssetIdentifier)
                .options(selectinload(Asset.identifiers))
                .where(
                    Asset.organization_id == observation.organization_id,
                    Asset.site_id == observation.site_id,
                    or_(*predicates),
                )
            )
        )
        .scalars()
        .unique()
        .all()
    )
    scored: list[tuple[Asset, float, list[dict[str, Any]], list[dict[str, Any]]]] = []
    for asset in assets:
        score, reasons, conflicts = score_asset(identifiers, asset)
        if score >= REVIEW_THRESHOLD:
            scored.append((asset, score, reasons, conflicts))
    scored.sort(key=lambda row: (-row[1], str(row[0].id)))
    candidates: list[ReconciliationCandidate] = []
    high_confidence = [row for row in scored if row[1] >= AUTO_MERGE_THRESHOLD and not row[3]]
    ambiguous = len(high_confidence) > 1
    for asset, score, reasons, conflicts in scored:
        stored_conflicts = list(conflicts)
        if ambiguous and score >= AUTO_MERGE_THRESHOLD:
            stored_conflicts.append({"kind": "ambiguous_high_confidence_candidate"})
        candidate = ReconciliationCandidate(
            organization_id=observation.organization_id,
            site_id=observation.site_id,
            observation_id=observation.id,
            candidate_asset_id=asset.id,
            score=score,
            reasons_json=reasons,
            conflicts_json=stored_conflicts,
            status=ReconciliationStatus.PENDING,
            merge_snapshot_json={},
        )
        session.add(candidate)
        candidates.append(candidate)
    await session.flush()
    if len(high_confidence) == 1:
        auto = next(
            item for item in candidates if item.candidate_asset_id == high_confidence[0][0].id
        )
        await merge_candidate(
            session,
            auto,
            status=ReconciliationStatus.AUTO_MERGED,
            actor_user_id=None,
            now=now,
        )
    elif not candidates:
        await _create_asset_from_observation(session, observation, now=now)
    return candidates


async def reject_candidate(
    session: AsyncSession,
    candidate: ReconciliationCandidate,
    *,
    actor_user_id: uuid.UUID,
    now: datetime,
) -> None:
    if candidate.status != ReconciliationStatus.PENDING:
        raise ReconciliationError("reconciliation candidate is no longer pending")
    candidate.status = ReconciliationStatus.REJECTED
    candidate.decided_by_user_id = actor_user_id
    candidate.decided_at = now
    observation = await session.get(AssetObservation, candidate.observation_id)
    if observation is None:
        raise ReconciliationError("reconciliation observation no longer exists")
    other_pending = await session.scalar(
        select(ReconciliationCandidate.id).where(
            ReconciliationCandidate.observation_id == observation.id,
            ReconciliationCandidate.id != candidate.id,
            ReconciliationCandidate.status == ReconciliationStatus.PENDING,
        )
    )
    if other_pending is None and observation.matched_asset_id is None:
        await _create_asset_from_observation(session, observation, now=now)


async def split_candidate(
    session: AsyncSession,
    candidate: ReconciliationCandidate,
    *,
    actor_user_id: uuid.UUID,
    now: datetime,
) -> Asset:
    if candidate.status not in (
        ReconciliationStatus.APPROVED,
        ReconciliationStatus.AUTO_MERGED,
    ):
        raise ReconciliationError("only a completed merge can be split")
    observation = await session.get(AssetObservation, candidate.observation_id)
    if observation is None or observation.matched_asset_id != candidate.candidate_asset_id:
        raise ReconciliationError("merge is no longer the active source mapping")
    target_asset = await session.get(Asset, candidate.candidate_asset_id)
    if target_asset is None:
        raise ReconciliationError("merged asset no longer exists")
    snapshot = candidate.merge_snapshot_json or {}
    identifier_changes = snapshot.get("asset_identifier_changes") or {}
    for item in identifier_changes.get("added", []):
        identifier = await session.scalar(
            select(AssetIdentifier).where(
                AssetIdentifier.asset_id == target_asset.id,
                AssetIdentifier.identifier_type == IdentifierType(item["identifier_type"]),
                func.lower(AssetIdentifier.identifier_value) == item["identifier_value"],
            )
        )
        if identifier is not None and _same_moment(
            identifier.last_seen_at, observation.observed_at
        ):
            await session.delete(identifier)
    for item in identifier_changes.get("updated", []):
        identifier = await session.scalar(
            select(AssetIdentifier).where(
                AssetIdentifier.asset_id == target_asset.id,
                AssetIdentifier.identifier_type == IdentifierType(item["identifier_type"]),
                func.lower(AssetIdentifier.identifier_value) == item["identifier_value"],
            )
        )
        if identifier is not None and _same_moment(
            identifier.last_seen_at, observation.observed_at
        ):
            prior = item.get("prior_last_seen_at")
            identifier.last_seen_at = datetime.fromisoformat(prior) if prior else None
    prior_asset_last_seen = snapshot.get("prior_asset_last_seen_at")
    prior_asset_last_seen_at = (
        datetime.fromisoformat(prior_asset_last_seen) if prior_asset_last_seen else None
    )
    merged_last_seen_at = (
        _later(prior_asset_last_seen_at, observation.observed_at)
        if prior_asset_last_seen_at
        else observation.observed_at
    )
    if _same_moment(target_asset.last_seen_at, merged_last_seen_at):
        target_asset.last_seen_at = prior_asset_last_seen_at
    link = await session.scalar(
        select(AssetSourceLink).where(
            AssetSourceLink.connector_id == observation.connector_id,
            AssetSourceLink.source_record_id == observation.source_record_id,
        )
    )
    prior_link = snapshot.get("prior_source_link")
    if prior_link:
        prior_asset_id = uuid.UUID(prior_link["asset_id"])
        prior_asset = await session.get(Asset, prior_asset_id)
        if (
            prior_asset is None
            or prior_asset.organization_id != observation.organization_id
            or prior_asset.site_id != observation.site_id
        ):
            raise ReconciliationError("prior source mapping can no longer be restored")
        if link is None:
            link = AssetSourceLink(
                organization_id=observation.organization_id,
                site_id=observation.site_id,
                connector_id=observation.connector_id,
                source_record_id=observation.source_record_id,
                asset_id=prior_asset_id,
                first_observed_at=datetime.fromisoformat(prior_link["first_observed_at"]),
                last_observed_at=datetime.fromisoformat(prior_link["last_observed_at"]),
                identifiers_json=prior_link["identifiers"],
            )
            session.add(link)
        else:
            link.asset_id = prior_asset_id
            link.first_observed_at = datetime.fromisoformat(prior_link["first_observed_at"])
            link.last_observed_at = datetime.fromisoformat(prior_link["last_observed_at"])
            link.identifiers_json = prior_link["identifiers"]
        prior_matched = snapshot.get("prior_matched_asset_id")
        observation.matched_asset_id = uuid.UUID(prior_matched) if prior_matched else None
        asset = prior_asset
    else:
        if link is not None:
            await session.delete(link)
        observation.matched_asset_id = None
        asset = await _create_asset_from_observation(session, observation, now=now)
    candidate.status = ReconciliationStatus.SPLIT
    candidate.decided_by_user_id = actor_user_id
    candidate.split_at = now
    await session.flush()
    return asset


async def sweep_inventory_states(
    session: AsyncSession,
    organization_id: uuid.UUID,
    *,
    now: datetime,
) -> dict[str, int]:
    """Derive stale/missing states without deleting observations or assets."""

    rows = (
        (
            await session.execute(
                select(AssetInventoryState).where(
                    AssetInventoryState.organization_id == organization_id
                )
            )
        )
        .scalars()
        .all()
    )
    changed = 0
    counts: dict[str, int] = {}
    for row in rows:
        reference = row.last_observed_at or row.assessed_at or row.discovered_at or row.created_at
        comparable_reference = reference if reference.tzinfo else reference.replace(tzinfo=UTC)
        age = now - comparable_reference
        previous = row.state
        if age > timedelta(days=row.stale_after_days * 2):
            row.state = InventoryAssetState.MISSING
            row.missing_since = row.missing_since or now
        elif age > timedelta(days=row.stale_after_days):
            row.state = InventoryAssetState.STALE
            row.missing_since = None
        elif row.assessed_at is not None:
            row.state = InventoryAssetState.ASSESSED
            row.missing_since = None
        elif row.last_observed_at is not None or row.discovered_at is not None:
            row.state = InventoryAssetState.DISCOVERED
            row.missing_since = None
        elif row.expected:
            row.state = InventoryAssetState.EXPECTED
            row.missing_since = None
        if previous != row.state:
            session.add(
                InventoryLifecycleEvent(
                    organization_id=row.organization_id,
                    site_id=row.site_id,
                    asset_id=row.asset_id,
                    previous_state=previous,
                    new_state=row.state,
                    reason="inventory freshness policy",
                    metadata_json={"stale_after_days": row.stale_after_days},
                )
            )
            changed += 1
        counts[row.state.value] = counts.get(row.state.value, 0) + 1
    return {"changed": changed, **counts}
