"""Safe asset grouping, tag compatibility, and deterministic ownership."""

from __future__ import annotations

import unicodedata
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.asset_context import (
    AssetGroup,
    AssetGroupMembership,
    AssetOwnershipHistory,
    AssetTag,
    AssetTagAssignment,
    DepartmentOwner,
)
from app.models.enums import (
    AssetGroupType,
    AssetMembershipSource,
    AssetTagSource,
    OwnershipSource,
)
from app.models.finding import Finding
from app.models.site import Site
from app.models.user import User

MAX_RULE_DEPTH = 6
MAX_RULE_NODES = 100
MAX_RULE_VALUE_LENGTH = 1024

RULE_FIELDS = frozenset(
    {
        "canonical_name",
        "asset_type",
        "status",
        "operating_system",
        "manufacturer",
        "site_id",
        "department",
        "business_function",
        "environment",
        "criticality",
        "data_classification",
        "internet_exposed",
        "tag",
    }
)
RULE_OPERATORS = frozenset(
    {"eq", "neq", "contains", "starts_with", "in", "not_in", "is_null", "is_not_null"}
)


class AssetContextError(ValueError):
    """An asset-context configuration is malformed or ambiguous."""


@dataclass(frozen=True)
class OwnershipResult:
    asset_id: uuid.UUID
    finding_id: uuid.UUID | None
    owner_user_id: uuid.UUID | None
    source: OwnershipSource
    source_id: uuid.UUID | None
    explanation: dict[str, Any]


def normalize_name(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).strip().split()).casefold()


def display_name(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).strip().split())


def validate_context_json(value: dict[str, Any]) -> dict[str, Any]:
    """Keep extension context small and JSON-shaped; structured fields stay first-class."""
    if len(value) > 50:
        raise AssetContextError("context_json supports at most 50 keys")

    def validate_item(item: Any, *, depth: int) -> None:
        if depth > 3:
            raise AssetContextError("context_json nesting is limited to 3 levels")
        if item is None or isinstance(item, (bool, int, float)):
            return
        if isinstance(item, str):
            if len(item) > 2048:
                raise AssetContextError("context_json strings are limited to 2048 characters")
            return
        if isinstance(item, list):
            if len(item) > 100:
                raise AssetContextError("context_json lists are limited to 100 values")
            for child in item:
                validate_item(child, depth=depth + 1)
            return
        if isinstance(item, dict):
            if len(item) > 50:
                raise AssetContextError("context_json objects are limited to 50 keys")
            for key, child in item.items():
                if not isinstance(key, str) or not key or len(key) > 64:
                    raise AssetContextError("context_json keys must be 1-64 character strings")
                validate_item(child, depth=depth + 1)
            return
        raise AssetContextError("context_json accepts JSON values only")

    validate_item(value, depth=0)
    return value


def validate_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Validate a bounded JSON AST. It is data, never parsed or executed as code."""
    node_count = 0

    def walk(node: Any, depth: int) -> None:
        nonlocal node_count
        node_count += 1
        if node_count > MAX_RULE_NODES:
            raise AssetContextError(f"Dynamic rules support at most {MAX_RULE_NODES} nodes")
        if depth > MAX_RULE_DEPTH:
            raise AssetContextError(f"Dynamic rule depth is limited to {MAX_RULE_DEPTH}")
        if not isinstance(node, dict):
            raise AssetContextError("Every dynamic-rule node must be an object")

        logical = set(node).intersection({"all", "any", "not"})
        if logical:
            if len(logical) != 1 or len(node) != 1:
                raise AssetContextError("Logical rule nodes must contain exactly one operator")
            key = next(iter(logical))
            child = node[key]
            if key == "not":
                walk(child, depth + 1)
                return
            if not isinstance(child, list) or not child:
                raise AssetContextError(f"'{key}' requires a non-empty list")
            if len(child) > 25:
                raise AssetContextError(f"'{key}' supports at most 25 child rules")
            for item in child:
                walk(item, depth + 1)
            return

        allowed_leaf_keys = {"field", "operator", "value"}
        if set(node) - allowed_leaf_keys:
            raise AssetContextError("Rule leaves accept only field, operator, and value")
        field = node.get("field")
        operator = node.get("operator")
        if field not in RULE_FIELDS:
            raise AssetContextError(f"Unsupported dynamic-rule field: {field}")
        if operator not in RULE_OPERATORS:
            raise AssetContextError(f"Unsupported dynamic-rule operator: {operator}")
        if operator in {"is_null", "is_not_null"}:
            if "value" in node:
                raise AssetContextError(f"'{operator}' does not accept a value")
            return
        if "value" not in node:
            raise AssetContextError(f"'{operator}' requires a value")
        value = node["value"]

        def validate_scalar(item: Any) -> None:
            if item is not None and not isinstance(item, (bool, int, float, str)):
                raise AssetContextError(f"'{operator}' accepts scalar JSON values only")
            if isinstance(item, str) and len(item) > MAX_RULE_VALUE_LENGTH:
                raise AssetContextError(
                    f"Dynamic-rule strings are limited to {MAX_RULE_VALUE_LENGTH} characters"
                )

        if operator in {"in", "not_in"}:
            if not isinstance(value, list) or not value or len(value) > 100:
                raise AssetContextError(f"'{operator}' requires 1-100 values")
            for item in value:
                validate_scalar(item)
        elif operator in {"contains", "starts_with"} and not isinstance(value, str):
            raise AssetContextError(f"'{operator}' requires a string value")
        else:
            validate_scalar(value)

    walk(rule, 1)
    return rule


def _serial(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


def _compare(actual: Any, operator: str, expected: Any) -> bool:
    actual = _serial(actual)
    if isinstance(actual, str):
        comparable_actual: Any = actual.casefold()
    elif isinstance(actual, list):
        comparable_actual = [str(item).casefold() for item in actual]
    else:
        comparable_actual = actual

    def comparable(value: Any) -> Any:
        serialized = _serial(value)
        return serialized.casefold() if isinstance(serialized, str) else serialized

    if operator == "is_null":
        return actual is None
    if operator == "is_not_null":
        return actual is not None
    if operator == "eq":
        expected_value = comparable(expected)
        if isinstance(comparable_actual, list):
            return bool(expected_value in comparable_actual)
        return bool(comparable_actual == expected_value)
    if operator == "neq":
        return not _compare(actual, "eq", expected)
    if operator == "contains":
        needle = str(expected).casefold()
        if isinstance(comparable_actual, list):
            return any(needle in str(value) for value in comparable_actual)
        return needle in str(comparable_actual or "")
    if operator == "starts_with":
        return str(comparable_actual or "").startswith(str(expected).casefold())
    expected_values = [comparable(value) for value in expected]
    if operator == "in":
        if isinstance(comparable_actual, list):
            return any(value in expected_values for value in comparable_actual)
        return comparable_actual in expected_values
    if operator == "not_in":
        return not _compare(actual, "in", expected)
    raise AssetContextError(f"Unsupported operator: {operator}")


def evaluate_rule(
    rule: dict[str, Any], asset: Asset, tag_names: set[str]
) -> tuple[bool, dict[str, Any]]:
    """Evaluate a validated AST and return an explanation tree."""
    facts: dict[str, Any] = {
        "canonical_name": asset.canonical_name,
        "asset_type": asset.asset_type,
        "status": asset.status,
        "operating_system": asset.operating_system,
        "manufacturer": asset.manufacturer,
        "site_id": asset.site_id,
        "department": asset.department,
        "business_function": asset.business_function,
        "environment": asset.environment,
        "criticality": asset.criticality,
        "data_classification": asset.data_classification,
        "internet_exposed": asset.internet_exposed,
        "tag": sorted(tag_names),
    }

    def walk(node: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        if "all" in node:
            children = [walk(value) for value in node["all"]]
            matched = all(value[0] for value in children)
            return matched, {
                "operator": "all",
                "matched": matched,
                "children": [value[1] for value in children],
            }
        if "any" in node:
            children = [walk(value) for value in node["any"]]
            matched = any(value[0] for value in children)
            return matched, {
                "operator": "any",
                "matched": matched,
                "children": [value[1] for value in children],
            }
        if "not" in node:
            child_matched, child = walk(node["not"])
            return not child_matched, {
                "operator": "not",
                "matched": not child_matched,
                "child": child,
            }
        field = str(node["field"])
        operator = str(node["operator"])
        actual = facts[field]
        expected = node.get("value")
        matched = _compare(actual, operator, expected)
        return matched, {
            "field": field,
            "operator": operator,
            "actual": _serial(actual),
            "expected": expected,
            "matched": matched,
        }

    validate_rule(rule)
    return walk(rule)


async def tag_names_by_asset(
    session: AsyncSession, organization_id: uuid.UUID, asset_ids: list[uuid.UUID]
) -> dict[uuid.UUID, set[str]]:
    result: dict[uuid.UUID, set[str]] = {asset_id: set() for asset_id in asset_ids}
    if not asset_ids:
        return result
    rows = (
        await session.execute(
            select(AssetTagAssignment.asset_id, AssetTag.normalized_name)
            .join(AssetTag, AssetTag.id == AssetTagAssignment.tag_id)
            .where(
                AssetTagAssignment.organization_id == organization_id,
                AssetTagAssignment.asset_id.in_(asset_ids),
            )
        )
    ).all()
    for asset_id, name in rows:
        result.setdefault(asset_id, set()).add(name)
    return result


async def sync_legacy_tags(session: AsyncSession, asset: Asset) -> None:
    """Keep the `/api/v1` tags_json compatibility field as a derived projection."""
    names = list(
        (
            await session.execute(
                select(AssetTag.name)
                .join(AssetTagAssignment, AssetTagAssignment.tag_id == AssetTag.id)
                .where(
                    AssetTagAssignment.organization_id == asset.organization_id,
                    AssetTagAssignment.asset_id == asset.id,
                )
                .order_by(AssetTag.normalized_name)
            )
        ).scalars()
    )
    asset.tags_json = names


async def validate_owner(
    session: AsyncSession, organization_id: uuid.UUID, owner_user_id: uuid.UUID | None
) -> None:
    if owner_user_id is None:
        return
    user = await session.get(User, owner_user_id)
    if user is None or user.organization_id != organization_id or not user.is_active:
        raise AssetContextError("Owner must be an active user in this organization")


async def validate_group_tie(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    priority: int,
    owner_user_id: uuid.UUID | None,
    enabled: bool,
    site_id: uuid.UUID | None,
    exclude_group_id: uuid.UUID | None = None,
) -> None:
    """Reject possible equal-priority owner matches before they become ambiguous."""
    if owner_user_id is None or not enabled:
        return
    filters: list[Any] = [
        AssetGroup.organization_id == organization_id,
        AssetGroup.enabled.is_(True),
        AssetGroup.owner_user_id.is_not(None),
        AssetGroup.priority == priority,
    ]
    if site_id is not None:
        filters.append(or_(AssetGroup.site_id.is_(None), AssetGroup.site_id == site_id))
    if exclude_group_id is not None:
        filters.append(AssetGroup.id != exclude_group_id)
    existing = await session.scalar(select(AssetGroup.id).where(*filters).limit(1))
    if existing is not None:
        raise AssetContextError(
            "Ownership group priority conflicts with another potentially matching group"
        )


async def preview_rule(
    session: AsyncSession,
    organization_id: uuid.UUID,
    rule: dict[str, Any],
    *,
    site_id: uuid.UUID | None = None,
) -> list[tuple[Asset, dict[str, Any]]]:
    validate_rule(rule)
    filters = [Asset.organization_id == organization_id]
    if site_id is not None:
        filters.append(Asset.site_id == site_id)
    assets = list((await session.execute(select(Asset).where(*filters))).scalars())
    tags = await tag_names_by_asset(session, organization_id, [asset.id for asset in assets])
    matches: list[tuple[Asset, dict[str, Any]]] = []
    for asset in assets:
        matched, explanation = evaluate_rule(rule, asset, tags.get(asset.id, set()))
        if matched:
            matches.append((asset, explanation))
    return matches


async def materialize_dynamic_group(
    session: AsyncSession, group: AssetGroup, *, now: datetime | None = None
) -> tuple[int, int]:
    if group.group_type != AssetGroupType.DYNAMIC or group.rule_json is None:
        raise AssetContextError("Only dynamic groups can be evaluated")
    matches = (
        await preview_rule(session, group.organization_id, group.rule_json, site_id=group.site_id)
        if group.enabled
        else []
    )
    matched = {asset.id: explanation for asset, explanation in matches}
    existing = {
        membership.asset_id: membership
        for membership in (
            await session.execute(
                select(AssetGroupMembership).where(AssetGroupMembership.group_id == group.id)
            )
        ).scalars()
    }
    removed = 0
    for asset_id, current_membership in existing.items():
        if asset_id not in matched:
            await session.delete(current_membership)
            removed += 1
    added = 0
    for asset_id, explanation in matched.items():
        existing_membership = existing.get(asset_id)
        if existing_membership is None:
            session.add(
                AssetGroupMembership(
                    organization_id=group.organization_id,
                    group_id=group.id,
                    asset_id=asset_id,
                    source=AssetMembershipSource.DYNAMIC,
                    explanation_json=explanation,
                )
            )
            added += 1
        else:
            existing_membership.source = AssetMembershipSource.DYNAMIC
            existing_membership.explanation_json = explanation
    group.last_evaluated_at = now or datetime.now(UTC)
    await session.flush()
    return added, removed


async def refresh_dynamic_memberships_for_asset(
    session: AsyncSession, asset: Asset, *, now: datetime | None = None
) -> tuple[int, int]:
    """Re-evaluate one asset after discovery, context, or tag changes."""
    groups = list(
        (
            await session.execute(
                select(AssetGroup).where(
                    AssetGroup.organization_id == asset.organization_id,
                    AssetGroup.group_type == AssetGroupType.DYNAMIC,
                )
            )
        ).scalars()
    )
    if not groups:
        return 0, 0
    tag_names = (await tag_names_by_asset(session, asset.organization_id, [asset.id]))[asset.id]
    added = removed = 0
    evaluated_at = now or datetime.now(UTC)
    for group in groups:
        in_group_scope = group.site_id is None or group.site_id == asset.site_id
        if group.enabled and in_group_scope and group.rule_json is not None:
            matched, explanation = evaluate_rule(group.rule_json, asset, tag_names)
        else:
            matched, explanation = (
                False,
                {
                    "matched": False,
                    "reason": "Group is disabled or the asset is outside its site scope",
                },
            )
        membership = await session.scalar(
            select(AssetGroupMembership).where(
                AssetGroupMembership.group_id == group.id,
                AssetGroupMembership.asset_id == asset.id,
            )
        )
        if matched and membership is None:
            session.add(
                AssetGroupMembership(
                    organization_id=asset.organization_id,
                    group_id=group.id,
                    asset_id=asset.id,
                    source=AssetMembershipSource.DYNAMIC,
                    explanation_json=explanation,
                )
            )
            added += 1
        elif matched and membership is not None:
            membership.source = AssetMembershipSource.DYNAMIC
            membership.explanation_json = explanation
        elif not matched and membership is not None:
            await session.delete(membership)
            removed += 1
        group.last_evaluated_at = evaluated_at
    await session.flush()
    return added, removed


async def resolve_ownership(
    session: AsyncSession,
    asset: Asset,
    *,
    finding: Finding | None = None,
) -> OwnershipResult:
    if finding is not None:
        if finding.organization_id != asset.organization_id or finding.asset_id != asset.id:
            raise AssetContextError("Finding does not belong to this asset")
        if finding.owner_user_id is not None:
            return OwnershipResult(
                asset.id,
                finding.id,
                finding.owner_user_id,
                OwnershipSource.EXPLICIT_FINDING,
                finding.id,
                {"precedence": 1, "reason": "Finding has an explicit owner"},
            )
    if asset.owner_user_id is not None:
        return OwnershipResult(
            asset.id,
            finding.id if finding else None,
            asset.owner_user_id,
            OwnershipSource.EXPLICIT_ASSET,
            asset.id,
            {"precedence": 2, "reason": "Asset has an explicit owner"},
        )

    groups = list(
        (
            await session.execute(
                select(AssetGroup)
                .join(AssetGroupMembership, AssetGroupMembership.group_id == AssetGroup.id)
                .where(
                    AssetGroup.organization_id == asset.organization_id,
                    AssetGroupMembership.asset_id == asset.id,
                    AssetGroup.enabled.is_(True),
                    AssetGroup.owner_user_id.is_not(None),
                )
                .order_by(AssetGroup.priority.desc(), AssetGroup.id)
            )
        ).scalars()
    )
    if groups:
        if len(groups) > 1 and groups[0].priority == groups[1].priority:
            raise AssetContextError("Asset matches tied ownership groups; resolve the priorities")
        group = groups[0]
        return OwnershipResult(
            asset.id,
            finding.id if finding else None,
            group.owner_user_id,
            OwnershipSource.GROUP,
            group.id,
            {
                "precedence": 3,
                "reason": "Highest-priority matching asset group",
                "group_name": group.name,
                "priority": group.priority,
            },
        )

    site = await session.get(Site, asset.site_id)
    if site is not None and site.owner_user_id is not None:
        return OwnershipResult(
            asset.id,
            finding.id if finding else None,
            site.owner_user_id,
            OwnershipSource.SITE,
            site.id,
            {"precedence": 4, "reason": "Site fallback owner", "site_name": site.name},
        )
    if asset.department:
        department = await session.scalar(
            select(DepartmentOwner).where(
                DepartmentOwner.organization_id == asset.organization_id,
                DepartmentOwner.department_key == normalize_name(asset.department),
            )
        )
        if department is not None:
            return OwnershipResult(
                asset.id,
                finding.id if finding else None,
                department.owner_user_id,
                OwnershipSource.DEPARTMENT,
                department.id,
                {
                    "precedence": 5,
                    "reason": "Department fallback owner",
                    "department": department.department,
                },
            )
    return OwnershipResult(
        asset.id,
        finding.id if finding else None,
        None,
        OwnershipSource.UNASSIGNED,
        None,
        {"precedence": 6, "reason": "No configured owner matched"},
    )


async def record_ownership_snapshot(
    session: AsyncSession, result: OwnershipResult
) -> AssetOwnershipHistory | None:
    asset = await session.get(Asset, result.asset_id)
    if asset is None:
        raise AssetContextError("Asset not found")
    last = await session.scalar(
        select(AssetOwnershipHistory)
        .where(
            AssetOwnershipHistory.organization_id == asset.organization_id,
            AssetOwnershipHistory.asset_id == result.asset_id,
            (
                AssetOwnershipHistory.finding_id.is_(None)
                if result.finding_id is None
                else AssetOwnershipHistory.finding_id == result.finding_id
            ),
        )
        .order_by(AssetOwnershipHistory.created_at.desc())
        .limit(1)
    )
    if (
        last is not None
        and last.owner_user_id == result.owner_user_id
        and last.source == result.source
        and last.source_id == result.source_id
    ):
        return None
    row = AssetOwnershipHistory(
        organization_id=asset.organization_id,
        asset_id=asset.id,
        finding_id=result.finding_id,
        owner_user_id=result.owner_user_id,
        source=result.source,
        source_id=result.source_id,
        explanation_json=result.explanation,
        created_at=datetime.now(UTC),
    )
    session.add(row)
    await session.flush()
    return row


async def ensure_tag(
    session: AsyncSession,
    organization_id: uuid.UUID,
    name: str,
    *,
    description: str | None = None,
    color: str | None = None,
) -> AssetTag:
    clean_name = display_name(name)
    normalized = normalize_name(clean_name)
    if not normalized:
        raise AssetContextError("Tag name cannot be blank")
    tag = await session.scalar(
        select(AssetTag).where(
            AssetTag.organization_id == organization_id,
            AssetTag.normalized_name == normalized,
        )
    )
    if tag is None:
        tag = AssetTag(
            organization_id=organization_id,
            name=clean_name,
            normalized_name=normalized,
            description=description,
            color=color,
        )
        session.add(tag)
        await session.flush()
    return tag


async def assign_tag(
    session: AsyncSession,
    asset: Asset,
    tag: AssetTag,
    *,
    source: AssetTagSource = AssetTagSource.MANUAL,
    assigned_by_user_id: uuid.UUID | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[AssetTagAssignment, bool]:
    if tag.organization_id != asset.organization_id:
        raise AssetContextError("Tag and asset must belong to the same organization")
    existing = await session.scalar(
        select(AssetTagAssignment).where(
            AssetTagAssignment.asset_id == asset.id,
            AssetTagAssignment.tag_id == tag.id,
        )
    )
    if existing is not None:
        return existing, False
    assignment = AssetTagAssignment(
        organization_id=asset.organization_id,
        asset_id=asset.id,
        tag_id=tag.id,
        source=source,
        assigned_by_user_id=assigned_by_user_id,
        metadata_json=metadata or {},
    )
    session.add(assignment)
    await session.flush()
    await sync_legacy_tags(session, asset)
    await refresh_dynamic_memberships_for_asset(session, asset)
    return assignment, True


async def remove_tag(session: AsyncSession, asset: Asset, tag_id: uuid.UUID) -> bool:
    assignment = await session.scalar(
        select(AssetTagAssignment).where(
            AssetTagAssignment.organization_id == asset.organization_id,
            AssetTagAssignment.asset_id == asset.id,
            AssetTagAssignment.tag_id == tag_id,
        )
    )
    if assignment is None:
        return False
    await session.delete(assignment)
    await session.flush()
    await sync_legacy_tags(session, asset)
    await refresh_dynamic_memberships_for_asset(session, asset)
    return True


async def resolve_report_asset_ids(
    session: AsyncSession,
    *,
    organization_id: uuid.UUID,
    site_id: uuid.UUID,
    tag_ids: list[uuid.UUID],
    group_ids: list[uuid.UUID],
) -> set[uuid.UUID] | None:
    """Resolve report filters with AND semantics across every selected tag/group."""
    unique_tags = set(tag_ids)
    unique_groups = set(group_ids)
    if not unique_tags and not unique_groups:
        return None
    if unique_tags:
        found_tags = set(
            (
                await session.execute(
                    select(AssetTag.id).where(
                        AssetTag.organization_id == organization_id,
                        AssetTag.id.in_(unique_tags),
                    )
                )
            ).scalars()
        )
        if found_tags != unique_tags:
            raise AssetContextError("One or more report tag filters were not found")
    if unique_groups:
        groups = list(
            (
                await session.execute(
                    select(AssetGroup).where(
                        AssetGroup.organization_id == organization_id,
                        AssetGroup.id.in_(unique_groups),
                        AssetGroup.enabled.is_(True),
                    )
                )
            ).scalars()
        )
        if {group.id for group in groups} != unique_groups:
            raise AssetContextError("One or more report group filters were not found")
        if any(group.site_id is not None and group.site_id != site_id for group in groups):
            raise AssetContextError("A report group filter belongs to a different site")

    candidates = set(
        (
            await session.execute(
                select(Asset.id).where(
                    Asset.organization_id == organization_id,
                    Asset.site_id == site_id,
                )
            )
        ).scalars()
    )
    if unique_tags:
        tag_matches = set(
            (
                await session.execute(
                    select(AssetTagAssignment.asset_id)
                    .where(
                        AssetTagAssignment.organization_id == organization_id,
                        AssetTagAssignment.tag_id.in_(unique_tags),
                    )
                    .group_by(AssetTagAssignment.asset_id)
                    .having(
                        func.count(func.distinct(AssetTagAssignment.tag_id)) == len(unique_tags)
                    )
                )
            ).scalars()
        )
        candidates.intersection_update(tag_matches)
    if unique_groups:
        group_matches = set(
            (
                await session.execute(
                    select(AssetGroupMembership.asset_id)
                    .join(AssetGroup, AssetGroup.id == AssetGroupMembership.group_id)
                    .where(
                        AssetGroupMembership.organization_id == organization_id,
                        AssetGroupMembership.group_id.in_(unique_groups),
                        AssetGroup.enabled.is_(True),
                    )
                    .group_by(AssetGroupMembership.asset_id)
                    .having(
                        func.count(func.distinct(AssetGroupMembership.group_id))
                        == len(unique_groups)
                    )
                )
            ).scalars()
        )
        candidates.intersection_update(group_matches)
    return candidates
