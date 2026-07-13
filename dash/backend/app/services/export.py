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
from app.models.asset_context import (
    AssetGroup,
    AssetGroupMembership,
    AssetOwnershipHistory,
    AssetTag,
    AssetTagAssignment,
    DepartmentOwner,
)
from app.models.authorization import (
    ApiToken,
    AuthorizationRole,
    RolePermission,
    ScopedGrant,
    ServiceAccount,
)
from app.models.credential import (
    CredentialAssignment,
    CredentialRecord,
    CredentialSecretVersion,
    CredentialTest,
    CredentialUsageAudit,
)
from app.models.finding import Finding
from app.models.finding_note import FindingNote
from app.models.network_scope import NetworkScope
from app.models.organization import Organization
from app.models.probe import Probe
from app.models.report import Report
from app.models.risk import (
    FindingDecision,
    FindingScoreSnapshot,
    RemediationSuggestion,
    RemediationUnit,
    RemediationUnitFinding,
    RiskProfile,
)
from app.models.risk_acceptance import RiskAcceptance
from app.models.scim import (
    ScimGroup,
    ScimGroupMember,
    ScimGroupSiteMapping,
    ScimProvisioningLog,
)
from app.models.service import Service
from app.models.site import Site
from app.models.sla import (
    FindingSlaCalculation,
    RemediationGuidance,
    SlaException,
    SlaHistory,
    SlaPolicy,
)
from app.models.software import EolOverride, SoftwareInventoryHistory, SoftwareInventoryItem
from app.models.ticketing import TicketConnector, TicketSync, TicketSyncEvent
from app.models.user import User
from app.models.user_lifecycle import UserSiteAssignment

EXPORT_SCHEMA_VERSION = "7"
SUPPORTED_IMPORT_SCHEMA_VERSIONS = {
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    EXPORT_SCHEMA_VERSION,
}
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
            "id": str(org.id),
            "name": org.name,
            "slug": org.slug,
            "default_timezone": org.default_timezone,
            "experience_profile": org.experience_profile.value,
            "feature_overrides": org.feature_overrides_json,
        },
        "users": await _users(session, org_id),
        "user_site_assignments": await _user_site_assignments(session, org_id),
        "authorization_roles": await _authorization_roles(session, org_id),
        "scoped_grants": await _scoped_grants(session, org_id),
        "service_accounts": await _service_accounts(session, org_id),
        "api_tokens": await _api_tokens(session, org_id),
        "credential_records": await _credential_records(session, org_id),
        "credential_assignments": await _credential_assignments(session, org_id),
        "credential_tests": await _credential_tests(session, org_id),
        "credential_usage": await _credential_usage(session, org_id),
        "scim_groups": await _scim_groups(session, org_id),
        "scim_group_members": await _scim_group_members(session, org_id),
        "scim_group_site_mappings": await _scim_group_site_mappings(session, org_id),
        "scim_provisioning_logs": await _scim_provisioning_logs(session, org_id),
        "sites": await _sites(session, org_id),
        "network_scopes": await _scopes(session, org_id),
        "scouts": await _scouts(session, org_id),
        "assets": await _assets(session, org_id),
        "asset_tags": await _asset_tags(session, org_id),
        "asset_tag_assignments": await _asset_tag_assignments(session, org_id),
        "asset_groups": await _asset_groups(session, org_id),
        "asset_group_memberships": await _asset_group_memberships(session, org_id),
        "department_owners": await _department_owners(session, org_id),
        "asset_ownership_history": await _asset_ownership_history(session, org_id),
        "services": await _services(session, org_id),
        "software_inventory": await _software_inventory(session, org_id),
        "software_history": await _software_history(session, org_id),
        "eol_overrides": await _eol_overrides(session, org_id),
        "findings": await _findings(session, org_id),
        "risk_profiles": await _risk_profiles(session, org_id),
        "finding_score_snapshots": await _finding_score_snapshots(session, org_id),
        "remediation_units": await _remediation_units(session, org_id),
        "remediation_unit_findings": await _remediation_unit_findings(session, org_id),
        "remediation_suggestions": await _remediation_suggestions(session, org_id),
        "finding_decisions": await _finding_decisions(session, org_id),
        "sla_policies": await _sla_policies(session, org_id),
        "finding_sla_calculations": await _finding_sla_calculations(session, org_id),
        "sla_exceptions": await _sla_exceptions(session, org_id),
        "sla_history": await _sla_history(session, org_id),
        "remediation_guidance": await _remediation_guidance(session, org_id),
        "ticket_connectors": await _ticket_connectors(session, org_id),
        "ticket_syncs": await _ticket_syncs(session, org_id),
        "ticket_sync_events": await _ticket_sync_events(session, org_id),
        "reports": await _reports(session, org_id),
        "risk_acceptances": await _risk_acceptances(session, org_id),
        "finding_notes": await _finding_notes(session, org_id),
    }
    bundle[CHECKSUM_FIELD] = checksum(bundle)
    return bundle


async def _users(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    """Lifecycle metadata only; authentication material is categorically excluded."""
    rows = (await session.execute(select(User).where(User.organization_id == org_id))).scalars()
    return [
        {
            "id": str(user.id),
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role.value,
            "account_status": user.account_status.value,
            "authentication_source": user.authentication_source.value,
            "scim_external_id": user.scim_external_id,
            "site_access_mode": user.site_access_mode.value,
            "last_login_at": _iso(user.last_login_at),
        }
        for user in rows
    ]


async def _user_site_assignments(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(UserSiteAssignment).where(UserSiteAssignment.organization_id == org_id)
        )
    ).scalars()
    return [{"user_id": str(row.user_id), "site_id": str(row.site_id)} for row in rows]


async def _authorization_roles(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    roles = list(
        (
            await session.execute(
                select(AuthorizationRole).where(AuthorizationRole.organization_id == org_id)
            )
        ).scalars()
    )
    permissions = list(
        (
            await session.execute(
                select(RolePermission).where(RolePermission.organization_id == org_id)
            )
        ).scalars()
    )
    by_role: dict[uuid.UUID, list[str]] = {}
    for permission in permissions:
        by_role.setdefault(permission.role_id, []).append(permission.permission_key)
    return [
        {
            "id": str(role.id),
            "key": role.key,
            "name": role.name,
            "description": role.description,
            "is_system": role.is_system,
            "compatibility_role": (
                role.compatibility_role.value if role.compatibility_role else None
            ),
            "permission_keys": sorted(by_role.get(role.id, [])),
        }
        for role in roles
    ]


async def _scoped_grants(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(ScopedGrant).where(ScopedGrant.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(row.id),
            "principal_type": row.principal_type.value,
            "principal_id": str(row.user_id or row.service_account_id),
            "role_id": str(row.role_id),
            "scope_type": row.scope_type.value,
            "scope_id": str(row.scope_id),
        }
        for row in rows
    ]


async def _service_accounts(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(ServiceAccount).where(ServiceAccount.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "name": row.name,
            "description": row.description,
            "status": row.status.value,
            "primary_role": row.primary_role.value,
            "last_used_at": _iso(row.last_used_at),
        }
        for row in rows
    ]


async def _api_tokens(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    """Export lifecycle metadata only; token hashes and values never leave the database."""
    rows = (
        await session.execute(select(ApiToken).where(ApiToken.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(row.id),
            "principal_type": row.principal_type.value,
            "principal_id": str(row.user_id or row.service_account_id),
            "name": row.name,
            "has_secret": True,
            "expires_at": _iso(row.expires_at),
            "revoked_at": _iso(row.revoked_at),
            "ip_restrictions": list(row.ip_restrictions_json or []),
            "last_used_at": _iso(row.last_used_at),
        }
        for row in rows
    ]


async def _credential_records(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    """Export metadata and version numbers only; encrypted secret values never leave storage."""
    records = list(
        (
            await session.execute(
                select(CredentialRecord).where(CredentialRecord.organization_id == org_id)
            )
        ).scalars()
    )
    versions = list(
        (
            await session.execute(
                select(CredentialSecretVersion).where(
                    CredentialSecretVersion.organization_id == org_id
                )
            )
        ).scalars()
    )
    latest: dict[uuid.UUID, int] = {}
    for version in versions:
        latest[version.credential_id] = max(latest.get(version.credential_id, 0), version.version)
    return [
        {
            "id": str(row.id),
            "name": row.name,
            "description": row.description,
            "protocol": row.protocol.value,
            "auth_type": row.auth_type.value,
            "username": row.username,
            "metadata": row.metadata_json,
            "is_active": row.is_active,
            "has_secret": row.id in latest,
            "current_version": latest.get(row.id, 0),
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
        }
        for row in records
    ]


async def _credential_assignments(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(CredentialAssignment).where(CredentialAssignment.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "credential_id": str(row.credential_id),
            "target_type": row.target_type.value,
            "target_id": row.target_id,
            "site_id": str(row.site_id) if row.site_id else None,
            "enabled": row.enabled,
        }
        for row in rows
    ]


async def _credential_tests(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = list(
        (
            await session.execute(
                select(CredentialTest).where(CredentialTest.organization_id == org_id)
            )
        ).scalars()
    )
    versions = {
        row.id: row.version
        for row in (
            await session.execute(
                select(CredentialSecretVersion).where(
                    CredentialSecretVersion.organization_id == org_id
                )
            )
        ).scalars()
    }
    return [
        {
            "id": str(row.id),
            "credential_id": str(row.credential_id),
            "secret_version": versions.get(row.secret_version_id),
            "asset_id": str(row.asset_id),
            "scan_job_id": str(row.scan_job_id) if row.scan_job_id else None,
            "status": row.status.value,
            "message": row.message,
            "created_at": _iso(row.created_at),
            "finished_at": _iso(row.finished_at),
        }
        for row in rows
    ]


async def _credential_usage(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(CredentialUsageAudit).where(CredentialUsageAudit.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "credential_id": str(row.credential_id),
            "asset_id": str(row.asset_id),
            "probe_id": str(row.probe_id),
            "scan_job_id": str(row.scan_job_id) if row.scan_job_id else None,
            "protocol": row.protocol.value,
            "status": row.status.value,
            "detail": row.detail,
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _scim_groups(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(ScimGroup).where(ScimGroup.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(row.id),
            "display_name": row.display_name,
            "external_id": row.external_id,
            "mapped_role": row.mapped_role.value if row.mapped_role else None,
            "grants_all_sites": row.grants_all_sites,
            "asset_group_ids": [
                str(target["asset_group_id"])
                for target in row.asset_group_targets_json or []
                if target.get("asset_group_id")
            ],
        }
        for row in rows
    ]


async def _scim_group_members(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(ScimGroupMember).where(ScimGroupMember.organization_id == org_id)
        )
    ).scalars()
    return [{"group_id": str(row.group_id), "user_id": str(row.user_id)} for row in rows]


async def _scim_group_site_mappings(
    session: AsyncSession, org_id: uuid.UUID
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(ScimGroupSiteMapping).where(ScimGroupSiteMapping.organization_id == org_id)
        )
    ).scalars()
    return [{"group_id": str(row.group_id), "site_id": str(row.site_id)} for row in rows]


async def _scim_provisioning_logs(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    # Token identifiers and source IPs are deliberately excluded. The portable
    # history is useful without becoming a credential or network-metadata export.
    rows = (
        await session.execute(
            select(ScimProvisioningLog).where(ScimProvisioningLog.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "operation": row.operation,
            "resource_type": row.resource_type,
            "resource_id": row.resource_id,
            "external_id": row.external_id,
            "status_code": row.status_code,
            "succeeded": row.succeeded,
            "detail": row.detail,
            "request_id": row.request_id,
            "changes": row.changes_json,
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _sites(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (await session.execute(select(Site).where(Site.organization_id == org_id))).scalars()
    return [
        {
            "id": str(s.id),
            "name": s.name,
            "code": s.code,
            "description": s.description,
            "tags": s.tags,
            "owner_user_id": str(s.owner_user_id) if s.owner_user_id else None,
        }
        for s in rows
    ]


async def _scopes(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(NetworkScope).where(NetworkScope.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(x.id),
            "site_id": str(x.site_id),
            "name": x.name,
            "cidr": x.cidr,
            "enabled": x.enabled,
            "allow_public_addresses": x.allow_public_addresses,
            "approved_at": _iso(x.approved_at),
            "expires_at": _iso(x.expires_at),
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
            "id": str(p.id),
            "name": p.name,
            "status": p.status.value,
            "certificate_fingerprint": p.certificate_fingerprint,
            "agent_version": p.agent_version,
            "credentialed_scans_enabled": p.credentialed_scans_enabled,
            "has_encryption_key": bool(p.encryption_public_key_b64),
            "last_seen_at": _iso(p.last_seen_at),
        }
        for p in rows
    ]


async def _assets(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (await session.execute(select(Asset).where(Asset.organization_id == org_id))).scalars()
    return [
        {
            "id": str(a.id),
            "site_id": str(a.site_id),
            "canonical_name": a.canonical_name,
            "asset_type": a.asset_type.value,
            "status": a.status.value,
            "department": a.department,
            "business_function": a.business_function,
            "environment": a.environment.value,
            "criticality": a.criticality.value,
            "data_classification": a.data_classification.value,
            "internet_exposed": a.internet_exposed,
            "owner_user_id": str(a.owner_user_id) if a.owner_user_id else None,
            "context": a.context_json,
            "legacy_tags": a.tags_json,
            "metadata": a.metadata_json,
        }
        for a in rows
    ]


async def _asset_tags(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(AssetTag).where(AssetTag.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(row.id),
            "name": row.name,
            "description": row.description,
            "color": row.color,
        }
        for row in rows
    ]


async def _asset_tag_assignments(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(AssetTagAssignment).where(AssetTagAssignment.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "asset_id": str(row.asset_id),
            "tag_id": str(row.tag_id),
            "source": row.source.value,
            "metadata": row.metadata_json,
        }
        for row in rows
    ]


async def _asset_groups(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(AssetGroup).where(AssetGroup.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id) if row.site_id else None,
            "name": row.name,
            "description": row.description,
            "group_type": row.group_type.value,
            "rule": row.rule_json,
            "priority": row.priority,
            "owner_user_id": str(row.owner_user_id) if row.owner_user_id else None,
            "enabled": row.enabled,
            "last_evaluated_at": _iso(row.last_evaluated_at),
        }
        for row in rows
    ]


async def _asset_group_memberships(
    session: AsyncSession, org_id: uuid.UUID
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(AssetGroupMembership).where(AssetGroupMembership.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "group_id": str(row.group_id),
            "asset_id": str(row.asset_id),
            "source": row.source.value,
            "explanation": row.explanation_json,
        }
        for row in rows
    ]


async def _department_owners(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(DepartmentOwner).where(DepartmentOwner.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "department": row.department,
            "owner_user_id": str(row.owner_user_id),
        }
        for row in rows
    ]


async def _asset_ownership_history(
    session: AsyncSession, org_id: uuid.UUID
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(AssetOwnershipHistory).where(AssetOwnershipHistory.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "asset_id": str(row.asset_id),
            "finding_id": str(row.finding_id) if row.finding_id else None,
            "owner_user_id": str(row.owner_user_id) if row.owner_user_id else None,
            "source": row.source.value,
            "source_id": str(row.source_id) if row.source_id else None,
            "explanation": row.explanation_json,
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _services(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(Service)
            .join(Asset, Asset.id == Service.asset_id)
            .where(Asset.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(s.id),
            "asset_id": str(s.asset_id),
            "transport": s.transport.value,
            "port": s.port,
            "state": s.state.value,
        }
        for s in rows
    ]


async def _software_inventory(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(SoftwareInventoryItem).where(SoftwareInventoryItem.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "asset_id": str(row.asset_id),
            "source": row.source.value,
            "name": row.name,
            "package_key": row.package_key,
            "version": row.version,
            "architecture": row.architecture,
            "publisher": row.publisher,
            "product_key": row.product_key,
            "install_date": row.install_date.isoformat() if row.install_date else None,
            "first_seen_at": _iso(row.first_seen_at),
            "last_seen_at": _iso(row.last_seen_at),
            "removed_at": _iso(row.removed_at),
            "metadata": row.metadata_json,
        }
        for row in rows
    ]


async def _software_history(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(SoftwareInventoryHistory).where(
                SoftwareInventoryHistory.organization_id == org_id
            )
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "asset_id": str(row.asset_id),
            "software_item_id": str(row.software_item_id),
            "scan_job_id": str(row.scan_job_id) if row.scan_job_id else None,
            "change_type": row.change_type.value,
            "previous_version": row.previous_version,
            "observed_version": row.observed_version,
            "observation": row.observation_json,
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _eol_overrides(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(EolOverride).where(EolOverride.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(row.id),
            "software_item_id": str(row.software_item_id),
            "status": row.status.value,
            "eol_date": row.eol_date.isoformat() if row.eol_date else None,
            "reason": row.reason,
            "expires_at": _iso(row.expires_at),
            "active": row.active,
            "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at),
        }
        for row in rows
    ]


async def _findings(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(Finding).where(Finding.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(f.id),
            "site_id": str(f.site_id),
            "asset_id": str(f.asset_id) if f.asset_id else None,
            "scanner_name": f.scanner_name,
            "canonical_finding_key": f.canonical_finding_key,
            "finding_type": f.finding_type.value,
            "title": f.title,
            "severity": f.severity.value,
            "status": f.status.value,
            "cve_ids": f.cve_ids_json,
            "known_exploited": f.known_exploited,
            "risk_score": f.risk_score,
            "risk_profile_version": f.risk_profile_version,
            "current_score_snapshot_id": (
                str(f.current_score_snapshot_id) if f.current_score_snapshot_id else None
            ),
            "due_at": _iso(f.due_at),
            "current_sla_calculation_id": (
                str(f.current_sla_calculation_id) if f.current_sla_calculation_id else None
            ),
            "sla_started_at": _iso(f.sla_started_at),
            "sla_paused_at": _iso(f.sla_paused_at),
            "sla_completed_at": _iso(f.sla_completed_at),
        }
        for f in rows
    ]


async def _sla_policies(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(SlaPolicy).where(SlaPolicy.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(row.id),
            "name": row.name,
            "description": row.description,
            "priority": row.priority,
            "enabled": row.enabled,
            "match": row.match_json,
            "due_days": row.due_days_json,
            "pause_on_risk_acceptance": row.pause_on_risk_acceptance,
        }
        for row in rows
    ]


async def _finding_sla_calculations(
    session: AsyncSession, org_id: uuid.UUID
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(FindingSlaCalculation).where(
                FindingSlaCalculation.organization_id == org_id
            )
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "finding_id": str(row.finding_id),
            "policy_id": str(row.policy_id) if row.policy_id else None,
            "previous_calculation_id": (
                str(row.previous_calculation_id) if row.previous_calculation_id else None
            ),
            "source": row.source.value,
            "started_at": _iso(row.started_at),
            "due_at": _iso(row.due_at),
            "calculation": row.calculation_json,
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _sla_exceptions(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(SlaException).where(SlaException.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "finding_id": str(row.finding_id),
            "requested_due_at": _iso(row.requested_due_at),
            "reason": row.reason,
            "status": row.status.value,
            "review_notes": row.review_notes,
            "resulting_calculation_id": (
                str(row.resulting_calculation_id) if row.resulting_calculation_id else None
            ),
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _sla_history(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(SlaHistory).where(SlaHistory.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "finding_id": str(row.finding_id),
            "event": row.event.value,
            "metadata": row.metadata_json,
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _remediation_guidance(
    session: AsyncSession, org_id: uuid.UUID
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(RemediationGuidance).where(RemediationGuidance.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "finding_id": str(row.finding_id),
            "classification": row.classification.value,
            "summary": row.summary,
            "steps": row.steps_json,
            "validation_steps": row.validation_steps_json,
            "references": row.references_json,
            "source": row.source,
        }
        for row in rows
    ]


async def _ticket_connectors(
    session: AsyncSession, org_id: uuid.UUID
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(TicketConnector).where(TicketConnector.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "name": row.name,
            "connector_type": row.connector_type.value,
            "base_url": row.base_url,
            "project_key": row.project_key,
            "config": row.config_json,
            "has_secret": bool(row.encrypted_secret),
            "enabled": row.enabled,
            "close_after_verification": row.close_after_verification,
            "successful_test_at": _iso(row.successful_test_at),
        }
        for row in rows
    ]


async def _ticket_syncs(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(TicketSync).where(TicketSync.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "connector_id": str(row.connector_id),
            "finding_id": str(row.finding_id),
            "status": row.status.value,
            "last_action": row.last_action.value,
            "external_ticket_id": row.external_ticket_id,
            "external_ticket_url": row.external_ticket_url,
            "last_payload_hash": row.last_payload_hash,
            "last_synced_at": _iso(row.last_synced_at),
        }
        for row in rows
    ]


async def _ticket_sync_events(
    session: AsyncSession, org_id: uuid.UUID
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(TicketSyncEvent).where(TicketSyncEvent.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "sync_id": str(row.sync_id),
            "action": row.action.value,
            "status": row.status.value,
            "payload_hash": row.payload_hash,
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _risk_profiles(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(select(RiskProfile).where(RiskProfile.organization_id == org_id))
    ).scalars()
    return [
        {
            "id": str(row.id),
            "name": row.name,
            "version": row.version,
            "description": row.description,
            "weights": row.weights_json,
            "is_default": row.is_default,
            "created_by_user_id": (str(row.created_by_user_id) if row.created_by_user_id else None),
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _finding_score_snapshots(
    session: AsyncSession, org_id: uuid.UUID
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(FindingScoreSnapshot).where(FindingScoreSnapshot.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "finding_id": str(row.finding_id),
            "risk_profile_id": str(row.risk_profile_id),
            "profile_version": row.profile_version,
            "score": row.score,
            "weighted_sum": row.weighted_sum,
            "positive_maximum": row.positive_maximum,
            "source_values": row.source_values_json,
            "factors": row.factors_json,
            "input_hash": row.input_hash,
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _remediation_units(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(RemediationUnit).where(RemediationUnit.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "key_type": row.key_type.value,
            "exact_key": row.exact_key,
            "title": row.title,
            "description": row.description,
            "status": row.status.value,
            "owner_user_id": str(row.owner_user_id) if row.owner_user_id else None,
            "automatically_created": row.automatically_created,
        }
        for row in rows
    ]


async def _remediation_unit_findings(
    session: AsyncSession, org_id: uuid.UUID
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(RemediationUnitFinding).where(RemediationUnitFinding.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "remediation_unit_id": str(row.remediation_unit_id),
            "finding_id": str(row.finding_id),
            "match_basis": row.match_basis_json,
            "added_by_user_id": str(row.added_by_user_id) if row.added_by_user_id else None,
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _remediation_suggestions(
    session: AsyncSession, org_id: uuid.UUID
) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(RemediationSuggestion).where(RemediationSuggestion.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "remediation_unit_id": str(row.remediation_unit_id),
            "finding_id": str(row.finding_id),
            "similarity": row.similarity,
            "explanation": row.explanation_json,
            "status": row.status.value,
            "reviewed_by_user_id": (
                str(row.reviewed_by_user_id) if row.reviewed_by_user_id else None
            ),
            "reviewed_at": _iso(row.reviewed_at),
        }
        for row in rows
    ]


async def _finding_decisions(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(FindingDecision).where(FindingDecision.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(row.id),
            "site_id": str(row.site_id),
            "finding_id": str(row.finding_id),
            "decision_type": row.decision_type.value,
            "status": row.status.value,
            "reason": row.reason,
            "evidence": row.evidence_json,
            "expires_at": _iso(row.expires_at),
            "duplicate_of_finding_id": (
                str(row.duplicate_of_finding_id) if row.duplicate_of_finding_id else None
            ),
            "previous_status": row.previous_status.value,
            "created_by_user_id": (str(row.created_by_user_id) if row.created_by_user_id else None),
            "revoked_by_user_id": (str(row.revoked_by_user_id) if row.revoked_by_user_id else None),
            "revoked_at": _iso(row.revoked_at),
            "created_at": _iso(row.created_at),
        }
        for row in rows
    ]


async def _reports(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    # Report metadata + integrity hash only — never the report file bytes.
    rows = (await session.execute(select(Report).where(Report.organization_id == org_id))).scalars()
    return [
        {
            "id": str(r.id),
            "report_type": r.report_type.value,
            "format": r.format.value,
            "status": r.status.value,
            "sha256": r.sha256,
            "size_bytes": r.size_bytes,
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
            "id": str(x.id),
            "finding_id": str(x.finding_id),
            "reason": x.reason,
            "status": x.status.value,
            "expires_at": _iso(x.expires_at),
        }
        for x in rows
    ]


async def _finding_notes(session: AsyncSession, org_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = (
        await session.execute(
            select(FindingNote)
            .join(Finding, Finding.id == FindingNote.finding_id)
            .where(Finding.organization_id == org_id)
        )
    ).scalars()
    return [
        {
            "id": str(n.id),
            "finding_id": str(n.finding_id),
            "body": n.body,
            "created_at": _iso(n.created_at),
        }
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
    if version not in SUPPORTED_IMPORT_SCHEMA_VERSIONS:
        errors.append(
            f"Unsupported schema_version '{version}'; this build reads "
            f"{sorted(SUPPORTED_IMPORT_SCHEMA_VERSIONS)}."
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
    asset_ids = {asset.get("id") for asset in payload.get("assets", [])}
    asset_tag_ids = {tag.get("id") for tag in payload.get("asset_tags", [])}
    asset_group_ids = {group.get("id") for group in payload.get("asset_groups", [])}
    for assignment in payload.get("asset_tag_assignments", []):
        if assignment.get("asset_id") not in asset_ids:
            warnings.append("An asset-tag assignment references an unknown asset.")
        if assignment.get("tag_id") not in asset_tag_ids:
            warnings.append("An asset-tag assignment references an unknown tag.")
    for membership in payload.get("asset_group_memberships", []):
        if membership.get("asset_id") not in asset_ids:
            warnings.append("An asset-group membership references an unknown asset.")
        if membership.get("group_id") not in asset_group_ids:
            warnings.append("An asset-group membership references an unknown group.")

    finding_ids = {finding.get("id") for finding in payload.get("findings", [])}
    risk_profile_ids = {profile.get("id") for profile in payload.get("risk_profiles", [])}
    remediation_unit_ids = {unit.get("id") for unit in payload.get("remediation_units", [])}
    for snapshot in payload.get("finding_score_snapshots", []):
        if snapshot.get("finding_id") not in finding_ids:
            warnings.append("A finding-score snapshot references an unknown finding.")
        if snapshot.get("risk_profile_id") not in risk_profile_ids:
            warnings.append("A finding-score snapshot references an unknown risk profile.")
    for unit in payload.get("remediation_units", []):
        if unit.get("site_id") not in site_ids:
            warnings.append("A remediation unit references an unknown site.")
    for membership in payload.get("remediation_unit_findings", []):
        if membership.get("remediation_unit_id") not in remediation_unit_ids:
            warnings.append("A remediation membership references an unknown unit.")
        if membership.get("finding_id") not in finding_ids:
            warnings.append("A remediation membership references an unknown finding.")
    for suggestion in payload.get("remediation_suggestions", []):
        if suggestion.get("remediation_unit_id") not in remediation_unit_ids:
            warnings.append("A remediation suggestion references an unknown unit.")
        if suggestion.get("finding_id") not in finding_ids:
            warnings.append("A remediation suggestion references an unknown finding.")
    for decision in payload.get("finding_decisions", []):
        if decision.get("finding_id") not in finding_ids:
            warnings.append("A finding decision references an unknown finding.")
        duplicate_of = decision.get("duplicate_of_finding_id")
        if duplicate_of is not None and duplicate_of not in finding_ids:
            warnings.append("A duplicate decision references an unknown canonical finding.")

    user_ids = {u.get("id") for u in payload.get("users", [])}
    for assignment in payload.get("user_site_assignments", []):
        if assignment.get("user_id") not in user_ids:
            warnings.append("A user-site assignment references an unknown user.")
        if assignment.get("site_id") not in site_ids:
            warnings.append("A user-site assignment references an unknown site.")

    group_ids = {group.get("id") for group in payload.get("scim_groups", [])}
    for group in payload.get("scim_groups", []):
        for asset_group_id in group.get("asset_group_ids", []):
            if asset_group_id not in asset_group_ids:
                warnings.append("A SCIM mapping references an unknown asset group.")
    for membership in payload.get("scim_group_members", []):
        if membership.get("group_id") not in group_ids:
            warnings.append("A SCIM membership references an unknown group.")
        if membership.get("user_id") not in user_ids:
            warnings.append("A SCIM membership references an unknown user.")
    for mapping in payload.get("scim_group_site_mappings", []):
        if mapping.get("group_id") not in group_ids:
            warnings.append("A SCIM site mapping references an unknown group.")
        if mapping.get("site_id") not in site_ids:
            warnings.append("A SCIM site mapping references an unknown site.")

    role_ids = {role.get("id") for role in payload.get("authorization_roles", [])}
    service_ids = {service.get("id") for service in payload.get("service_accounts", [])}
    for grant in payload.get("scoped_grants", []):
        if grant.get("role_id") not in role_ids:
            warnings.append("An authorization grant references an unknown role.")
        if grant.get("principal_type") == "user" and grant.get("principal_id") not in user_ids:
            warnings.append("An authorization grant references an unknown user.")
        if (
            grant.get("principal_type") == "service_account"
            and grant.get("principal_id") not in service_ids
        ):
            warnings.append("An authorization grant references an unknown service account.")
        if grant.get("scope_type") == "site" and grant.get("scope_id") not in site_ids:
            warnings.append("An authorization grant references an unknown site.")

    principal_ids = user_ids | service_ids
    for token in payload.get("api_tokens", []):
        if token.get("principal_id") not in principal_ids:
            warnings.append("An API token record references an unknown principal.")

    counts = {
        key: len(payload.get(key, []))
        for key in (
            "users",
            "service_accounts",
            "sites",
            "assets",
            "services",
            "findings",
            "remediation_units",
            "reports",
        )
    }
    return {
        "valid": not errors,
        "schema_version": version,
        "checksum_ok": checksum_ok,
        "errors": errors,
        "warnings": warnings,
        "counts": counts,
    }
