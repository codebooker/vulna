"""Scan-job creation: target validation, envelope building, and signing.

The orchestrator validates targets against the probe's approved scopes as
defense in depth (the probe independently enforces its signed local policy too),
builds the job envelope (build plan Section 11.3), and signs it with Ed25519.
The exact signed envelope is stored verbatim so delivery is byte-identical to
what was signed.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.asset import Asset, AssetIdentifier
from app.models.credential import CredentialUsageAudit
from app.models.enums import (
    CredentialProtocol,
    CredentialUsageStatus,
    IdentifierType,
    JobMode,
    JobStatus,
    WebScanProfile,
)
from app.models.network import Network, NetworkScout
from app.models.network_scope import NetworkScope
from app.models.probe import Probe
from app.models.scan_job import ScanJob
from app.services import credentials as credential_service
from app.services.policy import build_policy_document
from app.services.scopes import ScopeValidationError, normalize_cidr
from app.services.signing import get_signer


async def _job_site_id(
    session: AsyncSession, probe: Probe, network_id: uuid.UUID | None
) -> uuid.UUID:
    """The site a job's discovered assets belong to. For a network-targeted job
    that is the network's site (which may differ from the scout's own site when a
    scout scans another site's network across an SD-WAN), else the scout's site."""
    if network_id is not None:
        net = await session.get(Network, network_id)
        if net is not None:
            return net.site_id
    return probe.site_id


# The non-intrusive assessment workflow: discovery, then vulnerability and TLS
# stages. A probe skips any stage whose scanner it does not have installed.
_SUPPORTED_MODES = {JobMode.VULNERABILITY_ASSESSMENT}
_DEFAULT_WORKFLOW: list[dict[str, Any]] = [
    {"stage": "discovery", "plugin": "nmap", "config": {}},
    {"stage": "vulnerability", "plugin": "nuclei", "config": {}},
    {"stage": "tls", "plugin": "testssl", "config": {}},
]


def _validate_web_start_urls(start_urls: list[str], approved: list[str]) -> list[str]:
    """Validate ZAP start URLs. Each must be an http(s) URL; an IP-literal host
    must fall within an approved scope (defense in depth — the probe enforces
    scope too)."""
    validated: list[str] = []
    for raw in start_urls:
        parts = urlsplit(raw)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise JobValidationError(f"Invalid web start URL '{raw}'")
        host = parts.hostname
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise JobValidationError(
                "Web start URLs must use an IP-literal host; DNS names are disabled"
            ) from exc
        if not _target_within_approved(host, approved):
            raise JobValidationError(
                f"Web start URL host '{host}' is outside the approved scope"
            )
        validated.append(raw)
    return validated


def _build_web_stage(
    profile: WebScanProfile, start_urls: list[str], limits: dict[str, Any]
) -> dict[str, Any]:
    duration_s = int(limits.get("max_duration_seconds", 600) or 600)
    rps = int(limits.get("max_packets_per_second", 10) or 10)
    return {
        "stage": "web",
        "plugin": "zap",
        "config": {
            "profile": profile.value,
            "start_urls": start_urls,
            "max_duration_minutes": max(1, duration_s // 60),
            "requests_per_second": min(max(1, rps), 20),
        },
    }


class JobValidationError(ValueError):
    """Raised when a job request is invalid or out of scope."""


async def _validate_network_job(
    session: AsyncSession, probe: Probe, network_id: uuid.UUID
) -> list[str]:
    """Validate a network-targeted job and return that network's enabled ranges.

    This check belongs in the job service so API, scheduler, and workflow callers
    cannot accidentally create a site-wide job while claiming network semantics.
    """
    network = await session.get(Network, network_id)
    if network is None or network.organization_id != probe.organization_id:
        raise JobValidationError("Network not found")
    if not network.enabled:
        raise JobValidationError("The network is disabled")

    binding = (
        await session.execute(
            select(NetworkScout.id).where(
                NetworkScout.network_id == network_id,
                NetworkScout.probe_id == probe.id,
            )
        )
    ).scalar_one_or_none()
    if binding is None:
        raise JobValidationError("The probe is not bound to this network")

    active = (
        await session.execute(
            select(ScanJob.id)
            .where(
                ScanJob.network_id == network_id,
                ScanJob.status.in_(
                    (JobStatus.QUEUED, JobStatus.OFFERED, JobStatus.ACCEPTED, JobStatus.RUNNING)
                ),
            )
            .limit(1)
        )
    ).first()
    if active is not None:
        raise JobValidationError("the network is already under test")

    ranges = list(
        (
            await session.execute(
                select(NetworkScope.cidr).where(
                    NetworkScope.network_id == network_id,
                    NetworkScope.enabled.is_(True),
                )
            )
        ).scalars()
    )
    if not ranges:
        raise JobValidationError("The network has no enabled ranges")
    return ranges


async def _persist_job(session: AsyncSession, job: ScanJob) -> ScanJob:
    """Insert a job inside a SAVEPOINT so the partial-unique "one active job per
    network" index turns a lost race into a clean ``JobValidationError`` instead of
    an IntegrityError that poisons the surrounding transaction. The app-level check
    (``network_has_active_job``) handles the common case; this closes the race
    window between that check and the insert without rolling back the caller's other
    work (e.g. a scheduler sweep processing many schedules in one transaction)."""
    try:
        async with session.begin_nested():
            session.add(job)
            await session.flush()
    except IntegrityError as exc:
        if job.network_id is not None:
            raise JobValidationError("the network is already under test") from exc
        raise
    return job


def _target_within_approved(target: str, approved: list[str]) -> bool:
    """Return whether a target (IP or CIDR) is fully contained in an approved CIDR."""
    try:
        net = normalize_cidr(target)
    except ScopeValidationError:
        return False
    for cidr in approved:
        try:
            approved_net = normalize_cidr(cidr)
        except ScopeValidationError:
            continue
        if net.version != approved_net.version:
            continue
        if net.subnet_of(approved_net):  # type: ignore[arg-type]
            return True
    return False


def _validate_targets(targets: list[str], approved: list[str], *, allow_public: bool) -> list[str]:
    if not targets:
        raise JobValidationError("At least one target is required")
    normalized: list[str] = []
    for target in targets:
        try:
            net = normalize_cidr(target)
        except ScopeValidationError as exc:
            raise JobValidationError(str(exc)) from exc
        if not allow_public and not net.is_private:
            raise JobValidationError(f"Target {target} is a public address")
        if not _target_within_approved(target, approved):
            raise JobValidationError(f"Target {target} is outside the approved scope")
        normalized.append(str(net))
    return normalized


def _count_hosts(targets: list[str]) -> int:
    """Total addresses spanned by the targets (a bare IP counts as one host)."""
    total = 0
    for target in targets:
        try:
            total += normalize_cidr(target).num_addresses
        except ScopeValidationError:
            continue
    return total


def _enforce_host_limit(targets: list[str], limits: dict[str, Any]) -> None:
    """Reject a job whose targets span more hosts than the policy permits.

    The limit is carried in the signed policy and independently re-checked by the
    probe; enforcing it here stops an oversized job from being created and signed
    in the first place.
    """
    max_hosts = int(limits.get("max_hosts", 0) or 0)
    if max_hosts <= 0:
        return
    requested = _count_hosts(targets)
    if requested > max_hosts:
        raise JobValidationError(
            f"Job spans {requested} hosts, exceeding the scope limit of {max_hosts}"
        )


def build_job_envelope(
    *,
    job_id: uuid.UUID,
    probe: Probe,
    mode: JobMode,
    targets: list[str],
    workflow: list[dict[str, Any]],
    limits: dict[str, Any],
    policy_version: int,
    not_before: datetime,
    expires_at: datetime,
    credential_envelope: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build the unsigned job envelope payload (build plan Section 11.3)."""
    envelope: dict[str, Any] = {
        "job_id": str(job_id),
        "probe_id": str(probe.id),
        "site_id": str(probe.site_id),
        "mode": mode.value,
        "policy_version": policy_version,
        "not_before": not_before.isoformat(),
        "expires_at": expires_at.isoformat(),
        "targets": targets,
        "workflow": workflow,
        "limits": limits,
    }
    if credential_envelope is not None:
        envelope["credential_envelope"] = credential_envelope
    return envelope


async def create_scan_job(
    session: AsyncSession,
    probe: Probe,
    settings: Settings,
    *,
    targets: list[str],
    mode: JobMode,
    created_by: uuid.UUID | None,
    not_before: datetime | None = None,
    expires_at: datetime | None = None,
    web_profile: WebScanProfile | None = None,
    web_start_urls: list[str] | None = None,
    verifies_finding_ids: list[str] | None = None,
    stages: list[str] | None = None,
    network_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    authenticated_protocols: list[CredentialProtocol] | None = None,
    preset_key: str | None = None,
    include_default_workflow: bool = True,
) -> ScanJob:
    """Validate, build, sign, and persist a scan job for a probe (status queued).

    ``stages`` restricts the job to a subset of the default workflow stages (by
    stage name, e.g. ``["discovery"]``) so a caller — the full-spectrum workflow —
    can dispatch one scanner at a time; ``None`` includes them all.
    """
    if mode not in _SUPPORTED_MODES:
        raise JobValidationError(f"Mode '{mode.value}' is not supported yet")

    policy = await build_policy_document(session, probe, settings)
    approved = list(policy["approved_cidrs"])
    if not approved:
        raise JobValidationError("The probe has no approved scopes; approve a scope first")

    if network_id is not None:
        approved = await _validate_network_job(session, probe, network_id)

    normalized_targets = _validate_targets(
        targets, approved, allow_public=bool(policy["allow_public_addresses"])
    )
    _enforce_host_limit(normalized_targets, policy["limits"])

    protocols = list(dict.fromkeys(authenticated_protocols or []))
    asset: Asset | None = None
    resolved_credentials: list[credential_service.ResolvedCredential] = []
    if protocols:
        if not probe.credentialed_scans_enabled:
            raise JobValidationError(
                "Credentialed scans are not enabled on this Scout; an administrator must opt it in"
            )
        if not probe.encryption_public_key_b64:
            raise JobValidationError(
                "Scout has no credential-encryption key; re-enroll it before credentialed scans"
            )
        if asset_id is None:
            raise JobValidationError("asset_id is required for authenticated inventory")
        asset = await session.scalar(
            select(Asset).where(
                Asset.id == asset_id,
                Asset.organization_id == probe.organization_id,
            )
        )
        if asset is None:
            raise JobValidationError("Authenticated inventory asset was not found")
        job_site_id = await _job_site_id(session, probe, network_id)
        if asset.site_id != job_site_id:
            raise JobValidationError("Authenticated inventory asset is outside the job site")
        if len(normalized_targets) != 1 or normalize_cidr(normalized_targets[0]).num_addresses != 1:
            raise JobValidationError("Authenticated inventory requires exactly one host target")
        target_ip = str(normalize_cidr(normalized_targets[0]).network_address)
        owns_ip = await session.scalar(
            select(AssetIdentifier.id).where(
                AssetIdentifier.asset_id == asset.id,
                AssetIdentifier.identifier_type == IdentifierType.IP_ADDRESS,
                AssetIdentifier.identifier_value == target_ip,
            )
        )
        if owns_ip is None:
            raise JobValidationError("Authenticated inventory target is not an IP of the asset")
        try:
            resolved_credentials = await credential_service.resolve_required_credentials(
                session,
                asset,
                protocols,
                network_id=network_id,
                preset_key=preset_key,
            )
        except credential_service.CredentialResolutionError as exc:
            raise JobValidationError(str(exc)) from exc

    workflow = list(_DEFAULT_WORKFLOW) if include_default_workflow else []
    if stages is not None:
        wanted = set(stages)
        workflow = [s for s in workflow if s["stage"] in wanted]
        if not workflow:
            raise JobValidationError(f"No known scanner stages in {stages}")
    if web_profile is not None and web_start_urls:
        validated_urls = _validate_web_start_urls(web_start_urls, approved)
        workflow.append(_build_web_stage(web_profile, validated_urls, policy["limits"]))
    for protocol in protocols:
        workflow.append(
            {
                "stage": "inventory",
                "plugin": f"{protocol.value}_inventory",
                "config": {
                    "asset_id": str(asset_id),
                    "protocol": protocol.value,
                    "read_only": True,
                },
            }
        )

    now = datetime.now(UTC)
    start = not_before or now
    end = expires_at or (now + timedelta(minutes=settings.job_default_ttl_minutes))
    if end <= start:
        raise JobValidationError("expires_at must be after not_before")

    job_id = uuid.uuid4()
    credential_envelope: dict[str, str] | None = None
    if resolved_credentials:
        master_secret = settings.require_secret_key()
        plaintext = [
            (
                item,
                credential_service.decrypt_resolved_secret(item, master_secret=master_secret),
            )
            for item in resolved_credentials
        ]
        credential_envelope = credential_service.build_scout_credential_envelope(
            job_id=job_id,
            probe_id=probe.id,
            probe_public_key_b64=probe.encryption_public_key_b64 or "",
            expires_at=end.isoformat(),
            credentials=plaintext,
        )
    envelope = build_job_envelope(
        job_id=job_id,
        probe=probe,
        mode=mode,
        targets=normalized_targets,
        workflow=workflow,
        limits=policy["limits"],
        policy_version=int(policy["policy_version"]),
        not_before=start,
        expires_at=end,
        credential_envelope=credential_envelope,
    )
    signed = get_signer().sign_document(envelope)

    job = ScanJob(
        id=job_id,
        organization_id=probe.organization_id,
        site_id=await _job_site_id(session, probe, network_id),
        probe_id=probe.id,
        network_id=network_id,
        asset_id=asset_id,
        mode=mode,
        status=JobStatus.QUEUED,
        requested_targets_json=normalized_targets,
        workflow_json=workflow,
        limits_json=policy["limits"],
        policy_version=int(policy["policy_version"]),
        envelope_json=signed,
        job_signature=signed["signature"],
        not_before=start,
        expires_at=end,
        created_by=created_by,
        verifies_finding_ids_json=list(verifies_finding_ids or []),
        credential_protocols_json=[protocol.value for protocol in protocols],
    )
    await _persist_job(session, job)
    if asset is not None:
        for item in resolved_credentials:
            if item.record is None or item.version is None:
                raise JobValidationError("credential resolution changed while creating the job")
            session.add(
                CredentialUsageAudit(
                    organization_id=job.organization_id,
                    credential_id=item.record.id,
                    secret_version_id=item.version.id,
                    asset_id=asset.id,
                    probe_id=probe.id,
                    scan_job_id=job.id,
                    protocol=item.protocol,
                    status=CredentialUsageStatus.ENCRYPTED_FOR_JOB,
                )
            )
    return job


async def create_pentest_job(
    session: AsyncSession,
    probe: Probe,
    settings: Settings,
    *,
    target: str,
    module: str,
    payload: str | None,
    options: dict[str, Any],
    max_session_seconds: int,
    expires_at: datetime,
    created_by: uuid.UUID | None,
    network_id: uuid.UUID | None = None,
) -> ScanJob:
    """Build, sign, and persist a controlled-pentest job: one authorized module
    against one in-scope target, time-boxed. The scout re-verifies the module and
    scope locally before running (fail-closed)."""
    policy = await build_policy_document(session, probe, settings)
    approved = list(policy["approved_cidrs"])
    try:
        normalized = str(normalize_cidr(target))
    except ScopeValidationError as exc:
        raise JobValidationError(str(exc)) from exc
    if not _target_within_approved(normalized, approved):
        raise JobValidationError(f"Target {target} is outside the scout's approved scope")

    now = datetime.now(UTC)
    job_id = uuid.uuid4()
    workflow = [
        {
            "stage": "exploit",
            "plugin": "metasploit",
            "config": {
                "module": module,
                "payload": payload,
                "options": dict(options or {}),
                "max_session_seconds": max_session_seconds,
            },
        }
    ]
    limits = {"max_session_seconds": max_session_seconds}
    envelope = build_job_envelope(
        job_id=job_id,
        probe=probe,
        mode=JobMode.CONTROLLED_PENTEST,
        targets=[normalized],
        workflow=workflow,
        limits=limits,
        policy_version=int(policy["policy_version"]),
        not_before=now,
        expires_at=expires_at,
    )
    signed = get_signer().sign_document(envelope)
    job = ScanJob(
        id=job_id,
        organization_id=probe.organization_id,
        site_id=await _job_site_id(session, probe, network_id),
        probe_id=probe.id,
        network_id=network_id,
        mode=JobMode.CONTROLLED_PENTEST,
        status=JobStatus.QUEUED,
        requested_targets_json=[normalized],
        workflow_json=workflow,
        limits_json=limits,
        policy_version=int(policy["policy_version"]),
        envelope_json=signed,
        job_signature=signed["signature"],
        not_before=now,
        expires_at=expires_at,
        created_by=created_by,
    )
    return await _persist_job(session, job)
