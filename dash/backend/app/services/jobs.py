"""Scan-job creation: target validation, envelope building, and signing.

The orchestrator validates targets against the probe's approved scopes as
defense in depth (the probe independently enforces its signed local policy too),
builds the job envelope (build plan Section 11.3), and signs it with Ed25519.
The exact signed envelope is stored verbatim so delivery is byte-identical to
what was signed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models.enums import JobMode, JobStatus
from app.models.probe import Probe
from app.models.scan_job import ScanJob
from app.services.policy import build_policy_document
from app.services.scopes import ScopeValidationError, normalize_cidr
from app.services.signing import get_signer

# The non-intrusive assessment workflow: discovery, then vulnerability and TLS
# stages. A probe skips any stage whose scanner it does not have installed.
_SUPPORTED_MODES = {JobMode.VULNERABILITY_ASSESSMENT}
_DEFAULT_WORKFLOW: list[dict[str, Any]] = [
    {"stage": "discovery", "plugin": "nmap", "config": {}},
    {"stage": "vulnerability", "plugin": "nuclei", "config": {}},
    {"stage": "tls", "plugin": "testssl", "config": {}},
]


class JobValidationError(ValueError):
    """Raised when a job request is invalid or out of scope."""


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
) -> dict[str, Any]:
    """Build the unsigned job envelope payload (build plan Section 11.3)."""
    return {
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
) -> ScanJob:
    """Validate, build, sign, and persist a scan job for a probe (status queued)."""
    if mode not in _SUPPORTED_MODES:
        raise JobValidationError(f"Mode '{mode.value}' is not supported yet")

    policy = await build_policy_document(session, probe, settings)
    approved = list(policy["approved_cidrs"])
    if not approved:
        raise JobValidationError("The probe has no approved scopes; approve a scope first")

    normalized_targets = _validate_targets(
        targets, approved, allow_public=bool(policy["allow_public_addresses"])
    )

    now = datetime.now(UTC)
    start = not_before or now
    end = expires_at or (now + timedelta(minutes=settings.job_default_ttl_minutes))
    if end <= start:
        raise JobValidationError("expires_at must be after not_before")

    job_id = uuid.uuid4()
    envelope = build_job_envelope(
        job_id=job_id,
        probe=probe,
        mode=mode,
        targets=normalized_targets,
        workflow=_DEFAULT_WORKFLOW,
        limits=policy["limits"],
        policy_version=int(policy["policy_version"]),
        not_before=start,
        expires_at=end,
    )
    signed = get_signer().sign_document(envelope)

    job = ScanJob(
        id=job_id,
        organization_id=probe.organization_id,
        site_id=probe.site_id,
        probe_id=probe.id,
        mode=mode,
        status=JobStatus.QUEUED,
        requested_targets_json=normalized_targets,
        workflow_json=_DEFAULT_WORKFLOW,
        limits_json=policy["limits"],
        policy_version=int(policy["policy_version"]),
        envelope_json=signed,
        job_signature=signed["signature"],
        not_before=start,
        expires_at=end,
        created_by=created_by,
    )
    session.add(job)
    await session.flush()
    return job
