"""VulnaScout probe endpoints.

Two audiences share the ``/probes`` prefix:

* **Administrators** mint enrollment tokens and manage probe lifecycle
  (list, get, approve, revoke, disable), authenticated as users.
* **Probes** enroll (token-gated), heartbeat, and poll for jobs, authenticated
  by their mutual-TLS client certificate (see ``app.api.probe_auth``).

Static probe-facing routes (``/enroll``, ``/enrollment-tokens``) are declared
before the ``/{probe_id}`` routes so they are matched correctly.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.api.probe_auth import CurrentProbe
from app.auth.dependencies import StepUpIdentity, require_permission
from app.auth.site_scope import get_accessible_site, site_scope_clause
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.credential import CredentialTest, CredentialUsageAudit
from app.models.enrollment_token import EnrollmentToken
from app.models.enums import (
    ActorType,
    CredentialTestStatus,
    CredentialUsageStatus,
    JobMode,
    JobStatus,
    ProbeStatus,
    SoftwareInventorySource,
)
from app.models.probe import Probe
from app.models.probe_result_upload import ProbeResultUpload
from app.models.scan_job import ScanJob
from app.models.scan_job_attempt import ScanJobAttempt
from app.models.user import User
from app.schemas.common import Page
from app.schemas.enrollment import (
    EnrollmentCommandRequest,
    EnrollmentCommandResponse,
    EnrollmentTokenCreate,
    EnrollmentTokenCreated,
    EnrollRequest,
    EnrollResponse,
)
from app.schemas.job import JobStatusUpdate, ResultIngestSummary, ResultUploadEnvelope
from app.schemas.probe import (
    CertificateStatus,
    CredentialedScanToggle,
    HeartbeatRequest,
    HeartbeatResponse,
    PentestToggle,
    PolicyStatus,
    ProbeRead,
    ProbeUpdate,
    serialize_probe,
)
from app.services import networks as networks_service
from app.services import pentest as pentest_service
from app.services import reaper, workflow_dispatch
from app.services.audit import record_audit
from app.services.ca import CertificateAuthorityError, certificate_fingerprint, get_ca
from app.services.enrollment import generate_token, hash_token
from app.services.findings import ingest_findings
from app.services.ingest import ingest_nmap_result, store_scan_artifact
from app.services.nmap_parser import NmapParseError
from app.services.notifications import EventType, NotificationEvent
from app.services.notify import emit_event
from app.services.nuclei_parser import parse_nuclei_jsonl
from app.services.policy import build_policy_document
from app.services.remediation import finalize_scanner_verification
from app.services.remote_scout import build_install_commands
from app.services.scan_observability import (
    apply_progress,
    build_failure_log,
    sanitize_failure_message,
    sanitize_label,
)
from app.services.signing import document_hash, get_signer
from app.services.software_inventory import SoftwareInventoryError, ingest_inventory
from app.services.testssl_parser import TestsslParseError, parse_testssl_json
from app.services.zap_parser import ZapParseError, parse_zap_json

# Upper bound on a single result upload (defense against oversized payloads).
_MAX_RESULT_BYTES = 25 * 1024 * 1024
_MAX_RESULT_ENVELOPE_BYTES = (_MAX_RESULT_BYTES * 4 // 3) + 16 * 1024
_RESULT_ENVELOPE_CONTENT_TYPE = "application/vnd.vulna.result+json"
_RESULT_FORMATS_BY_SCANNER = {
    "nmap": "nmap_xml",
    "nuclei": "nuclei_jsonl",
    "testssl": "testssl_json",
    "zap": "zap_json",
    "metasploit": "metasploit_json",
    "ssh_inventory": "software_inventory_json",
    "winrm_inventory": "software_inventory_json",
}

router = APIRouter(prefix="/probes", tags=["probes"])

# A suggested client heartbeat cadence; also used for the "expiring soon" window.
_HEARTBEAT_INTERVAL_SECONDS = 60
_CERT_EXPIRING_SOON = timedelta(days=14)
_JOB_LEASE_DURATION = timedelta(minutes=3)
_ACTIVE_ATTEMPT_STATUSES = {"offered", "accepted", "running"}
_TERMINAL_ATTEMPT_STATUSES = {
    "completed",
    "failed",
    "cancelled",
    "expired",
    "rejected_by_probe",
}


def _attempt_response_headers(attempt: ScanJobAttempt) -> dict[str, str]:
    return {
        "X-Vulna-Attempt-ID": str(attempt.id),
        "X-Vulna-Lease-ID": str(attempt.lease_id),
        "X-Vulna-Fencing-Token": str(attempt.fencing_token),
        "X-Vulna-Lease-Expires-At": attempt.lease_expires_at.isoformat(),
    }


def _result_idempotency_key(
    job_id: uuid.UUID, stage: str, scanner: str, raw: bytes, *, complete: bool
) -> str:
    digest = hashlib.sha256()
    digest.update(f"{job_id}\0{stage}\0{scanner}\0".encode())
    digest.update(b"1\0" if complete else b"0\0")
    digest.update(raw)
    return digest.hexdigest()


def _parse_attempt_headers(
    attempt_id: str | None, lease_id: str | None, fencing_token: str | None
) -> tuple[uuid.UUID, uuid.UUID, int]:
    if not attempt_id or not lease_id or not fencing_token:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Job attempt, lease, and fencing headers are required",
        )
    try:
        parsed_attempt = uuid.UUID(attempt_id)
        parsed_lease = uuid.UUID(lease_id)
        parsed_fence = int(fencing_token)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Job attempt headers are invalid",
        ) from exc
    if parsed_fence < 1:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Job fencing token is invalid",
        )
    return parsed_attempt, parsed_lease, parsed_fence


async def _require_current_attempt(
    session: AsyncSession,
    *,
    job: ScanJob,
    probe: Probe,
    attempt_id: str | None,
    lease_id: str | None,
    fencing_token: str | None,
    now: datetime,
    allow_terminal: bool = False,
) -> ScanJobAttempt:
    parsed_attempt, parsed_lease, parsed_fence = _parse_attempt_headers(
        attempt_id, lease_id, fencing_token
    )
    attempt = await session.scalar(
        select(ScanJobAttempt)
        .where(
            ScanJobAttempt.id == parsed_attempt,
            ScanJobAttempt.scan_job_id == job.id,
            ScanJobAttempt.probe_id == probe.id,
            ScanJobAttempt.lease_id == parsed_lease,
            ScanJobAttempt.fencing_token == parsed_fence,
        )
        .with_for_update()
    )
    latest_fence = await session.scalar(
        select(func.max(ScanJobAttempt.fencing_token)).where(ScanJobAttempt.scan_job_id == job.id)
    )
    if attempt is None or latest_fence != parsed_fence:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This job attempt has been fenced by a newer execution",
        )
    attempt_expiry = (
        attempt.lease_expires_at
        if attempt.lease_expires_at.tzinfo
        else attempt.lease_expires_at.replace(tzinfo=UTC)
    )
    if attempt.status in _ACTIVE_ATTEMPT_STATUSES and attempt_expiry <= now:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This job attempt lease has expired",
        )
    if attempt.status in _TERMINAL_ATTEMPT_STATUSES and not allow_terminal:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This job attempt is already terminal",
        )
    return attempt


async def _reclaim_expired_attempts(session: AsyncSession, probe: Probe, now: datetime) -> None:
    rows = (
        await session.execute(
            select(ScanJobAttempt, ScanJob)
            .join(ScanJob, ScanJob.id == ScanJobAttempt.scan_job_id)
            .where(
                ScanJobAttempt.probe_id == probe.id,
                ScanJobAttempt.status.in_(_ACTIVE_ATTEMPT_STATUSES),
                ScanJobAttempt.lease_expires_at <= now,
                ScanJob.status.in_([JobStatus.OFFERED, JobStatus.ACCEPTED, JobStatus.RUNNING]),
            )
            .with_for_update(skip_locked=True)
        )
    ).all()
    for attempt, job in rows:
        latest_fence = await session.scalar(
            select(func.max(ScanJobAttempt.fencing_token)).where(
                ScanJobAttempt.scan_job_id == job.id
            )
        )
        if latest_fence != attempt.fencing_token:
            continue
        attempt.status = "expired"
        attempt.finished_at = now
        expires = job.expires_at if job.expires_at.tzinfo else job.expires_at.replace(tzinfo=UTC)
        if expires <= now:
            job.status = JobStatus.EXPIRED
            job.finished_at = now
        elif job.cancel_requested_at is not None:
            job.status = JobStatus.CANCELLED
            job.finished_at = now
        else:
            job.status = JobStatus.QUEUED
            job.offered_at = None
            job.accepted_at = None
    # The API session intentionally disables autoflush. Make reclaimed jobs
    # visible to the immediately following queued-job selection in this poll.
    if rows:
        await session.flush()


# ---------------------------------------------------------------------------
# Admin: enrollment tokens
# ---------------------------------------------------------------------------


@router.post(
    "/enrollment-tokens",
    response_model=EnrollmentTokenCreated,
    status_code=status.HTTP_201_CREATED,
    summary="Create a one-time probe enrollment token",
)
async def create_enrollment_token(
    payload: EnrollmentTokenCreate,
    admin: Annotated[User, Depends(require_permission("scouts.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> EnrollmentTokenCreated:
    """Mint a single-use enrollment token for a site (Administrator only)."""
    await get_accessible_site(session, admin, payload.site_id, permission_key="scouts.manage")

    generated = generate_token()
    expires_at = datetime.now(UTC) + timedelta(minutes=settings.enrollment_token_ttl_minutes)
    token = EnrollmentToken(
        organization_id=admin.organization_id,
        site_id=payload.site_id,
        token_hash=generated.token_hash,
        short_code=generated.short_code,
        probe_name=payload.probe_name,
        description=payload.description,
        created_by=admin.id,
        expires_at=expires_at,
    )
    session.add(token)
    await session.flush()

    record_audit(
        session,
        action="probe.enrollment_token_created",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="enrollment_token",
        target_id=token.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"site_id": str(payload.site_id), "short_code": generated.short_code},
    )
    return EnrollmentTokenCreated(
        id=token.id,
        site_id=token.site_id,
        probe_name=token.probe_name,
        token=generated.secret,
        short_code=generated.short_code,
        expires_at=expires_at,
    )


@router.post(
    "/enrollment-command",
    response_model=EnrollmentCommandResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a VulnaScout: mint a token and build install commands",
)
async def create_enrollment_command(
    payload: EnrollmentCommandRequest,
    request: Request,
    admin: Annotated[User, Depends(require_permission("scouts.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> EnrollmentCommandResponse:
    """Mint a single-use enrollment token for a site and return copy-paste install
    commands. The token is short-lived, hashed centrally, and passed via the
    environment (not argv) so it does not linger in process listings. Every command
    routes through the signature-verifying bootstrap."""
    await get_accessible_site(session, admin, payload.site_id, permission_key="scouts.manage")

    generated = generate_token()
    expires_at = datetime.now(UTC) + timedelta(minutes=settings.enrollment_token_ttl_minutes)
    token = EnrollmentToken(
        organization_id=admin.organization_id,
        site_id=payload.site_id,
        token_hash=generated.token_hash,
        short_code=generated.short_code,
        probe_name=payload.probe_name,
        description=payload.description,
        created_by=admin.id,
        expires_at=expires_at,
    )
    session.add(token)
    await session.flush()

    record_audit(
        session,
        action="probe.enrollment_command_created",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="enrollment_token",
        target_id=token.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"site_id": str(payload.site_id), "short_code": generated.short_code},
    )

    server_url = str(settings.public_base_url or request.base_url).rstrip("/")
    return EnrollmentCommandResponse(
        site_id=token.site_id,
        probe_name=token.probe_name,
        token=generated.secret,
        short_code=generated.short_code,
        expires_at=expires_at,
        server_url=server_url,
        commands=build_install_commands(settings, server_url, generated.secret, token.probe_name),
        verification=(
            f"Confirm the short code '{generated.short_code}' matches on the Scout at "
            "enrollment. Enrolling does NOT authorize any target — approve a scope "
            "afterwards."
        ),
    )


# ---------------------------------------------------------------------------
# Probe-facing: enrollment (token-gated, no client cert yet)
# ---------------------------------------------------------------------------


@router.post(
    "/enroll",
    response_model=EnrollResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Enroll a probe using a one-time token and a CSR",
)
async def enroll_probe(
    payload: EnrollRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> EnrollResponse:
    """Consume an enrollment token and issue a client certificate for the probe."""
    invalid = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired enrollment token"
    )
    token_hash = hash_token(payload.token)
    result = await session.execute(
        select(EnrollmentToken)
        .where(EnrollmentToken.token_hash == token_hash)
        # Serialize consumers of this token until the request transaction
        # commits. A concurrent enrollment then observes ``used_at`` and is
        # rejected instead of issuing a second Scout identity.
        .with_for_update()
    )
    token = result.scalar_one_or_none()
    now = datetime.now(UTC)

    if token is None:
        raise invalid
    if token.used_at is not None:
        # Single-use: a reused token is rejected and audited.
        record_audit(
            session,
            action="probe.enroll_rejected_token_reused",
            actor_type=ActorType.SYSTEM,
            organization_id=token.organization_id,
            target_type="enrollment_token",
            target_id=token.id,
            source_ip=context.source_ip,
            request_id=context.request_id,
        )
        await session.commit()
        raise invalid
    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at < now:
        raise invalid
    if payload.encryption_public_key_b64 is not None:
        try:
            encryption_public_key = base64.b64decode(
                payload.encryption_public_key_b64, validate=True
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Scout credential-encryption public key is invalid",
            ) from exc
        if len(encryption_public_key) != 32:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Scout credential-encryption public key must be 32 raw bytes",
            )

    # Assign the probe's identity server-side and sign its CSR into a client cert.
    probe_id = uuid.uuid4()
    ca = get_ca(settings)
    try:
        cert = ca.sign_csr(
            payload.csr_pem.encode("utf-8"),
            common_name=str(probe_id),
            validity_days=settings.client_cert_validity_days,
        )
    except CertificateAuthorityError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    fingerprint = certificate_fingerprint(cert)
    cert_expires = cert.not_valid_after_utc

    # The internal single-host local Scout is auto-approved on enrollment; every
    # other probe is pending until an administrator approves it. Either way the
    # probe has no approved network scope until one is explicitly authorized.
    probe = Probe(
        id=probe_id,
        organization_id=token.organization_id,
        site_id=token.site_id,
        name=token.probe_name,
        description=token.description,
        status=ProbeStatus.ENROLLED if token.auto_approve else ProbeStatus.PENDING_ENROLLMENT,
        certificate_fingerprint=fingerprint,
        certificate_serial=format(cert.serial_number, "x"),
        certificate_expires_at=cert_expires,
        enrolled_at=now,
        approved_at=now if token.auto_approve else None,
        encryption_public_key_b64=payload.encryption_public_key_b64,
    )
    session.add(probe)

    token.used_at = now
    token.used_by_probe_id = probe_id
    await session.flush()

    # Bind to the site's default network (if any) so ranges added to the site via
    # the /scopes convenience reach this probe's policy.
    await networks_service.bind_probe_to_default_network(session, probe)

    record_audit(
        session,
        action="probe.enrolled",
        actor_type=ActorType.PROBE,
        actor_id=probe_id,
        organization_id=token.organization_id,
        target_type="probe",
        target_id=probe_id,
        source_ip=context.source_ip,
        request_id=context.request_id,
        metadata={"site_id": str(token.site_id), "fingerprint": fingerprint},
    )

    return EnrollResponse(
        probe_id=probe_id,
        site_id=token.site_id,
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        ca_certificate_pem=ca.cert_pem.decode("utf-8"),
        certificate_fingerprint=fingerprint,
        certificate_expires_at=cert_expires,
        signing_public_key_b64=get_signer().public_key_raw_b64,
    )


# ---------------------------------------------------------------------------
# Admin: probe management
# ---------------------------------------------------------------------------


async def _get_owned_probe(
    session: AsyncSession,
    probe_id: uuid.UUID,
    current_user: User,
    *,
    permission_key: str,
) -> Probe:
    probe = await session.scalar(
        select(Probe).where(
            Probe.id == probe_id,
            Probe.organization_id == current_user.organization_id,
            site_scope_clause(current_user, Probe.site_id, permission_key=permission_key),
        )
    )
    if probe is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Probe not found")
    return probe


@router.get("", response_model=Page[ProbeRead], summary="List probes")
async def list_probes(
    current_user: Annotated[User, Depends(require_permission("scouts.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    site_id: Annotated[uuid.UUID | None, Query(description="Filter by site")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ProbeRead]:
    """List probes in the caller's authorized organization/site scopes."""
    filters = [
        Probe.organization_id == current_user.organization_id,
        site_scope_clause(current_user, Probe.site_id, permission_key="scouts.read"),
    ]
    if site_id is not None:
        filters.append(Probe.site_id == site_id)
    total = await session.scalar(select(func.count()).select_from(Probe).where(*filters))
    result = await session.execute(
        select(Probe).where(*filters).order_by(Probe.created_at.asc()).limit(limit).offset(offset)
    )
    probes = result.scalars().all()
    return Page[ProbeRead](
        items=[
            serialize_probe(p, offline_after_seconds=settings.probe_offline_after_seconds)
            for p in probes
        ],
        total=total or 0,
        limit=limit,
        offset=offset,
    )


@router.get("/{probe_id}", response_model=ProbeRead, summary="Get a probe")
async def get_probe(
    probe_id: uuid.UUID,
    current_user: Annotated[User, Depends(require_permission("scouts.read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ProbeRead:
    probe = await _get_owned_probe(session, probe_id, current_user, permission_key="scouts.read")
    return serialize_probe(probe, offline_after_seconds=settings.probe_offline_after_seconds)


@router.patch("/{probe_id}", response_model=ProbeRead, summary="Rename or edit a probe (admin)")
async def update_probe(
    probe_id: uuid.UUID,
    payload: ProbeUpdate,
    admin: Annotated[User, Depends(require_permission("scouts.manage"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ProbeRead:
    """Update an appliance's editable fields (name, description). Administrator only."""
    probe = await _get_owned_probe(session, probe_id, admin, permission_key="scouts.manage")
    changed: dict[str, str] = {}
    if payload.name is not None and payload.name != probe.name:
        changed["name"] = payload.name
        probe.name = payload.name
    if payload.description is not None and payload.description != probe.description:
        changed["description"] = payload.description
        probe.description = payload.description
    if changed:
        record_audit(
            session,
            action="probe.updated",
            actor=admin,
            organization_id=admin.organization_id,
            target_type="probe",
            target_id=probe.id,
            source_ip=context.source_ip,
            user_agent=context.user_agent,
            request_id=context.request_id,
            metadata={"fields": ",".join(changed.keys())},
        )
        await session.flush()
    return serialize_probe(probe, offline_after_seconds=settings.probe_offline_after_seconds)


async def _lifecycle_transition(
    *,
    probe: Probe,
    new_status: ProbeStatus,
    admin: User,
    session: AsyncSession,
    settings: Settings,
    context: RequestContext,
    action: str,
    timestamp_field: str,
) -> ProbeRead:
    now = datetime.now(UTC)
    probe.status = new_status
    setattr(probe, timestamp_field, now)
    await session.flush()
    record_audit(
        session,
        action=action,
        actor=admin,
        organization_id=admin.organization_id,
        target_type="probe",
        target_id=probe.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"fingerprint": probe.certificate_fingerprint},
    )
    return serialize_probe(probe, offline_after_seconds=settings.probe_offline_after_seconds)


@router.post("/{probe_id}/approve", response_model=ProbeRead, summary="Approve a probe")
async def approve_probe(
    probe_id: uuid.UUID,
    admin: Annotated[User, Depends(require_permission("scouts.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ProbeRead:
    """Approve a pending probe, moving it to the ``enrolled`` (active) state."""
    probe = await _get_owned_probe(session, probe_id, admin, permission_key="scouts.manage")
    if probe.status not in (ProbeStatus.PENDING_ENROLLMENT, ProbeStatus.DISABLED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot approve a probe in state '{probe.status.value}'",
        )
    return await _lifecycle_transition(
        probe=probe,
        new_status=ProbeStatus.ENROLLED,
        admin=admin,
        session=session,
        settings=settings,
        context=context,
        action="probe.approved",
        timestamp_field="approved_at",
    )


@router.post("/{probe_id}/revoke", response_model=ProbeRead, summary="Revoke a probe")
async def revoke_probe(
    probe_id: uuid.UUID,
    admin: Annotated[User, Depends(require_permission("scouts.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ProbeRead:
    """Revoke a probe's certificate; it can no longer heartbeat or poll jobs."""
    probe = await _get_owned_probe(session, probe_id, admin, permission_key="scouts.manage")
    return await _lifecycle_transition(
        probe=probe,
        new_status=ProbeStatus.REVOKED,
        admin=admin,
        session=session,
        settings=settings,
        context=context,
        action="probe.revoked",
        timestamp_field="revoked_at",
    )


@router.post(
    "/{probe_id}/pentest",
    response_model=ProbeRead,
    summary="Enable or disable controlled-pentest execution on a scout",
)
async def set_pentest_enabled(
    probe_id: uuid.UUID,
    payload: PentestToggle,
    admin: Annotated[User, Depends(require_permission("scouts.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ProbeRead:
    """Opt a scout in or out of controlled-pentest execution. Only an enabled
    scout's signed policy permits the controlled_pentest mode, so a disabled scout
    fails closed on any pentest job (even from a compromised orchestrator). Bumps
    no scope, but the policy hash changes so the scout re-syncs."""
    probe = await _get_owned_probe(session, probe_id, admin, permission_key="scouts.manage")
    probe.pentest_enabled = payload.enabled
    record_audit(
        session,
        action="probe.pentest_" + ("enabled" if payload.enabled else "disabled"),
        actor=admin,
        organization_id=admin.organization_id,
        target_type="probe",
        target_id=probe.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
    )
    await session.flush()
    return serialize_probe(probe, offline_after_seconds=settings.probe_offline_after_seconds)


@router.post(
    "/{probe_id}/credentialed-scans",
    response_model=ProbeRead,
    summary="Enable or disable authenticated inventory on a Scout",
)
async def set_credentialed_scans_enabled(
    probe_id: uuid.UUID,
    payload: CredentialedScanToggle,
    admin: Annotated[User, Depends(require_permission("scouts.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ProbeRead:
    probe = await _get_owned_probe(session, probe_id, admin, permission_key="scouts.manage")
    if payload.enabled and not probe.encryption_public_key_b64:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scout must re-enroll with an X25519 encryption key before credential delivery",
        )
    probe.credentialed_scans_enabled = payload.enabled
    await session.flush()
    record_audit(
        session,
        action="probe.credentialed_scans_changed",
        actor=admin,
        organization_id=admin.organization_id,
        target_type="probe",
        target_id=probe.id,
        source_ip=context.source_ip,
        user_agent=context.user_agent,
        request_id=context.request_id,
        metadata={"enabled": payload.enabled},
    )
    return serialize_probe(probe, offline_after_seconds=settings.probe_offline_after_seconds)


@router.post("/{probe_id}/disable", response_model=ProbeRead, summary="Disable a probe")
async def disable_probe(
    probe_id: uuid.UUID,
    admin: Annotated[User, Depends(require_permission("scouts.manage"))],
    _step_up: StepUpIdentity,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ProbeRead:
    """Temporarily disable a probe (reversible via approve)."""
    probe = await _get_owned_probe(session, probe_id, admin, permission_key="scouts.manage")
    return await _lifecycle_transition(
        probe=probe,
        new_status=ProbeStatus.DISABLED,
        admin=admin,
        session=session,
        settings=settings,
        context=context,
        action="probe.disabled",
        timestamp_field="disabled_at",
    )


# ---------------------------------------------------------------------------
# Probe-facing: heartbeat and job polling (client-cert authenticated)
# ---------------------------------------------------------------------------


def _certificate_status(probe: Probe, now: datetime) -> CertificateStatus:
    status_str = "unknown"
    expires = probe.certificate_expires_at
    if expires is not None:
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        status_str = "expiring_soon" if (expires - now) < _CERT_EXPIRING_SOON else "ok"
    return CertificateStatus(
        fingerprint=probe.certificate_fingerprint,
        expires_at=probe.certificate_expires_at,
        status=status_str,
    )


@router.post("/self-revoke", summary="Probe self-revocation (reset)")
async def self_revoke(
    probe: CurrentProbe,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, str]:
    """A probe revokes its own identity, used by ``vulnascout reset``. After this the
    certificate can no longer heartbeat, poll jobs, or upload results — the old
    identity is dead centrally even if the local key survived on disk."""
    if probe.status != ProbeStatus.REVOKED:
        probe.status = ProbeStatus.REVOKED
        probe.revoked_at = datetime.now(UTC)
        session.add(probe)
        record_audit(
            session,
            action="probe.self_revoked",
            actor_type=ActorType.PROBE,
            organization_id=probe.organization_id,
            target_type="probe",
            target_id=probe.id,
            metadata={"probe_id": str(probe.id)},
        )
        await session.commit()
    return {"status": "revoked", "probe_id": str(probe.id)}


@router.post(
    "/{probe_id}/heartbeat",
    response_model=HeartbeatResponse,
    summary="Probe heartbeat",
)
async def heartbeat(
    probe_id: uuid.UUID,
    payload: HeartbeatRequest,
    probe: CurrentProbe,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> HeartbeatResponse:
    """Record a probe heartbeat and return server directives.

    The path ``probe_id`` must match the certificate-authenticated probe.
    """
    if probe.id != probe_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Certificate does not match the requested probe",
        )

    now = datetime.now(UTC)
    probe.last_seen_at = now
    if payload.agent_version is not None:
        probe.agent_version = payload.agent_version
    if payload.hostname is not None:
        probe.hostname = payload.hostname
    if payload.operating_system is not None:
        probe.operating_system = payload.operating_system
    if payload.architecture is not None:
        probe.architecture = payload.architecture
    if payload.capabilities:
        probe.capabilities_json = payload.capabilities
    if payload.health:
        probe.health_json = payload.health
    if payload.policy_hash is not None:
        probe.policy_hash = payload.policy_hash
    await session.flush()

    # Opportunistically reap stale jobs org-wide so a dead scout's work (and any
    # workflow waiting on it) doesn't hang. Cheap, indexed, and self-healing.
    await reaper.reap_stale_jobs(session, settings, organization_id=probe.organization_id)

    # Advertise the current policy so the probe can detect a stale local policy.
    policy_payload = await build_policy_document(session, probe, settings)
    current_hash = document_hash(policy_payload)
    policy_status = PolicyStatus(
        version=policy_payload["policy_version"],
        hash=current_hash,
        update_available=payload.policy_hash != current_hash,
    )

    # Jobs the probe should stop (cancellation requested while still active).
    cancel_result = await session.execute(
        select(ScanJob.id).where(
            ScanJob.probe_id == probe.id,
            ScanJob.cancel_requested_at.is_not(None),
            ScanJob.status.in_([JobStatus.OFFERED, JobStatus.ACCEPTED, JobStatus.RUNNING]),
        )
    )
    cancellations = [row[0] for row in cancel_result.all()]
    pending = await session.scalar(
        select(func.count())
        .select_from(ScanJob)
        .where(ScanJob.probe_id == probe.id, ScanJob.status == JobStatus.QUEUED)
    )

    return HeartbeatResponse(
        server_time=now,
        probe_status=probe.status,
        certificate=_certificate_status(probe, now),
        policy=policy_status,
        agent_update=None,
        pending_job_count=pending or 0,
        cancellations=cancellations,
        heartbeat_interval_seconds=_HEARTBEAT_INTERVAL_SECONDS,
    )


@router.get(
    "/{probe_id}/policy",
    summary="Fetch the signed local policy",
)
async def get_policy(
    probe_id: uuid.UUID,
    probe: CurrentProbe,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, object]:
    """Return the probe's signed local policy document (client-cert authenticated)."""
    if probe.id != probe_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Certificate does not match the requested probe",
        )
    payload = await build_policy_document(session, probe, settings)
    return get_signer().sign_document(payload)


@router.post(
    "/{probe_id}/jobs/next",
    response_model=None,
    summary="Poll for the next job",
)
async def poll_next_job(
    probe_id: uuid.UUID,
    probe: CurrentProbe,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    """Return the next signed job envelope for the probe, or 204 when none.

    Revoked or disabled probes are rejected by certificate authentication before
    reaching here, satisfying "a revoked probe cannot poll jobs".
    """
    if probe.id != probe_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Certificate does not match the requested probe",
        )

    now = datetime.now(UTC)
    await _reclaim_expired_attempts(session, probe, now)
    result = await session.execute(
        select(ScanJob)
        .where(
            ScanJob.probe_id == probe.id,
            ScanJob.status == JobStatus.QUEUED,
            ScanJob.cancel_requested_at.is_(None),
        )
        .order_by(ScanJob.created_at.asc())
        .limit(32)
        .with_for_update(skip_locked=True)
    )
    for job in result.scalars():
        expires = job.expires_at if job.expires_at.tzinfo else job.expires_at.replace(tzinfo=UTC)
        not_before = job.not_before if job.not_before.tzinfo else job.not_before.replace(tzinfo=UTC)
        if expires <= now:
            job.status = JobStatus.EXPIRED
            job.finished_at = now
            continue
        if not_before > now:
            continue  # not yet eligible; leave queued
        if "schema_version" not in job.envelope_json:
            # Rolling-upgrade bridge for jobs queued before the v1 wire
            # contract became explicit. Re-sign only work that has never been
            # offered; historical/active envelopes remain immutable.
            unsigned = dict(job.envelope_json)
            unsigned.pop("signature", None)
            unsigned["schema_version"] = 1
            unsigned["profile_version"] = 1
            job.envelope_json = get_signer().sign_document(unsigned)
        job.status = JobStatus.OFFERED
        job.offered_at = now
        previous_fence = await session.scalar(
            select(func.max(ScanJobAttempt.fencing_token)).where(
                ScanJobAttempt.scan_job_id == job.id
            )
        )
        fencing_token = (previous_fence or 0) + 1
        attempt = ScanJobAttempt(
            scan_job_id=job.id,
            probe_id=probe.id,
            attempt_number=fencing_token,
            fencing_token=fencing_token,
            lease_id=uuid.uuid4(),
            status="offered",
            offered_at=now,
            lease_expires_at=now + _JOB_LEASE_DURATION,
        )
        session.add(attempt)
        await session.flush()
        return JSONResponse(content=job.envelope_json, headers=_attempt_response_headers(attempt))

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{probe_id}/jobs/{job_id}/lease",
    response_model=None,
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Renew an active job-attempt lease",
)
async def renew_job_lease(
    probe_id: uuid.UUID,
    job_id: uuid.UUID,
    probe: CurrentProbe,
    session: Annotated[AsyncSession, Depends(get_session)],
    attempt_id: Annotated[str | None, Header(alias="X-Vulna-Attempt-ID", max_length=36)] = None,
    lease_id: Annotated[str | None, Header(alias="X-Vulna-Lease-ID", max_length=36)] = None,
    fencing_token: Annotated[
        str | None, Header(alias="X-Vulna-Fencing-Token", max_length=20)
    ] = None,
) -> Response:
    if probe.id != probe_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Certificate does not match the requested probe",
        )
    job = await session.get(ScanJob, job_id)
    if job is None or job.probe_id != probe.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    now = datetime.now(UTC)
    attempt = await _require_current_attempt(
        session,
        job=job,
        probe=probe,
        attempt_id=attempt_id,
        lease_id=lease_id,
        fencing_token=fencing_token,
        now=now,
    )
    if job.cancel_requested_at is not None:
        # A non-success response is the cancellation signal consumed by current
        # Scouts. They stop the worker and report the attempt as cancelled; the
        # existing attempt headers remain valid for that terminal report.
        return Response(status_code=status.HTTP_409_CONFLICT)
    attempt.last_renewed_at = now
    attempt.lease_expires_at = now + _JOB_LEASE_DURATION
    return Response(
        status_code=status.HTTP_204_NO_CONTENT,
        headers={"X-Vulna-Lease-Expires-At": attempt.lease_expires_at.isoformat()},
    )


@router.post(
    "/{probe_id}/jobs/{job_id}/status",
    response_model=None,
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Report job status",
)
async def report_job_status(
    probe_id: uuid.UUID,
    job_id: uuid.UUID,
    payload: JobStatusUpdate,
    probe: CurrentProbe,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    attempt_id: Annotated[str | None, Header(alias="X-Vulna-Attempt-ID", max_length=36)] = None,
    lease_id: Annotated[str | None, Header(alias="X-Vulna-Lease-ID", max_length=36)] = None,
    fencing_token: Annotated[
        str | None, Header(alias="X-Vulna-Fencing-Token", max_length=20)
    ] = None,
) -> Response:
    """A probe reports progress/outcome for a job it was offered."""
    if probe.id != probe_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Certificate does not match the requested probe",
        )
    job = await session.get(ScanJob, job_id)
    if job is None or job.probe_id != probe.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    now = datetime.now(UTC)
    attempt = await _require_current_attempt(
        session,
        job=job,
        probe=probe,
        attempt_id=attempt_id,
        lease_id=lease_id,
        fencing_token=fencing_token,
        now=now,
        allow_terminal=True,
    )
    terminal_statuses = {
        JobStatus.COMPLETED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
        JobStatus.EXPIRED,
        JobStatus.REJECTED_BY_PROBE,
    }
    if job.status in terminal_statuses:
        if payload.status == job.status or (
            job.status == JobStatus.EXPIRED and payload.status in terminal_statuses
        ):
            # A server-side timeout can race the Scout's own terminal report.
            # Keep the already-published EXPIRED outcome, but acknowledge any
            # late terminal status so the Scout can release its local job slot.
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A terminal scan job cannot return to an active state",
        )

    allowed_attempt_transitions = {
        "offered": {"accepted", "rejected_by_probe"},
        "accepted": {"accepted", "running", "failed", "cancelled", "rejected_by_probe"},
        "running": {"running", "completed", "failed", "cancelled", "rejected_by_probe"},
    }
    requested_status = payload.status.value
    if requested_status not in allowed_attempt_transitions.get(attempt.status, set()):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Invalid job-attempt transition from {attempt.status} to {requested_status}",
        )
    if payload.progress is not None:
        try:
            apply_progress(job, payload.progress, now)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    job.status = payload.status
    attempt.status = requested_status
    if requested_status in _ACTIVE_ATTEMPT_STATUSES:
        attempt.last_renewed_at = now
        attempt.lease_expires_at = now + _JOB_LEASE_DURATION
    if payload.status == JobStatus.ACCEPTED:
        job.accepted_at = now
        attempt.accepted_at = attempt.accepted_at or now
    elif payload.status == JobStatus.RUNNING:
        job.started_at = job.started_at or now
        attempt.started_at = attempt.started_at or now
    elif payload.status in (
        JobStatus.COMPLETED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
        JobStatus.REJECTED_BY_PROBE,
    ):
        job.finished_at = now
        attempt.finished_at = now
        job.estimated_completion_at = None
        if payload.status == JobStatus.COMPLETED:
            job.progress_percent = 100
            job.last_progress_at = now
        if payload.error_code is not None:
            job.error_code = sanitize_label(payload.error_code)
        if payload.error_message is not None:
            job.error_message = sanitize_failure_message(payload.error_message)
        if payload.summary is not None:
            job.summary_json = payload.summary
        if payload.status in (
            JobStatus.FAILED,
            JobStatus.CANCELLED,
            JobStatus.REJECTED_BY_PROBE,
        ):
            job.failure_log_json = build_failure_log(
                payload.failure_details,
                now=now,
                fallback_code=job.error_code,
                fallback_message=job.error_message,
            )
            record_audit(
                session,
                action="job.failure_recorded",
                actor_type=ActorType.PROBE,
                actor_id=probe.id,
                organization_id=job.organization_id,
                target_type="scan_job",
                target_id=job.id,
                metadata={
                    "error_code": job.error_code,
                    "diagnostic_entries": len(job.failure_log_json),
                },
            )
        usage_rows = list(
            (
                await session.execute(
                    select(CredentialUsageAudit).where(CredentialUsageAudit.scan_job_id == job.id)
                )
            ).scalars()
        )
        usage_status = (
            CredentialUsageStatus.SUCCEEDED
            if payload.status == JobStatus.COMPLETED
            else CredentialUsageStatus.FAILED
        )
        for usage in usage_rows:
            usage.status = usage_status
            if payload.error_code is not None:
                usage.detail = payload.error_code
        tests = list(
            (
                await session.execute(
                    select(CredentialTest).where(CredentialTest.scan_job_id == job.id)
                )
            ).scalars()
        )
        for credential_test in tests:
            credential_test.status = (
                CredentialTestStatus.SUCCEEDED
                if payload.status == JobStatus.COMPLETED
                else CredentialTestStatus.FAILED
            )
            credential_test.message = payload.error_code
            credential_test.finished_at = now
        await _emit_scan_event(session, job, payload.status)
        # A workflow's scan job finished: advance its stage and chain the next.
        await workflow_dispatch.on_scan_job_terminal(session, settings, job, payload.status)
        # A controlled-pentest job finished: close out its session (evidence is
        # minimized again server-side; cleanup state follows the teardown guarantee).
        if job.mode == JobMode.CONTROLLED_PENTEST:
            await pentest_service.complete_session_for_job(
                session,
                job=job,
                job_status=payload.status,
                evidence=payload.summary,
                now=now,
            )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


async def _emit_scan_event(session: AsyncSession, job: ScanJob, job_status: JobStatus) -> None:
    """Best-effort: queue a scan_completed/scan_failed notification. A notification
    problem must never block the job-status update, so this never raises."""
    mapping = {
        JobStatus.COMPLETED: (EventType.SCAN_COMPLETED, "info", "Scan completed"),
        JobStatus.FAILED: (EventType.SCAN_FAILED, "high", "Scan failed"),
    }
    if job_status not in mapping:
        return
    event_type, severity, title = mapping[job_status]
    # Notifications are never allowed to block a scan status update.
    with contextlib.suppress(Exception):
        await emit_event(
            session,
            job.organization_id,
            NotificationEvent(
                type=event_type,
                title=title,
                summary=f"{title} for a scan on this site.",
                severity=severity,
                site_id=str(job.site_id),
                object_type="job",
                object_id=str(job.id),
                data={"error_code": job.error_code or ""},
            ),
        )


@router.post(
    "/{probe_id}/jobs/{job_id}/results",
    response_model=ResultIngestSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Upload raw scanner results",
)
async def upload_job_results(
    probe_id: uuid.UUID,
    job_id: uuid.UUID,
    request: Request,
    response: Response,
    probe: CurrentProbe,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    stage: Annotated[str, Query(max_length=64)] = "discovery",
    scanner: Annotated[str, Query(max_length=64)] = "nmap",
    complete: Annotated[bool, Query()] = False,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", max_length=64)] = None,
    attempt_id: Annotated[str | None, Header(alias="X-Vulna-Attempt-ID", max_length=36)] = None,
    lease_id: Annotated[str | None, Header(alias="X-Vulna-Lease-ID", max_length=36)] = None,
    fencing_token: Annotated[
        str | None, Header(alias="X-Vulna-Fencing-Token", max_length=20)
    ] = None,
) -> ResultIngestSummary:
    """Ingest a probe's raw scanner output for a job.

    Nmap XML becomes assets/services; Nuclei JSONL and testssl.sh JSON become
    normalized findings. Raw output is retained verbatim and parsed defensively.

    A Scout on an intermittent link may re-upload a result after a lost
    acknowledgement. Every upload therefore requires a stable ``Idempotency-Key``;
    processed keys are recorded per job and repeats are no-ops. The reported
    stage/scanner pair must also be present in the signed workflow, binding raw
    evidence to the exact work the Scout was authorized to perform.
    """
    if probe.id != probe_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Certificate does not match the requested probe",
        )
    job = await session.get(ScanJob, job_id)
    if job is None or job.probe_id != probe.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    now = datetime.now(UTC)
    attempt = await _require_current_attempt(
        session,
        job=job,
        probe=probe,
        attempt_id=attempt_id,
        lease_id=lease_id,
        fencing_token=fencing_token,
        now=now,
        allow_terminal=True,
    )
    if attempt.status not in {"accepted", "running", *_TERMINAL_ATTEMPT_STATUSES}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Results cannot be uploaded before the job attempt is accepted",
        )

    expected_stage = any(
        value.get("stage") == stage and value.get("plugin") == scanner
        for value in (job.workflow_json or [])
    )
    if not expected_stage:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Result stage and scanner do not match the signed job workflow",
        )
    # Bound the request before reading it. A versioned JSON envelope carries a
    # base64 payload and therefore receives only the corresponding 4/3 overhead.
    envelope_request = request.headers.get("content-type", "").split(";", 1)[0].strip() == (
        _RESULT_ENVELOPE_CONTENT_TYPE
    )
    request_limit = _MAX_RESULT_ENVELOPE_BYTES if envelope_request else _MAX_RESULT_BYTES
    content_length = request.headers.get("content-length")
    if (
        content_length is not None
        and content_length.isdigit()
        and int(content_length) > request_limit
    ):
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Result upload too large"
        )
    body = await request.body()
    if len(body) > request_limit:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Result upload too large"
        )

    if envelope_request:
        try:
            envelope = ResultUploadEnvelope.model_validate_json(body)
            raw = base64.b64decode(envelope.payload, validate=True)
        except (ValueError, TypeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Result envelope is invalid",
            ) from exc
        if (
            envelope.job_id != job.id
            or envelope.probe_id != probe.id
            or envelope.stage != stage
            or envelope.scanner != scanner
            or envelope.complete != complete
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Result envelope identity does not match its authenticated upload",
            )
        expected_format = _RESULT_FORMATS_BY_SCANNER.get(scanner)
        if expected_format is None or envelope.result_format != expected_format:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Result envelope format does not match its scanner",
            )
        if len(raw) != envelope.byte_length or len(raw) > _MAX_RESULT_BYTES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Result envelope byte length is invalid",
            )
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if digest != envelope.content_hash:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Result envelope content hash does not match its payload",
            )
        body = raw

    # Current Scouts must explicitly bind their versioned envelope to the same
    # stable key they will reuse after a lost acknowledgement. For rolling
    # compatibility with raw-body Scouts, the server derives that exact key
    # instead of permitting a non-idempotent upload.
    if not idempotency_key:
        if envelope_request:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Versioned result uploads require an Idempotency-Key",
            )
        idempotency_key = _result_idempotency_key(job.id, stage, scanner, body, complete=complete)
    elif envelope_request and idempotency_key != _result_idempotency_key(
        job.id, stage, scanner, body, complete=complete
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Result Idempotency-Key does not match the authenticated envelope",
        )

    already = await session.scalar(
        select(ProbeResultUpload.id).where(
            ProbeResultUpload.scan_job_id == job.id,
            ProbeResultUpload.idempotency_key == idempotency_key,
        )
    )
    if already is not None:
        response.status_code = status.HTTP_200_OK
        return ResultIngestSummary(duplicate=True)

    if complete:
        await finalize_scanner_verification(session, job=job, scanner=scanner, now=now)
        session.add(
            ProbeResultUpload(
                scan_job_id=job.id,
                scan_job_attempt_id=attempt.id,
                idempotency_key=idempotency_key,
            )
        )
        return ResultIngestSummary()

    try:
        if scanner == "nmap":
            nmap_summary = await ingest_nmap_result(
                session,
                job=job,
                xml_bytes=body,
                probe_id=probe.id,
                stage=stage,
                scanner=scanner,
                master_key=settings.master_key,
            )
            result = ResultIngestSummary(
                hosts_seen=nmap_summary.hosts_seen,
                assets_created=nmap_summary.assets_created,
                assets_updated=nmap_summary.assets_updated,
                services_upserted=nmap_summary.services_upserted,
                change_events=nmap_summary.change_events,
            )
        elif scanner in ("nuclei", "testssl", "zap"):
            store_scan_artifact(
                session,
                job=job,
                probe_id=probe.id,
                stage=stage,
                scanner=scanner,
                raw=body,
                content_type="application/json",
                master_key=settings.master_key,
            )
            if scanner == "nuclei":
                parsed = parse_nuclei_jsonl(body)
            elif scanner == "testssl":
                parsed = parse_testssl_json(body)
            else:
                parsed = parse_zap_json(body)
            fsummary = await ingest_findings(session, job=job, parsed=parsed, now=now)
            result = ResultIngestSummary(
                findings_seen=fsummary.findings_seen,
                findings_created=fsummary.findings_created,
                findings_updated=fsummary.findings_updated,
                findings_reopened=fsummary.findings_reopened,
                change_events=fsummary.change_events,
            )
        elif scanner == "metasploit":
            # Controlled-pentest exploit output: retain the raw artifact (encrypted)
            # and record the minimized loot + cleanup_verified flag onto the session,
            # which is where they must land — the terminal status summary carries only
            # stage counts.
            store_scan_artifact(
                session,
                job=job,
                probe_id=probe.id,
                stage=stage,
                scanner=scanner,
                raw=body,
                content_type="application/json",
                master_key=settings.master_key,
            )
            try:
                output = json.loads(body)
            except (json.JSONDecodeError, ValueError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="metasploit result is not valid JSON",
                ) from exc
            if isinstance(output, dict):
                await pentest_service.record_pentest_result(session, job=job, output=output)
            result = ResultIngestSummary()
        elif scanner in ("ssh_inventory", "winrm_inventory"):
            expected_protocol = scanner.removesuffix("_inventory")
            if expected_protocol not in job.credential_protocols_json or job.asset_id is None:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Inventory result does not match the signed authenticated job",
                )
            inventory = await ingest_inventory(
                session,
                job=job,
                raw=body,
                source=(
                    SoftwareInventorySource.SSH
                    if scanner == "ssh_inventory"
                    else SoftwareInventorySource.WINRM
                ),
                now=now,
            )
            result = ResultIngestSummary(
                packages_seen=inventory.packages_seen,
                packages_added=inventory.packages_added,
                packages_updated=inventory.packages_updated,
                packages_removed=inventory.packages_removed,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unsupported scanner '{scanner}'",
            )
    except (NmapParseError, SoftwareInventoryError, TestsslParseError, ZapParseError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    if job.started_at is None:
        job.started_at = now
    session.add(
        ProbeResultUpload(
            scan_job_id=job.id,
            scan_job_attempt_id=attempt.id,
            idempotency_key=idempotency_key,
        )
    )
    return result
