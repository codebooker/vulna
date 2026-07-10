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

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.context import RequestContext, get_request_context
from app.api.probe_auth import CurrentProbe
from app.auth.dependencies import CurrentUser, require_admin
from app.core.config import Settings, get_settings
from app.db.session import get_session
from app.models.enrollment_token import EnrollmentToken
from app.models.enums import ActorType, JobStatus, ProbeStatus
from app.models.probe import Probe
from app.models.scan_job import ScanJob
from app.models.site import Site
from app.models.user import User
from app.schemas.common import Page
from app.schemas.enrollment import (
    EnrollmentTokenCreate,
    EnrollmentTokenCreated,
    EnrollRequest,
    EnrollResponse,
)
from app.schemas.job import JobStatusUpdate, ResultIngestSummary
from app.schemas.probe import (
    CertificateStatus,
    HeartbeatRequest,
    HeartbeatResponse,
    PolicyStatus,
    ProbeRead,
    serialize_probe,
)
from app.services.audit import record_audit
from app.services.ca import CertificateAuthorityError, certificate_fingerprint, get_ca
from app.services.enrollment import generate_token, hash_token
from app.services.findings import ingest_findings
from app.services.ingest import ingest_nmap_result, store_scan_artifact
from app.services.nmap_parser import NmapParseError
from app.services.nuclei_parser import parse_nuclei_jsonl
from app.services.policy import build_policy_document
from app.services.remediation import apply_verification
from app.services.signing import document_hash, get_signer
from app.services.testssl_parser import TestsslParseError, parse_testssl_json
from app.services.zap_parser import ZapParseError, parse_zap_json

# Upper bound on a single result upload (defense against oversized payloads).
_MAX_RESULT_BYTES = 25 * 1024 * 1024

router = APIRouter(prefix="/probes", tags=["probes"])

# A suggested client heartbeat cadence; also used for the "expiring soon" window.
_HEARTBEAT_INTERVAL_SECONDS = 60
_CERT_EXPIRING_SOON = timedelta(days=14)


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
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> EnrollmentTokenCreated:
    """Mint a single-use enrollment token for a site (Administrator only)."""
    site = await session.get(Site, payload.site_id)
    if site is None or site.organization_id != admin.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Site not found")

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
        select(EnrollmentToken).where(EnrollmentToken.token_hash == token_hash)
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
    )
    session.add(probe)

    token.used_at = now
    token.used_by_probe_id = probe_id
    await session.flush()

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


async def _get_owned_probe(session: AsyncSession, probe_id: uuid.UUID, org_id: uuid.UUID) -> Probe:
    probe = await session.get(Probe, probe_id)
    if probe is None or probe.organization_id != org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Probe not found")
    return probe


@router.get("", response_model=Page[ProbeRead], summary="List probes")
async def list_probes(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    site_id: Annotated[uuid.UUID | None, Query(description="Filter by site")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[ProbeRead]:
    """List probes in the caller's organization (any authenticated role)."""
    filters = [Probe.organization_id == current_user.organization_id]
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
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ProbeRead:
    probe = await _get_owned_probe(session, probe_id, current_user.organization_id)
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
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ProbeRead:
    """Approve a pending probe, moving it to the ``enrolled`` (active) state."""
    probe = await _get_owned_probe(session, probe_id, admin.organization_id)
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
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ProbeRead:
    """Revoke a probe's certificate; it can no longer heartbeat or poll jobs."""
    probe = await _get_owned_probe(session, probe_id, admin.organization_id)
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


@router.post("/{probe_id}/disable", response_model=ProbeRead, summary="Disable a probe")
async def disable_probe(
    probe_id: uuid.UUID,
    admin: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    context: Annotated[RequestContext, Depends(get_request_context)],
) -> ProbeRead:
    """Temporarily disable a probe (reversible via approve)."""
    probe = await _get_owned_probe(session, probe_id, admin.organization_id)
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
    result = await session.execute(
        select(ScanJob)
        .where(
            ScanJob.probe_id == probe.id,
            ScanJob.status == JobStatus.QUEUED,
            ScanJob.cancel_requested_at.is_(None),
        )
        .order_by(ScanJob.created_at.asc())
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
        job.status = JobStatus.OFFERED
        job.offered_at = now
        return JSONResponse(content=job.envelope_json)

    return Response(status_code=status.HTTP_204_NO_CONTENT)


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
    job.status = payload.status
    if payload.status == JobStatus.ACCEPTED:
        job.accepted_at = now
    elif payload.status == JobStatus.RUNNING:
        job.started_at = job.started_at or now
    elif payload.status in (
        JobStatus.COMPLETED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
        JobStatus.REJECTED_BY_PROBE,
    ):
        job.finished_at = now
        if payload.error_code is not None:
            job.error_code = payload.error_code
        if payload.error_message is not None:
            job.error_message = payload.error_message
        if payload.summary is not None:
            job.summary_json = payload.summary
    return Response(status_code=status.HTTP_204_NO_CONTENT)


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
    probe: CurrentProbe,
    session: Annotated[AsyncSession, Depends(get_session)],
    stage: Annotated[str, Query(max_length=64)] = "discovery",
    scanner: Annotated[str, Query(max_length=64)] = "nmap",
) -> ResultIngestSummary:
    """Ingest a probe's raw scanner output for a job.

    Nmap XML becomes assets/services; Nuclei JSONL and testssl.sh JSON become
    normalized findings. Raw output is retained verbatim and parsed defensively.
    """
    if probe.id != probe_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Certificate does not match the requested probe",
        )
    job = await session.get(ScanJob, job_id)
    if job is None or job.probe_id != probe.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")

    # Bound the payload size before reading it.
    content_length = request.headers.get("content-length")
    if (
        content_length is not None
        and content_length.isdigit()
        and int(content_length) > _MAX_RESULT_BYTES
    ):
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Result upload too large"
        )
    body = await request.body()
    if len(body) > _MAX_RESULT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Result upload too large"
        )

    now = datetime.now(UTC)
    try:
        if scanner == "nmap":
            nmap_summary = await ingest_nmap_result(
                session, job=job, xml_bytes=body, probe_id=probe.id, stage=stage, scanner=scanner
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
                session, job=job, probe_id=probe.id, stage=stage, scanner=scanner,
                raw=body, content_type="application/json",
            )
            if scanner == "nuclei":
                parsed = parse_nuclei_jsonl(body)
            elif scanner == "testssl":
                parsed = parse_testssl_json(body)
            else:
                parsed = parse_zap_json(body)
            fsummary = await ingest_findings(session, job=job, parsed=parsed, now=now)
            await apply_verification(
                session, job=job, scanner=scanner, seen_keys=fsummary.seen_keys, now=now
            )
            result = ResultIngestSummary(
                findings_seen=fsummary.findings_seen,
                findings_created=fsummary.findings_created,
                findings_updated=fsummary.findings_updated,
                findings_reopened=fsummary.findings_reopened,
                change_events=fsummary.change_events,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unsupported scanner '{scanner}'",
            )
    except (NmapParseError, TestsslParseError, ZapParseError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    if job.started_at is None:
        job.started_at = now
    return result
