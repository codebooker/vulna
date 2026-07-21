"""Dispatch real scan jobs for a full-spectrum workflow run — one job per stage.

The workflow's scanning stages (discovery → vulnerability → TLS) each map to a
single-stage scan job, so every stage reflects the real success/failure of its
scanner instead of one monolithic job standing in for all three.

Scout and targets are chosen from the run's target network when set (a scout
bound to that network, over the network's ranges), or otherwise from the site's
first enrolled probe over its whole approved scope. Dispatch and the probe's
job-completion report drive the run forward.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.config import Settings
from app.models.enums import JobMode, JobStatus, ProbeStatus, WorkflowStageStatus
from app.models.probe import Probe
from app.models.scan_job import ScanJob
from app.models.workflow_run import WorkflowRun
from app.services import networks
from app.services import workflow as engine
from app.services.jobs import JobValidationError, create_scan_job

# Workflow scanning stage -> the job stage(s) that realize it.
_STAGE_JOB_MAP: dict[str, list[str]] = {
    "discovery": ["discovery"],
    "vulnerability_assessment": ["vulnerability"],
    # Re-run bounded discovery with the web/TLS stage so Scout can derive fresh,
    # in-scope HTTP(S) start URLs for automatic passive ZAP. Workflow stages are
    # separate jobs, so the earlier discovery job's in-memory endpoints are gone.
    "web_and_tls": ["discovery", "tls", "web"],
}


async def _select_scout(session: AsyncSession, run: WorkflowRun) -> Probe | None:
    """Choose an enrolled scout to run the scan.

    With a target network, prefer its primary bound scout, then any bound scout;
    otherwise fall back to the site's first enrolled probe.
    """
    if run.network_id is not None:
        return await networks.select_network_scout(session, run.network_id)

    return (
        await session.execute(
            select(Probe)
            .where(Probe.site_id == run.site_id, Probe.status == ProbeStatus.ENROLLED)
            .order_by(Probe.created_at.asc())
        )
    ).scalars().first()


async def _targets(
    session: AsyncSession, run: WorkflowRun, probe: Probe, settings: Settings
) -> list[str]:
    """Targets for the run: the network's ranges when targeting a network, else
    the probe's whole approved scope (via the signed policy)."""
    if run.network_id is not None:
        return await networks.network_cidrs(session, run.network_id)
    from app.services.policy import build_policy_document

    policy = await build_policy_document(session, probe, settings)
    return list(policy["approved_cidrs"])


async def dispatch_current_scan_stage(
    session: AsyncSession, settings: Settings, run: WorkflowRun
) -> None:
    """If the run's current stage is a scanning stage with no job yet in flight
    for it, dispatch a single-stage scan job and link it. On no scout / no scope /
    validation error, fail the scanning stage so the run proceeds to its tail."""
    stage = engine.current_stage_name(run)
    job_stages = _STAGE_JOB_MAP.get(stage or "")
    if job_stages is None:
        return
    now = datetime.now(UTC)

    # One test per network at a time: never a second scout on a network already
    # under test. (The just-completed prior stage's job is terminal, so a
    # workflow's own next stage is not blocked by itself.)
    if run.network_id is not None and await networks.network_has_active_job(
        session, run.network_id
    ):
        engine.fail_scanning(run, detail="The network is already under test", now=now)
        flag_modified(run, "stages_json")
        return

    probe = await _select_scout(session, run)
    if probe is None:
        engine.fail_scanning(run, detail="No enrolled scout is available for this scan", now=now)
        flag_modified(run, "stages_json")
        return
    targets = await _targets(session, run, probe, settings)
    if not targets:
        engine.fail_scanning(run, detail="The target has no ranges/scope to scan", now=now)
        flag_modified(run, "stages_json")
        return
    try:
        job = await create_scan_job(
            session, probe, settings,
            targets=targets,
            mode=JobMode.VULNERABILITY_ASSESSMENT,
            created_by=run.created_by,
            stages=job_stages,
            network_id=run.network_id,
        )
    except JobValidationError as exc:
        engine.fail_scanning(run, detail=f"Could not dispatch scan: {exc}", now=now)
        flag_modified(run, "stages_json")
        return
    run.scan_job_id = job.id


async def on_scan_job_terminal(
    session: AsyncSession, settings: Settings, job: ScanJob, job_status: JobStatus
) -> None:
    """A workflow's scan job finished: advance its current scanning stage, then
    dispatch the next stage's job (or, on failure, skip to the tail)."""
    run = (
        await session.execute(select(WorkflowRun).where(WorkflowRun.scan_job_id == job.id))
    ).scalars().first()
    if run is None or not engine.scanning_stage_active(run):
        return
    now = datetime.now(UTC)
    if job_status == JobStatus.COMPLETED:
        engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=now)
        flag_modified(run, "stages_json")
        # Chain: if the next stage is also a scanning stage, dispatch its job.
        await dispatch_current_scan_stage(session, settings, run)
    else:
        engine.fail_scanning(
            run, detail=job.error_message or f"scan {job_status.value}", now=now
        )
        flag_modified(run, "stages_json")
