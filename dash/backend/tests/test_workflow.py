"""Full-spectrum workflow engine state machine and API."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from app.models.enums import UserRole, WorkflowRunStatus, WorkflowStageStatus
from app.models.workflow_run import WorkflowRun
from app.services import workflow as engine
from httpx import AsyncClient

from tests.conftest import UserFactory, auth_headers, probe_cert_headers, start_job_attempt

NOW = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)

EnrollFactory = Callable[..., Awaitable[dict[str, str]]]


def _run(*, web: bool, intrusive: bool) -> WorkflowRun:
    run = WorkflowRun(
        include_web=web,
        include_intrusive=intrusive,
        intrusive_approved=False,
        status=WorkflowRunStatus.PENDING,
        stages_json=engine.create_run(include_web=web, include_intrusive=intrusive),
    )
    engine.start(run, NOW)
    return run


def _status(run: WorkflowRun, name: str) -> str:
    return next(s["status"] for s in run.stages_json if s["name"] == name)


def _drive_to_gate_or_end(run: WorkflowRun) -> None:
    """Advance completing each running stage until the gate or the end."""
    while True:
        name = engine.current_stage_name(run)
        if name is None or name == "approval_gate":
            return
        engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)


def test_full_workflow_completes() -> None:
    run = _run(web=True, intrusive=False)
    _drive_to_gate_or_end(run)
    assert run.status == WorkflowRunStatus.COMPLETED
    assert _status(run, "reporting") == "completed"
    assert _status(run, "verification_scan") == "completed"
    # No intrusive requested -> validation stages skipped.
    assert _status(run, "approval_gate") == "skipped"
    assert _status(run, "allowlisted_validation") == "skipped"


def test_intrusive_denied_but_reports_still_generate() -> None:
    run = _run(web=False, intrusive=True)
    _drive_to_gate_or_end(run)
    assert engine.current_stage_name(run) == "approval_gate"
    assert run.status == WorkflowRunStatus.AWAITING_APPROVAL

    engine.decide_intrusive(run, approve=False, now=NOW)
    assert _status(run, "approval_gate") == "denied"
    # Validation is skipped; verification + reporting still run.
    assert _status(run, "allowlisted_validation") == "skipped"
    assert engine.current_stage_name(run) == "verification_scan"

    _drive_to_gate_or_end(run)
    assert run.status == WorkflowRunStatus.COMPLETED
    assert _status(run, "verification_scan") == "completed"
    assert _status(run, "reporting") == "completed"


def test_intrusive_approved_runs_validation_and_cleanup() -> None:
    run = _run(web=False, intrusive=True)
    _drive_to_gate_or_end(run)
    engine.decide_intrusive(run, approve=True, now=NOW)
    assert engine.current_stage_name(run) == "allowlisted_validation"
    _drive_to_gate_or_end(run)
    assert run.status == WorkflowRunStatus.COMPLETED
    for stage in ("allowlisted_validation", "evidence_collection", "cleanup", "reporting"):
        assert _status(run, stage) == "completed", stage


def test_stage_failure_is_reflected_and_tail_still_runs() -> None:
    run = _run(web=False, intrusive=True)
    # Complete precheck + discovery, then fail vulnerability assessment.
    engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)
    engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)
    engine.advance(run, outcome=WorkflowStageStatus.FAILED, detail="scanner crashed", now=NOW)

    # Intrusive validation stages are skipped after the failure...
    assert _status(run, "vulnerability_assessment") == "failed"
    assert _status(run, "candidate_validation_plan") == "skipped"
    # ...but verification + reporting still run.
    assert engine.current_stage_name(run) == "verification_scan"
    _drive_to_gate_or_end(run)
    assert _status(run, "verification_scan") == "completed"
    assert _status(run, "reporting") == "completed"
    assert run.status == WorkflowRunStatus.FAILED  # a stage failed


def test_scanning_stage_active_tracks_scan_stages() -> None:
    run = _run(web=True, intrusive=True)
    # Advance the precheck so discovery becomes the active (scanning) stage.
    engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)
    assert engine.scanning_stage_active(run)
    # Each scan stage is its own job; advancing one at a time walks discovery ->
    # vulnerability -> web_and_tls -> (intrusive) candidate_validation_plan.
    engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)
    assert engine.current_stage_name(run) == "vulnerability_assessment"
    assert engine.scanning_stage_active(run)
    engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)
    assert engine.current_stage_name(run) == "web_and_tls"
    engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)
    assert engine.current_stage_name(run) == "candidate_validation_plan"
    assert not engine.scanning_stage_active(run)


def test_fail_scanning_skips_to_tail() -> None:
    run = _run(web=False, intrusive=True)
    engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)  # precheck
    engine.fail_scanning(run, detail="probe offline", now=NOW)
    assert _status(run, "discovery") == "failed"
    assert _status(run, "candidate_validation_plan") == "skipped"
    assert engine.current_stage_name(run) == "verification_scan"


def test_cannot_advance_the_approval_gate() -> None:
    run = _run(web=False, intrusive=True)
    _drive_to_gate_or_end(run)
    try:
        engine.advance(run, outcome=WorkflowStageStatus.COMPLETED, detail=None, now=NOW)
    except engine.WorkflowError:
        return
    raise AssertionError("advancing the approval gate should raise")


# --- API E2E ---------------------------------------------------------------
async def _ready_probe(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    site_code: str = "WF",
) -> dict[str, str]:
    """Enroll + approve a probe and give its site an approved scope, so a workflow
    can dispatch a real scan job."""
    probe = await enroll_probe(site_code=site_code, probe_name=f"wf-{site_code}")
    await client.post(f"/api/v1/probes/{probe['probe_id']}/approve", headers=admin_headers)
    await client.post(
        "/api/v1/scopes",
        json={"site_id": probe["site_id"], "name": "lan", "cidr": "10.20.0.0/24"},
        headers=admin_headers,
    )
    return probe


async def _report_job(
    client: AsyncClient, probe: dict[str, str], job_id: str, job_status: str
) -> int:
    offered_job_id, attempt_headers = await start_job_attempt(
        client, probe["probe_id"], probe["fingerprint"]
    )
    assert offered_job_id == job_id
    resp = await client.post(
        f"/api/v1/probes/{probe['probe_id']}/jobs/{job_id}/status",
        json={"status": job_status},
        headers={**probe_cert_headers(probe["fingerprint"]), **attempt_headers},
    )
    return resp.status_code


_SCAN = ("discovery", "vulnerability_assessment", "web_and_tls")


async def _drive_scan_jobs(
    client: AsyncClient, probe: dict[str, str], run_id: str, headers: dict[str, str]
) -> dict:
    """Report each dispatched stage job complete until the run leaves the scanning
    phase (one job per stage). Returns the final run detail."""
    for _ in range(len(_SCAN) + 1):
        detail = (await client.get(f"/api/v1/workflows/{run_id}", headers=headers)).json()
        if engine_current(detail) not in _SCAN:
            return detail
        assert await _report_job(client, probe, detail["scan_job_id"], "completed") == 204
    return (await client.get(f"/api/v1/workflows/{run_id}", headers=headers)).json()


async def test_workflow_dispatches_scan_and_advances_on_completion(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe)
    created = await client.post(
        "/api/v1/workflows",
        json={"site_id": probe["site_id"], "include_web": True},
        headers=admin_headers,
    )
    assert created.status_code == 201, created.text
    run_id = created.json()["id"]
    assert created.json()["scan_job_id"] is None  # nothing dispatched at creation

    # Advancing the authorization precheck enters discovery -> dispatches a job.
    r = await client.post(
        f"/api/v1/workflows/{run_id}/advance", json={"outcome": "completed"}, headers=admin_headers
    )
    assert r.status_code == 200
    job_id = r.json()["scan_job_id"]
    assert job_id is not None

    # The scanning stage is now job-driven: manual advance is refused.
    manual = await client.post(
        f"/api/v1/workflows/{run_id}/advance", json={"outcome": "completed"}, headers=admin_headers
    )
    assert manual.status_code == 409

    # Each scan stage runs as its own job; completing each advances one stage and
    # dispatches the next. Drive all three to completion.
    detail = await _drive_scan_jobs(client, probe, run_id, admin_headers)
    stages = {s["name"]: s["status"] for s in detail["stages_json"]}
    assert stages["discovery"] == "completed"
    assert stages["vulnerability_assessment"] == "completed"
    assert stages["web_and_tls"] == "completed"
    assert engine_current(detail) == "verification_scan"  # non-intrusive -> tail


async def test_workflow_targets_network_ranges_via_bound_scout(
    client: AsyncClient,
    admin_headers: dict[str, str],
    enroll_probe: EnrollFactory,
    db_session,
) -> None:
    import uuid as _uuid

    from app.models.scan_job import ScanJob

    # A scout bound to a network; no separate site scope. The workflow targets the
    # network, so the dispatched job must run on that scout over the network range.
    probe = await enroll_probe(site_code="NET", probe_name="net-scout")
    await client.post(f"/api/v1/probes/{probe['probe_id']}/approve", headers=admin_headers)
    net = (
        await client.post(
            "/api/v1/networks",
            json={
                "site_id": probe["site_id"],
                "name": "Targeted",
                "ranges": [{"cidr": "10.30.0.0/24"}],
                "scouts": [{"probe_id": probe["probe_id"], "is_primary": True}],
            },
            headers=admin_headers,
        )
    ).json()

    run_id = (
        await client.post(
            "/api/v1/workflows",
            json={"site_id": probe["site_id"], "network_id": net["id"]},
            headers=admin_headers,
        )
    ).json()["id"]
    started = await client.post(
        f"/api/v1/workflows/{run_id}/advance", json={"outcome": "completed"}, headers=admin_headers
    )
    job_id = started.json()["scan_job_id"]
    assert job_id is not None

    job = await db_session.get(ScanJob, _uuid.UUID(job_id))
    assert job.probe_id == _uuid.UUID(probe["probe_id"])
    assert job.requested_targets_json == ["10.30.0.0/24"]
    # First stage only: discovery (per-stage decomposition).
    assert [s["stage"] for s in job.workflow_json] == ["discovery"]


async def test_workflow_blocked_when_network_already_under_test(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    # A schedule puts an active job on the network; a workflow targeting the same
    # network must not start a second concurrent test.
    probe = await enroll_probe(site_code="LOCK", probe_name="lock")
    await client.post(f"/api/v1/probes/{probe['probe_id']}/approve", headers=admin_headers)
    net = (
        await client.post(
            "/api/v1/networks",
            json={
                "site_id": probe["site_id"],
                "name": "Locked",
                "ranges": [{"cidr": "10.40.0.0/24"}],
                "scouts": [{"probe_id": probe["probe_id"], "is_primary": True}],
            },
            headers=admin_headers,
        )
    ).json()
    sid = (
        await client.post(
            "/api/v1/schedules",
            json={"network_id": net["id"], "name": "S", "interval_minutes": 60},
            headers=admin_headers,
        )
    ).json()["id"]
    ran = await client.post(f"/api/v1/schedules/{sid}/run", headers=admin_headers)
    assert ran.status_code == 200

    run_id = (
        await client.post(
            "/api/v1/workflows",
            json={"site_id": probe["site_id"], "network_id": net["id"]},
            headers=admin_headers,
        )
    ).json()["id"]
    started = await client.post(
        f"/api/v1/workflows/{run_id}/advance", json={"outcome": "completed"}, headers=admin_headers
    )
    # Dispatch was blocked: no job linked, discovery failed with the lock reason.
    body = started.json()
    assert body["scan_job_id"] is None
    discovery = next(s for s in body["stages_json"] if s["name"] == "discovery")
    assert discovery["status"] == "failed"
    assert "under test" in (discovery["detail"] or "").lower()


async def test_workflow_scan_failure_skips_to_tail(
    client: AsyncClient, admin_headers: dict[str, str], enroll_probe: EnrollFactory
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe, site_code="WFF")
    run_id = (
        await client.post(
            "/api/v1/workflows", json={"site_id": probe["site_id"]}, headers=admin_headers
        )
    ).json()["id"]
    job_id = (
        await client.post(
            f"/api/v1/workflows/{run_id}/advance",
            json={"outcome": "completed"},
            headers=admin_headers,
        )
    ).json()["scan_job_id"]
    assert await _report_job(client, probe, job_id, "failed") == 204
    detail = (await client.get(f"/api/v1/workflows/{run_id}", headers=admin_headers)).json()
    stages = {s["name"]: s["status"] for s in detail["stages_json"]}
    assert stages["discovery"] == "failed"
    assert engine_current(detail) == "verification_scan"


async def test_workflow_api_deny_flow(
    client: AsyncClient,
    admin_headers: dict[str, str],
    make_user: UserFactory,
    enroll_probe: EnrollFactory,
) -> None:
    probe = await _ready_probe(client, admin_headers, enroll_probe, site_code="WFD")
    created = await client.post(
        "/api/v1/workflows",
        json={"site_id": probe["site_id"], "include_intrusive": True},
        headers=admin_headers,
    )
    assert created.status_code == 201, created.text
    run_id = created.json()["id"]

    operator = await make_user(UserRole.SECURITY_OPERATOR)
    op_headers = auth_headers(operator)

    # Advance precheck -> dispatch scan jobs -> probe completes each -> scanning done.
    started = await client.post(
        f"/api/v1/workflows/{run_id}/advance", json={"outcome": "completed"}, headers=op_headers
    )
    assert started.json()["scan_job_id"] is not None
    await _drive_scan_jobs(client, probe, run_id, op_headers)

    # Now at the (manual) validation-plan stage; advance it to reach the gate.
    r = await client.post(
        f"/api/v1/workflows/{run_id}/advance", json={"outcome": "completed"}, headers=op_headers
    )
    assert r.status_code == 200 and r.json()["status"] == "awaiting_approval"

    # Operator cannot approve; the approver denies.
    denied = await client.post(
        f"/api/v1/workflows/{run_id}/approval", json={"approve": True}, headers=op_headers
    )
    assert denied.status_code == 403
    approver = await make_user(UserRole.PENTEST_APPROVER)
    dec = await client.post(
        f"/api/v1/workflows/{run_id}/approval",
        json={"approve": False},
        headers=auth_headers(approver),
    )
    assert dec.status_code == 200

    # Finish verification + reporting.
    while True:
        cur = await client.get(f"/api/v1/workflows/{run_id}", headers=op_headers)
        if cur.json()["status"] in ("completed", "failed"):
            break
        await client.post(
            f"/api/v1/workflows/{run_id}/advance", json={"outcome": "completed"}, headers=op_headers
        )
    final = await client.get(f"/api/v1/workflows/{run_id}", headers=op_headers)
    stages = {s["name"]: s["status"] for s in final.json()["stages_json"]}
    assert final.json()["status"] == "completed"
    assert stages["allowlisted_validation"] == "skipped"
    assert stages["reporting"] == "completed"


def engine_current(detail: dict) -> str | None:
    """Name of the running/awaiting stage from a serialized run detail."""
    for s in detail["stages_json"]:
        if s["status"] in ("running", "awaiting_approval"):
            return s["name"]
    return None
