"""Prometheus metrics exposition for VulnaDash (VulnaPulse).

Only **aggregate, non-sensitive** metrics are exposed. Labels are limited to enum
values (severity, status, feed source) and opaque UUIDs (probe id) — never a
finding title, description, evidence, IP address, or other sensitive content.
This is a hard requirement: the metrics endpoint is a data-exfiltration surface,
so no per-finding detail is ever placed in a label or value.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.core.config import Settings
from app.models.background_task import BackgroundTask, WorkerHeartbeat
from app.models.feed_health import FeedHealth
from app.models.finding import Finding
from app.models.pentest_session import PentestSession
from app.models.probe import Probe
from app.models.report import Report
from app.models.scan_job import ScanJob
from app.models.workflow_run import WorkflowRun

_OK_FEED_STATES = {"ok", "degraded"}


def _timestamp(value: datetime) -> float:
    return (value if value.tzinfo is not None else value.replace(tzinfo=UTC)).timestamp()


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


class _Writer:
    def __init__(self) -> None:
        self._lines: list[str] = []
        self._declared: set[str] = set()

    def metric(
        self,
        name: str,
        help_text: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        if name not in self._declared:
            self._lines.append(f"# HELP {name} {help_text}")
            self._lines.append(f"# TYPE {name} gauge")
            self._declared.add(name)
        if labels:
            rendered = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())
            self._lines.append(f"{name}{{{rendered}}} {value:g}")
        else:
            self._lines.append(f"{name} {value:g}")

    def render(self) -> str:
        return "\n".join(self._lines) + "\n"


async def _grouped(session: AsyncSession, column: Any) -> dict[str, int]:
    result = await session.execute(select(column, func.count()).group_by(column))
    return {str(getattr(k, "value", k)): n for k, n in result.all()}


async def render_metrics(session: AsyncSession, settings: Settings, now: datetime) -> str:
    """Render current metrics in Prometheus text exposition format."""
    w = _Writer()
    w.metric("vulna_build_info", "Build information.", 1, {"version": __version__})

    for sev, n in (await _grouped(session, Finding.severity)).items():
        w.metric("vulna_findings_by_severity", "Findings by severity.", n, {"severity": sev})
    for st, n in (await _grouped(session, Finding.status)).items():
        w.metric("vulna_findings_by_status", "Findings by workflow status.", n, {"status": st})
    kev = await session.scalar(
        select(func.count()).select_from(Finding).where(Finding.known_exploited.is_(True))
    )
    w.metric("vulna_findings_known_exploited", "Known-exploited findings.", kev or 0)

    for st, n in (await _grouped(session, Probe.status)).items():
        w.metric("vulna_probes_by_status", "Probes by lifecycle status.", n, {"status": st})
    for st, n in (await _grouped(session, ScanJob.status)).items():
        w.metric("vulna_scan_jobs_by_status", "Scan jobs by status.", n, {"status": st})
    for st, n in (await _grouped(session, PentestSession.status)).items():
        w.metric("vulna_pentest_sessions_by_status", "Pentest sessions.", n, {"status": st})
    for st, n in (await _grouped(session, WorkflowRun.status)).items():
        w.metric("vulna_workflow_runs_by_status", "Workflow runs.", n, {"status": st})
    reports = await session.scalar(select(func.count()).select_from(Report))
    w.metric("vulna_reports_total", "Reports generated.", reports or 0)
    for task_status, n in (await _grouped(session, BackgroundTask.status)).items():
        w.metric(
            "vulna_background_tasks_by_status",
            "Durable background tasks by lifecycle status.",
            n,
            {"status": task_status},
        )
    heartbeat_cutoff = now.timestamp() - max(60, settings.background_task_lease_seconds * 2)
    heartbeats = list((await session.execute(select(WorkerHeartbeat))).scalars())
    for kind in {heartbeat.kind for heartbeat in heartbeats}:
        alive = sum(
            1
            for heartbeat in heartbeats
            if heartbeat.kind == kind and _timestamp(heartbeat.last_seen_at) >= heartbeat_cutoff
        )
        w.metric(
            "vulna_background_processes_up",
            "Scheduler/worker processes seen within five minutes.",
            alive,
            {"kind": kind},
        )

    # Per-probe liveness/heartbeat (probe id is an opaque UUID, not sensitive).
    offline = settings.probe_offline_after_seconds
    online = 0
    for p in (await session.execute(select(Probe))).scalars().all():
        if p.last_seen_at is None:
            continue
        ts = p.last_seen_at.timestamp()
        up = 1 if (now.timestamp() - ts) <= offline else 0
        online += up
        labels = {"probe_id": str(p.id)}
        w.metric(
            "vulna_probe_last_heartbeat_timestamp_seconds",
            "Unix time of a probe's last heartbeat.",
            ts,
            labels,
        )
        w.metric("vulna_probe_up", "1 if the probe is online.", up, labels)
    w.metric("vulna_probes_online", "Probes currently online.", online)

    # Feed freshness — drives the stale-feed alert rule.
    for fh in (await session.execute(select(FeedHealth))).scalars().all():
        src = {"source": fh.source.value}
        up = 1 if fh.status.value in _OK_FEED_STATES else 0
        w.metric("vulna_feed_up", "1 if the last feed sync succeeded.", up, src)
        if fh.last_success_at is not None:
            w.metric(
                "vulna_feed_last_success_timestamp_seconds",
                "Unix time of a feed's last successful sync.",
                fh.last_success_at.timestamp(),
                src,
            )
        w.metric(
            "vulna_feed_records_processed", "Records in the last sync.", fh.records_processed, src
        )

    return w.render()
