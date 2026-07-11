"""Low-resource operating profiles, dynamic budgets, and fail-closed backpressure
(Phase 27).

Vulna runs on homelab hardware: a Raspberry Pi, an old desktop, a small VM. This
module decides *how much work* such a host may take on, and *when to stop taking
more*, from measured resources. It is a convenience/safety layer over the same
signed-job and local-policy controls — it only ever restricts work; it never
enables an intrusive stage, relaxes a scope, or bypasses a signature.

Everything here is pure and unit-testable: no database, no scanner invocation and
no host probing. Callers pass in measurements (from the Scout heartbeat) and the
authoritative policy limits, and get back a plan or an admission decision.

Two ideas:

* :func:`plan` turns measured resources into a :class:`ResourcePlan` — an
  operating profile, dynamic concurrency/queue limits (always clamped to policy),
  one-heavy-stage-at-a-time on constrained hosts, per-stage hard budgets, and the
  set of expensive components disabled under the Lite profile.
* :func:`admit` is the backpressure gate. Given current pressure (disk, queue,
  ingestion backlog) it returns accept / pause / reject with a named reason. It
  **fails closed**: intrusive or scope-sensitive stages are refused under any
  pressure, and heavy work stops before storage pressure risks evidence or
  database integrity.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Operating profiles
# --------------------------------------------------------------------------- #

LITE = "lite"
STANDARD = "standard"
FULL = "full"

# Reference tiers (documented in docs/low-resource.md). Memory is the dominant
# constraint for the scanners Vulna drives, so it selects the profile; CPU and
# disk further tighten the plan.
LITE_MAX_MEMORY_MB = 2048  # <= 2 GiB total RAM -> Lite
STANDARD_MAX_MEMORY_MB = 6144  # <= 6 GiB -> Standard; above -> Full

# Storage pressure thresholds (percent of the data volume still free). Heavy work
# pauses before the volume is dangerously full and stops entirely before there is
# any risk to evidence files or the database.
DISK_PAUSE_FREE_PCT = 10.0
DISK_REJECT_FREE_PCT = 5.0

# Ingestion backlog (results uploaded but not yet processed) above which we stop
# admitting new heavy jobs so the dashboard can catch up.
BACKLOG_PAUSE = 50


@dataclass(frozen=True)
class HostResources:
    """Measured resources for the host running a Scout (from its heartbeat)."""

    cpu_count: int
    memory_mb: int
    disk_free_mb: int
    disk_total_mb: int

    @property
    def disk_free_pct(self) -> float:
        if self.disk_total_mb <= 0:
            return 100.0
        return round(100.0 * self.disk_free_mb / self.disk_total_mb, 1)


def host_resources_from_health(health: dict[str, object] | None) -> HostResources:
    """Build :class:`HostResources` from a Scout's reported heartbeat health.

    Missing fields default to 0 (treated as "unknown" by the planner), so an older
    Scout that only reports ``cpu_count`` still yields a usable, conservative plan.
    """
    h = health or {}

    def _int(key: str) -> int:
        v = h.get(key)
        return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0

    return HostResources(
        cpu_count=max(1, _int("cpu_count")),
        memory_mb=_int("memory_mb"),
        disk_free_mb=_int("disk_free_mb"),
        disk_total_mb=_int("disk_total_mb"),
    )


def choose_profile(res: HostResources) -> str:
    """Pick the operating profile from measured memory (the dominant limit)."""
    mem = res.memory_mb if res.memory_mb > 0 else STANDARD_MAX_MEMORY_MB
    if mem <= LITE_MAX_MEMORY_MB:
        return LITE
    if mem <= STANDARD_MAX_MEMORY_MB:
        return STANDARD
    return FULL


# Expensive components switched off under Lite. These are conveniences, never
# safety controls: turning them off never enables intrusive behaviour.
EXPENSIVE_COMPONENTS: tuple[tuple[str, str], ...] = (
    ("active_web_zap", "Active ZAP web testing (passive review still runs)"),
    ("local_fulltext_index", "Local full-text search indexing"),
    ("large_report_render", "Large PDF report rendering (CSV/JSON still available)"),
    ("high_frequency_feed_matching", "High-frequency CVE feed re-matching"),
)


@dataclass(frozen=True)
class DisabledComponent:
    component: str
    reason: str


@dataclass(frozen=True)
class StageBudget:
    """Hard per-stage limits. A stage exceeding any of these is stopped."""

    stage: str
    max_wall_seconds: int
    max_memory_mb: int
    max_targets: int


# Base budgets for the Full profile; scaled down for Standard/Lite.
_BASE_STAGE_BUDGETS: dict[str, StageBudget] = {
    "discovery": StageBudget("discovery", 1800, 512, 4096),
    "service_detection": StageBudget("service_detection", 2400, 512, 4096),
    "vuln": StageBudget("vuln", 3600, 1024, 2048),
    "tls": StageBudget("tls", 1800, 512, 1024),
    "web_passive": StageBudget("web_passive", 3600, 1024, 256),
}

_PROFILE_SCALE: dict[str, float] = {LITE: 0.4, STANDARD: 0.7, FULL: 1.0}


def _scaled_budgets(profile: str) -> dict[str, StageBudget]:
    scale = _PROFILE_SCALE[profile]
    out: dict[str, StageBudget] = {}
    for key, b in _BASE_STAGE_BUDGETS.items():
        out[key] = StageBudget(
            stage=b.stage,
            max_wall_seconds=max(60, int(b.max_wall_seconds * scale)),
            max_memory_mb=max(128, int(b.max_memory_mb * scale)),
            max_targets=max(16, int(b.max_targets * scale)),
        )
    return out


@dataclass
class ResourcePlan:
    profile: str
    max_concurrency: int
    queue_depth: int
    one_heavy_stage_at_a_time: bool
    disabled: list[DisabledComponent] = field(default_factory=list)
    stage_budgets: dict[str, StageBudget] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def plan(
    res: HostResources,
    *,
    max_pps: int | None = None,
    max_concurrency: int | None = None,
) -> ResourcePlan:
    """Turn measured resources into an operating plan, clamped to policy limits.

    ``max_concurrency``/``max_pps`` are the authoritative local-policy hard limits;
    the returned plan never exceeds them.
    """
    profile = choose_profile(res)

    # Concurrency tracks CPU but stays modest on small hosts; Lite is capped hard.
    concurrency = max(1, res.cpu_count)
    if profile == LITE:
        concurrency = min(concurrency, 2)
    elif profile == STANDARD:
        concurrency = min(concurrency, 4)
    else:
        concurrency = min(concurrency, 8)
    if max_concurrency is not None:  # policy is authoritative
        concurrency = min(concurrency, max_concurrency)
    concurrency = max(1, concurrency)

    # Queue depth scales with memory so a small host cannot accumulate a backlog
    # it can never work through.
    mem = res.memory_mb if res.memory_mb > 0 else STANDARD_MAX_MEMORY_MB
    queue_depth = max(2, min(64, mem // 256))

    one_heavy = profile == LITE or res.cpu_count <= 2

    disabled: list[DisabledComponent] = []
    notes: list[str] = []
    if profile == LITE:
        disabled = [DisabledComponent(c, r) for c, r in EXPENSIVE_COMPONENTS]
        notes.append(
            "Lite profile: heavy stages run one at a time and expensive components "
            "are disabled to fit modest hardware."
        )
    if one_heavy and profile != LITE:
        notes.append("Constrained CPU: heavy stages run one at a time.")

    return ResourcePlan(
        profile=profile,
        max_concurrency=concurrency,
        queue_depth=queue_depth,
        one_heavy_stage_at_a_time=one_heavy,
        disabled=disabled,
        stage_budgets=_scaled_budgets(profile),
        notes=notes,
    )


# --------------------------------------------------------------------------- #
# Capability warning (Phase 27 acceptance: UI warns when a preset exceeds the
# Scout's recommended capability).
# --------------------------------------------------------------------------- #


@dataclass
class CapabilityWarning:
    exceeds: bool
    message: str


def capability_warning(
    res: HostResources, *, workload_class: str
) -> CapabilityWarning | None:
    """Warn (without blocking) when a preset's workload exceeds this host's tier.

    Advisory only: the operator can still run it. Returns ``None`` when the
    workload comfortably fits.
    """
    profile = choose_profile(res)
    if workload_class == "heavy" and profile == LITE:
        return CapabilityWarning(
            exceeds=True,
            message=(
                "This is a heavy preset and the Scout is on Lite-tier hardware. "
                "It will run one stage at a time and may take much longer; consider "
                "a lighter preset or a maintenance window."
            ),
        )
    if workload_class == "heavy" and res.cpu_count <= 2:
        return CapabilityWarning(
            exceeds=True,
            message=(
                "This is a heavy preset and the Scout has few CPU cores. Expect long "
                "run times; heavy stages are serialized to protect the host."
            ),
        )
    return None


# --------------------------------------------------------------------------- #
# Backpressure / admission — fail closed
# --------------------------------------------------------------------------- #


ACCEPT = "accept"
PAUSE = "pause"
REJECT = "reject"


@dataclass
class AdmissionDecision:
    action: str  # accept | pause | reject
    reason: str
    component: str
    impact: str
    next_step: str

    @property
    def admitted(self) -> bool:
        return self.action == ACCEPT


@dataclass(frozen=True)
class SystemPressure:
    disk_free_pct: float
    queue_depth: int
    queue_max: int
    ingestion_backlog: int


def _pressured(p: SystemPressure) -> bool:
    return (
        p.disk_free_pct < DISK_PAUSE_FREE_PCT
        or p.queue_depth >= p.queue_max
        or p.ingestion_backlog >= BACKLOG_PAUSE
    )


def admit(
    pressure: SystemPressure,
    *,
    intrusive: bool = False,
    heavy: bool = False,
) -> AdmissionDecision:
    """Decide whether to admit a new job, failing closed under pressure.

    Rules, in priority order:

    1. **Intrusive / scope-sensitive** stages fail closed: refused whenever *any*
       resource pressure is present, so a strained host never runs riskier work.
    2. **Storage** below the reject threshold refuses new heavy work entirely,
       protecting evidence files and the database from a full volume.
    3. **Storage** below the pause threshold, a full queue, or a large ingestion
       backlog pauses new heavy work until the host recovers.

    A pausing/rejecting decision always names the component, the impact, and the
    next step, so a stalled queue is never a mystery.
    """
    if intrusive and _pressured(pressure):
        return AdmissionDecision(
            action=REJECT,
            reason="intrusive_under_pressure",
            component="scheduler",
            impact=(
                "Intrusive or scope-sensitive stages are not run while the host is "
                "under resource pressure."
            ),
            next_step="Free disk, let the queue drain, then retry the intrusive job.",
        )

    if pressure.disk_free_pct < DISK_REJECT_FREE_PCT:
        return AdmissionDecision(
            action=REJECT,
            reason="storage_critical",
            component="storage",
            impact=(
                f"Only {pressure.disk_free_pct:.1f}% disk free; new heavy jobs are "
                "refused to protect evidence and the database from a full volume."
            ),
            next_step=(
                "Free disk space (prune old reports/evidence) or expand the volume, then retry."
            ),
        )

    if pressure.disk_free_pct < DISK_PAUSE_FREE_PCT:
        return AdmissionDecision(
            action=PAUSE,
            reason="storage_low",
            component="storage",
            impact=f"Disk is low ({pressure.disk_free_pct:.1f}% free); heavy jobs are paused.",
            next_step=(
                "Free some disk space; queued work resumes automatically once above the threshold."
            ),
        )

    if pressure.queue_depth >= pressure.queue_max:
        return AdmissionDecision(
            action=PAUSE,
            reason="queue_full",
            component="scheduler",
            impact=f"The Scout queue is full ({pressure.queue_depth}/{pressure.queue_max}).",
            next_step="Wait for running jobs to finish; new jobs are admitted as slots free up.",
        )

    if pressure.ingestion_backlog >= BACKLOG_PAUSE:
        return AdmissionDecision(
            action=PAUSE,
            reason="ingestion_backlog",
            component="ingestion",
            impact=(
                f"{pressure.ingestion_backlog} result batches are still being processed; "
                "new heavy jobs are paused so the dashboard can catch up."
            ),
            next_step="No action needed; admission resumes as the backlog clears.",
        )

    return AdmissionDecision(
        action=ACCEPT,
        reason="ok",
        component="scheduler",
        impact="",
        next_step="",
    )
