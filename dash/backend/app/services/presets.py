"""Opinionated, versioned scan presets and automatic tuning (Phase 21).

Presets are a convenience layer over the *same* signed-job and local-policy
controls — they never introduce raw command strings, arbitrary executables, or
intrusive behavior. Built-in presets contain only passive/safe stages; intrusive
and active-web checks are never hidden inside a friendly preset name. All rate and
concurrency tuning is clamped to the hard limits carried in local Scout policy.

Everything here is pure and unit-testable: no database, no scanner invocation.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

# --------------------------------------------------------------------------- #
# Stage catalogue
# --------------------------------------------------------------------------- #

# Classification governs safety. Built-in presets only ever use "passive" or
# "safe" stages; "active"/"intrusive" exist for classification/validation but are
# never part of a default preset and cannot be enabled by a custom preset.
SAFE_CLASSES = ("passive", "safe")


@dataclass(frozen=True)
class StageSpec:
    """One workflow stage, the scanner it needs, and its safety classification."""

    key: str
    scanner: str
    classification: str
    label: str


STAGE_CATALOG: dict[str, StageSpec] = {
    "discovery": StageSpec("discovery", "nmap", "safe", "Host & port discovery"),
    "service_detection": StageSpec(
        "service_detection", "nmap", "safe", "Service/version detection"
    ),
    "vuln": StageSpec("vuln", "nuclei", "safe", "Non-intrusive vulnerability checks"),
    "tls": StageSpec("tls", "testssl", "safe", "TLS configuration review"),
    "web_passive": StageSpec("web_passive", "zap", "passive", "Passive web analysis"),
}

# Scanners the platform knows about (for the capability manager).
KNOWN_SCANNERS = ("nmap", "nuclei", "testssl", "zap")


@dataclass(frozen=True)
class RateProfile:
    """Advisory rate/concurrency for a preset. Always clamped to policy limits."""

    packets_per_second: int
    concurrency: int


@dataclass(frozen=True)
class Preset:
    """A versioned, opinionated scan preset."""

    key: str
    version: int
    name: str
    use_case: str
    description: str
    stage_keys: tuple[str, ...]
    rate: RateProfile
    workload_class: str  # light | moderate | heavy
    duration_class: str
    mode: str = "vulnerability_assessment"
    web_profile: str | None = None
    intrusive: bool = False
    active_web: bool = False
    uses_credentials: bool = False

    def stages(self) -> list[StageSpec]:
        return [STAGE_CATALOG[k] for k in self.stage_keys]


# --------------------------------------------------------------------------- #
# Built-in presets (versioned). Bump `version` when definitions change so pinned
# historical reports stay reproducible and schedules are not silently altered.
# --------------------------------------------------------------------------- #

BUILTIN_PRESETS: tuple[Preset, ...] = (
    Preset(
        key="quick",
        version=1,
        name="Quick Check",
        use_case="Frequent lightweight visibility",
        description="Discovery of common ports and basic service detection. Fast and light.",
        stage_keys=("discovery", "service_detection"),
        rate=RateProfile(packets_per_second=200, concurrency=4),
        workload_class="light",
        duration_class="a few minutes for a small subnet",
    ),
    Preset(
        key="standard",
        version=1,
        name="Standard Security Check",
        use_case="Default homelab and small-business scan",
        description=(
            "Discovery, broader service detection, non-intrusive vulnerability checks, "
            "and TLS review. No intrusive tests, active web attacks, or credentials."
        ),
        stage_keys=("discovery", "service_detection", "vuln", "tls"),
        rate=RateProfile(packets_per_second=150, concurrency=4),
        workload_class="moderate",
        duration_class="minutes to tens of minutes depending on host count",
    ),
    Preset(
        key="fragile",
        version=1,
        name="Fragile / IoT Safe",
        use_case="Printers, cameras, appliances, embedded devices",
        description=(
            "Conservative discovery and connection rates for delicate devices. "
            "No active web attack and no intrusive checks."
        ),
        stage_keys=("discovery", "service_detection"),
        rate=RateProfile(packets_per_second=20, concurrency=1),
        workload_class="light",
        duration_class="slower by design; conservative rates",
    ),
    Preset(
        key="web_tls",
        version=1,
        name="Web and TLS Check",
        use_case="Known websites and internal applications",
        description="Scoped passive web analysis and TLS configuration review.",
        stage_keys=("web_passive", "tls"),
        rate=RateProfile(packets_per_second=100, concurrency=2),
        workload_class="moderate",
        duration_class="minutes per application",
        web_profile="passive_baseline",
    ),
    Preset(
        key="deep_safe",
        version=1,
        name="Deep Safe Check",
        use_case="Planned maintenance window",
        description=(
            "Broader safe coverage across discovery, services, vulnerabilities, TLS, and "
            "passive web. Longer, but still no exploitation."
        ),
        stage_keys=("discovery", "service_detection", "vuln", "tls", "web_passive"),
        rate=RateProfile(packets_per_second=150, concurrency=6),
        workload_class="heavy",
        duration_class="tens of minutes to hours for large scopes",
        web_profile="passive_baseline",
    ),
)

# Version 2 makes the advertised tuning executable. The v1 definitions remain
# available for pinned historical schedules/reports; new jobs resolve the latest
# version. LAN-oriented presets use the existing signed 1,000 pps ceiling, while
# the fragile profile remains deliberately conservative.
BUILTIN_PRESETS += (
    replace(
        BUILTIN_PRESETS[0],
        version=2,
        rate=RateProfile(packets_per_second=1000, concurrency=8),
    ),
    replace(
        BUILTIN_PRESETS[1],
        version=2,
        stage_keys=("discovery", "service_detection", "vuln", "tls", "web_passive"),
        rate=RateProfile(packets_per_second=1000, concurrency=8),
    ),
    replace(
        BUILTIN_PRESETS[2],
        version=2,
        rate=RateProfile(packets_per_second=50, concurrency=1),
    ),
    replace(
        BUILTIN_PRESETS[3],
        version=2,
        rate=RateProfile(packets_per_second=500, concurrency=4),
    ),
    replace(
        BUILTIN_PRESETS[4],
        version=2,
        rate=RateProfile(packets_per_second=1000, concurrency=8),
    ),
)


class PresetError(ValueError):
    """Raised when a preset lookup or custom-preset validation fails."""


def list_presets() -> list[Preset]:
    """Return the latest version of each built-in preset."""
    latest: dict[str, Preset] = {}
    for p in BUILTIN_PRESETS:
        cur = latest.get(p.key)
        if cur is None or p.version > cur.version:
            latest[p.key] = p
    return list(latest.values())


def get_preset(key: str, version: int | None = None) -> Preset:
    """Return a preset by key, optionally pinned to a specific version."""
    candidates = [p for p in BUILTIN_PRESETS if p.key == key]
    if version is not None:
        candidates = [p for p in candidates if p.version == version]
    if not candidates:
        raise PresetError(f"Unknown preset '{key}'" + (f" v{version}" if version else ""))
    return max(candidates, key=lambda p: p.version)


# --------------------------------------------------------------------------- #
# Stage resolution + "why was this skipped?"
# --------------------------------------------------------------------------- #


@dataclass
class SkippedStage:
    stage: str
    scanner: str
    reason: str


@dataclass
class Resolution:
    run: list[StageSpec] = field(default_factory=list)
    skipped: list[SkippedStage] = field(default_factory=list)
    blocked: bool = False  # True when a required scanner is missing and downgrade is off


def resolve_stages(preset: Preset, available: set[str], *, allow_downgrade: bool) -> Resolution:
    """Decide which stages run given the installed scanners.

    A stage whose scanner is unavailable is skipped with a plain-language reason.
    Skipping only *proceeds* when the operator has approved downgrade; otherwise
    the job is ``blocked`` so a missing scanner surfaces as a preflight result
    before the job begins (never a silent omission).
    """
    res = Resolution()
    for spec in preset.stages():
        if spec.scanner in available:
            res.run.append(spec)
        else:
            res.skipped.append(
                SkippedStage(
                    stage=spec.key,
                    scanner=spec.scanner,
                    reason=(
                        f"The '{spec.label}' stage needs the {spec.scanner} scanner, "
                        f"which is not installed on this Scout."
                    ),
                )
            )
    if res.skipped and not allow_downgrade:
        res.blocked = True
    return res


# --------------------------------------------------------------------------- #
# Estimates (ranges / workload classes, never false precision)
# --------------------------------------------------------------------------- #


def estimate(preset: Preset, host_count: int) -> dict[str, str]:
    """Return a coarse workload/duration estimate as ranges, not exact numbers."""
    if host_count <= 16:
        size = "small"
    elif host_count <= 256:
        size = "medium"
    else:
        size = "large"
    duration = {
        ("light", "small"): "under a minute",
        ("light", "medium"): "a few minutes",
        ("light", "large"): "several minutes",
        ("moderate", "small"): "a few minutes",
        ("moderate", "medium"): "several to tens of minutes",
        ("moderate", "large"): "tens of minutes or more",
        ("heavy", "small"): "several minutes",
        ("heavy", "medium"): "tens of minutes",
        ("heavy", "large"): "up to a few hours",
    }.get((preset.workload_class, size), "varies")
    return {
        "workload_class": preset.workload_class,
        "size_class": size,
        "duration_range": duration,
    }


# --------------------------------------------------------------------------- #
# Hardware-aware tuning (always clamped to policy hard limits)
# --------------------------------------------------------------------------- #


def recommend_tuning(
    preset: Preset,
    *,
    cpu_count: int,
    memory_bytes: int,
    max_pps: int | None,
    max_concurrency: int | None,
) -> RateProfile:
    """Recommend a rate profile from host resources, never exceeding policy limits.

    The recommendation starts from the preset's advisory rate and adjusts down for
    small hosts, then is hard-clamped to the local-policy maxima so tuning can
    never exceed what the signed scope permits.
    """
    concurrency = preset.rate.concurrency
    if cpu_count >= 1:
        concurrency = min(concurrency, max(1, cpu_count))
    if memory_bytes and memory_bytes < (2 << 30):  # < 2 GiB: be gentle
        concurrency = min(concurrency, 2)

    pps = preset.rate.packets_per_second

    # Hard clamp to policy limits (authoritative).
    if max_concurrency is not None:
        concurrency = min(concurrency, max_concurrency)
    if max_pps is not None:
        pps = min(pps, max_pps)
    return RateProfile(packets_per_second=max(1, pps), concurrency=max(1, concurrency))


# --------------------------------------------------------------------------- #
# Custom presets: validated choices, never raw commands
# --------------------------------------------------------------------------- #

# Advisory bounds for custom rate/concurrency (still additionally clamped to
# policy at run time).
CUSTOM_MAX_PPS = 1000
CUSTOM_MAX_CONCURRENCY = 16
ALLOWED_SEVERITIES = ("info", "low", "medium", "high", "critical")


def validate_custom(spec: dict[str, object]) -> Preset:
    """Validate an expert custom preset built from *validated choices only*.

    A custom preset is a structured selection — a name, a subset of the allowlisted
    stage keys, numeric rate/concurrency within bounds, and optional Nuclei
    severities from a fixed set. It can therefore never introduce arbitrary
    executable paths, shell fragments, unrestricted Nmap scripts, or unreviewed
    Nuclei template sets, and it can never enable an active/intrusive stage.
    Raises :class:`PresetError` on any violation.
    """
    name = spec.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 80:
        raise PresetError("Custom preset needs a name (1–80 characters).")

    raw_stages = spec.get("stage_keys")
    if not isinstance(raw_stages, list) or not raw_stages:
        raise PresetError("Select at least one stage.")
    stage_keys: list[str] = []
    for key in raw_stages:
        if key not in STAGE_CATALOG:
            raise PresetError(f"Unknown stage '{key}'. Choose from the stage catalogue.")
        spec_stage = STAGE_CATALOG[str(key)]
        if spec_stage.classification not in SAFE_CLASSES:
            raise PresetError(
                f"Stage '{key}' is {spec_stage.classification} and cannot be enabled "
                "in a custom preset."
            )
        stage_keys.append(str(key))

    pps = _bounded_int(spec.get("packets_per_second", 100), 1, CUSTOM_MAX_PPS, "packets_per_second")
    concurrency = _bounded_int(spec.get("concurrency", 2), 1, CUSTOM_MAX_CONCURRENCY, "concurrency")

    severities = spec.get("severities", list(ALLOWED_SEVERITIES))
    if not isinstance(severities, list) or any(s not in ALLOWED_SEVERITIES for s in severities):
        raise PresetError(f"Severities must be a subset of {list(ALLOWED_SEVERITIES)}.")

    # Reject any attempt to smuggle raw commands / scripts / template paths.
    forbidden = {"command", "args", "script", "scripts", "templates", "template", "exec", "shell"}
    present = forbidden.intersection(spec.keys())
    if present:
        raise PresetError(
            f"Custom presets cannot set raw {sorted(present)}; only validated choices are allowed."
        )

    return Preset(
        key="custom",
        version=1,
        name=name.strip(),
        use_case="Expert custom preset",
        description="Validated custom selection of safe stages.",
        stage_keys=tuple(stage_keys),
        rate=RateProfile(packets_per_second=pps, concurrency=concurrency),
        workload_class="moderate",
        duration_class="depends on selected stages and host count",
    )


def _bounded_int(value: object, lo: int, hi: int, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PresetError(f"{name} must be an integer.")
    if value < lo or value > hi:
        raise PresetError(f"{name} must be between {lo} and {hi}.")
    return value
