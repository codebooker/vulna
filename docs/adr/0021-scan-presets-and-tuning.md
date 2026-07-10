# ADR 0021: Opinionated Scan Presets and Automatic Tuning

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 21 (Opinionated Scan Presets and Automatic Tuning)

## Context

Phase 19 shipped one safe preset to get a first scan running. Self-hosters need a
small set of understandable *outcomes* — "quick look", "standard check", "safe for
fragile devices" — instead of scanner flags, while keeping every safety control
and never hiding intrusive behavior behind a friendly name.

## Decisions

### 1. A versioned preset registry, not scanner configuration

`app/services/presets.py` defines built-in presets (Quick Check, Standard Security
Check, Fragile / IoT Safe, Web and TLS Check, Deep Safe Check) plus a validated
Custom path. Each preset is a **version-pinned** selection of allowlisted stages
from a fixed catalogue, with an advisory rate/concurrency profile and a workload
class. Because reports and schedules can pin `(key, version)`, updating a built-in
preset is a new version the operator reviews and adopts — it never silently
changes an existing schedule or makes an old report irreproducible.

### 2. Presets are convenience over the same controls; intrusive is never hidden

A preset only chooses stages and advisory rates; it flows through the unchanged
signed-job and local-policy path. Every stage carries a safety classification, and
built-in presets contain **only** `passive`/`safe` stages. `intrusive` and
active-web stages are never part of a default preset and cannot be enabled by a
custom preset, so a friendly name can never smuggle intrusive behavior.

### 3. Capability manager + "why was this skipped?"

The Scout now reports its installed scanners (from self-test) and CPU count in the
heartbeat, so `GET /presets/capabilities` reports each known scanner as installed,
missing, unhealthy, or unsupported. `POST /presets/preview` resolves a preset
against a Scout's actual capabilities and returns exactly which stages will run
and, for each omission, a plain-language reason. A stage whose scanner is missing
is **blocked** unless the operator has explicitly approved downgrade — so a missing
scanner surfaces as a preflight result *before* the job begins, never as a silent
gap.

### 4. Hardware-aware tuning, hard-clamped to policy

`recommend_tuning` suggests concurrency/rate from the Scout's CPU (and memory when
reported), then **hard-clamps** to the `maximum_packets_per_second` and
`maximum_concurrency` carried in local Scout policy. Tuning can lower rates (e.g.
Fragile mode's conservative defaults) but can never exceed the signed policy
limits.

### 5. Custom presets are validated choices, never raw commands

`validate_custom` accepts a structured selection — a name, a subset of the
allowlisted stage keys, numeric rate/concurrency within bounds, and optional Nuclei
severities from a fixed set. By construction it cannot introduce arbitrary
executable paths, shell fragments, unrestricted Nmap scripts, or unreviewed Nuclei
template sets, and it rejects any attempt to set such raw fields. It can never
enable an active/intrusive stage.

### 6. Estimates as ranges, not false precision

`estimate` returns a workload class and a duration *range* bucketed by host count,
rather than a fabricated exact time.

## Security constraints (how they are met)

- **Convenience over signed controls** — presets choose stages/rates only; the
  signed job and local policy are unchanged (§2).
- **Intrusive stays off and unhidden** — built-ins are passive/safe only; custom
  cannot enable active/intrusive stages (§2, §5).
- **Classifications and verification retained** — stages keep their classification
  through resolution; scanner presence is reported, not silently assumed (§3).
- **Tuning ≤ policy** — recommendations are hard-clamped to policy maxima (§4).

## Consequences

- The standard preset runs on the reference deployment with no plugin-argument
  editing; onboarding now offers the full preset set from the same registry.
- Fragile mode enforces low rates and contains no active/intrusive stage.
- A missing scanner is a clear preflight result, not a silent skip.
- Expert users get validated custom presets without a raw-command foot-gun.

## Rollback / migration

Additive. The presets API and the Scout's richer heartbeat (capabilities +
cpu_count) do not change existing jobs; older Scouts that report no capabilities
simply show scanners as "missing" in the report. Onboarding's preset list is now
derived from the registry, so the wizard gains the additional presets with no
behavior change to the default path.

## Alternatives considered

- **Free-form custom command strings for experts.** Rejected: it reintroduces the
  arbitrary-exec / unrestricted-template risk the platform exists to avoid. Experts
  get validated structured choices instead.
- **Auto-downgrading silently when a scanner is missing.** Rejected as a default:
  silent gaps hide coverage loss. Downgrade is opt-in; otherwise the job is blocked
  with an explanation.
