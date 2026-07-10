# ADR 0013: Full-Spectrum Workflow

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 12 (Full-Spectrum workflow)

## Context

The earlier phases each deliver a capability (discovery, assessment, CVE
intelligence, web scanning, remediation, controlled validation, reporting). A
full-spectrum assessment chains them into one run with an approval pause for the
intrusive part and guarantees that cleanup, verification, and reporting always
happen — even when the intrusive stage is denied or a stage fails (build plan
§13.3). Phase 12 adds the engine that orchestrates that.

## Decisions

### 1. A deterministic, externally-driven state machine

The engine owns *ordering and transitions*; it does not execute stages. A caller
advances the run as each stage completes, fails, or is decided. This keeps the
long-running, asynchronous work (probe scans, validation, report rendering) where
it already lives and makes the workflow itself a small, fully unit-testable state
machine — no background orchestration, timers, or hidden execution in the engine.

### 2. Conditional stages and a guaranteed tail

Stages carry an applicability rule evaluated against the run's flags: web/TLS runs
only when requested; candidate-validation and the approval gate run only for an
intrusive run; validation/evidence/cleanup run only once the intrusive stage is
approved. The tail — cleanup (when a validation ran), the verification scan, and
reporting — always runs when applicable. Denial at the gate and failure of any
stage both route straight to the tail rather than aborting, which is exactly the
"reports still generate" / "cleanup and verification always run" requirement.

### 3. Denial and failure are first-class, not errors

Denying the intrusive stage sets the gate to `denied`, skips the validation
stages, and continues to verification/reporting — the run still `completed`. A
failed stage is recorded `failed`, the remaining non-tail stages are skipped, the
tail runs, and the run finishes `failed` so the failure is visible without losing
the cleanup/verification/report. Both are ordinary transitions, so the trail
(`stages_json`) is an accurate, audited record of what happened.

### 4. In-place JSON mutation must be flagged

Stage state lives in a JSON column. SQLAlchemy does not detect in-place mutation
of a JSON/dict structure across a commit, so the API flags the column modified
after each engine call. Without this, stage progress would silently fail to
persist between requests (caught by the API end-to-end test, not the in-memory
unit tests). Recorded here because it is a subtle, easy-to-reintroduce trap.

## Consequences

- A full assessment is one auditable run with a clear stage trail and an explicit
  approval pause.
- The same engine underlies both a fully-automated safe run (no intrusive) and an
  approval-gated intrusive run.
- Adding or reordering stages is a change to one ordered list plus applicability
  rules.

## Alternatives considered

- **A background job engine that executes stages itself:** rejected for now; it
  would duplicate the probe's async execution and couple the workflow to a
  scheduler. An externally-driven machine is simpler and testable, and a scheduler
  can drive it later without changing the transitions.
- **Aborting the run on failure:** rejected; it would violate the requirement that
  cleanup and verification always run, and would discard the report.
- **Tracking stage state in normalized rows instead of JSON:** deferred; the JSON
  trail is sufficient and simple, with the mutation-flagging caveat documented.
