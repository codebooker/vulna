# ADR 0027: Low-Resource, ARM64, Intermittent, and Offline-Friendly Operation

- **Status:** Accepted
- **Date:** 2026-07-11
- **Phase:** 27 (Low-Resource, ARM64, Intermittent, and Offline-Friendly Operation)

## Context

Vulna targets homelabs and small sites: a Raspberry Pi in a closet, an old
desktop, a VM with 2 GB of RAM, a remote site on a flaky LTE link. The platform
has to stay useful there without weakening the safety model. This phase adds a
resource-aware operating profile, fail-closed backpressure, a durable result
queue for intermittent links, and signed offline bundles for air-gapped sites.

## Decisions

### 1. A resource-aware operating profile (Lite / Standard / Full)

`app/services/resources.py` turns a Scout's measured resources (reported in its
heartbeat) into a plan: an operating profile selected by memory (the dominant
limit for the scanners Vulna drives), a dynamic concurrency and queue limit,
one-heavy-stage-at-a-time on constrained hosts, per-stage hard budgets, and the
set of expensive components disabled under **Lite** (active ZAP, local full-text
indexing, large report rendering, high-frequency feed re-matching). Concurrency is
still **clamped to the signed local-policy limits** — the profile only ever
restricts work; it never raises a limit or enables a stage. The Scout reports
CPU, memory, and free/total disk via a stdlib-only, build-tagged probe
(`scout/internal/telemetry`, real figures on Linux, "unknown" elsewhere).

### 2. Backpressure fails closed

`resources.admit` is the admission gate. It stops heavy work **before** the data
volume is dangerously full (pausing at low disk, refusing at critical disk to
protect evidence and the database), and pauses on a full queue or a large
ingestion backlog. Every non-accepting decision names the component, the impact,
and the next step. Intrusive or scope-sensitive stages **fail closed**: they are
refused whenever any resource pressure is present, so a strained host never runs
riskier work.

### 3. A durable result queue for intermittent links

`scout/internal/queue` is an on-disk, owner-only queue of finished result
batches. When the WAN link is down the Scout keeps accepted work locally
(surviving a crash via write-then-rename) and drains it when connectivity
returns. A byte cap provides backpressure rather than filling the disk, and the
backlog count and size are reported in the heartbeat.

### 4. Resumable uploads are idempotent

Each result batch carries a **content-derived idempotency key**
(`sha256(job|stage|scanner|payload)`) sent as `Idempotency-Key`. The server
records processed keys per job (`probe_result_uploads`) and treats a repeat as a
no-op. So a Scout that re-uploads a batch after a lost acknowledgement never
produces a duplicate observation on resume.

### 5. Signed, data-only offline bundles

`app/services/offline_bundle.py` verifies and imports offline intelligence/update
bundles for air-gapped sites. A bundle is a signed manifest (the same Ed25519
canonical-document scheme as jobs and policy) whose `kind` must be on a
**data-only allowlist** (`intel`, `feeds`, `templates`, `update`). Import **fails
closed** on a bad signature and refuses any non-data kind, so a bundle can never
side-load an executable or plugin. Inspect surfaces creation time, feed age, and
content versions before import; import is admin-only and audited, which is the
source of the import history.

## Security constraints (how they are met)

- **Fail closed under pressure** — intrusive/scope-sensitive stages are refused
  under any resource pressure; heavy work stops before storage risk.
- **No safety bypass** — the resource layer only restricts admission and
  scheduling. Target checks, signature verification, cancellation, scope, and
  evidence integrity are untouched; rate/concurrency stays clamped to signed
  policy.
- **Offline import is data-only** — allowlisted kinds, signature required, never
  an executable or plugin side-loading path.
- **Temporary data** — the durable queue is owner-only (0700 dir, 0600 files)
  under the Scout state directory, following normal permission/cleanup rules.

## Consequences

- A Pi-class Scout runs a documented Lite assessment without being pushed into
  out-of-memory territory, and the UI warns before a heavy preset is run on it.
- A site on an intermittent link loses no accepted work and never double-reports
  after reconnecting.
- An air-gapped site can import fresh, signature-verified intelligence without a
  new remote-code path.

## Rollback / migration

One additive table (`probe_result_uploads`) for upload idempotency; everything
else is new pure logic, a new Scout package, and display/admin endpoints. No
existing behavior changes when a Scout does not report resources or supply an
idempotency key.

## Alternatives considered

- **A single global concurrency knob.** Rejected: it cannot express per-stage
  budgets, one-heavy-at-a-time, or fail-closed storage behavior.
- **Unsigned offline import (drop a file in a directory).** Rejected by the
  security constraint: import must be signature-verified and data-only.
- **Best-effort re-upload without idempotency.** Rejected: reconnection would
  risk duplicate observations; content-keyed idempotency makes resume exactly
  once.
