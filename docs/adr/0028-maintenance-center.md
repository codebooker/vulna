# ADR 0028: Unified Maintenance Center

- **Status:** Accepted
- **Date:** 2026-07-11
- **Phase:** 28 (Unified Maintenance Center)

## Context

A self-hoster needs one place to answer "does Vulna need attention?" — across
updates, Scouts, scanners, feeds, backups, certificates, storage, retention,
failed schedules, stuck jobs, report failures, and plugin health. They also need
to reclaim disk space over time without accidentally destroying evidence or
report snapshots. This phase adds a maintenance overview, storage budgets, a
fail-closed retention/cleanup workflow, certificate-rotation preflight, and a
self-hosting health report.

## Decisions

### 1. The overview aggregates diagnostics, it does not duplicate them

`app/services/maintenance.py` reuses the Phase 26 `run_diagnostics` results (so the
Maintenance and System Health views never disagree) and maps each to a **green /
warning / action-required** state, then adds the two maintenance-specific signals:
**stuck jobs** (running far longer than expected) and **reclaimable storage**.
Every non-green item carries a specific action, never a generic "check the logs".
The overview has no dependency on the optional monitoring stack, so it works when
Prometheus/Grafana are not installed.

### 2. One planner drives both preview and deletion

`app/services/retention.build_cleanup_plan` computes a single plan of **eligible**
and **protected** objects. The preview returns that plan's manifest, and the
cleanup executes exactly the plan's eligible list — so the preview always matches
the deletion, and the manifest is an auditable record of what was (or would be)
removed.

### 3. Cleanup fails closed

An object is deleted only when it is **past its retention window and nothing
depends on it**. It is protected (never deleted) when it is still within
retention, produced by a still-active job, backing an **active (unresolved)
finding**, referenced by a **retained report snapshot**, or under a **legal
hold**. A `retention_holds` table records legal holds; a retention policy has a
hard floor (`MIN_RETENTION_DAYS`) so it can never be set to purge fresh data.

### 4. Cleanup is a high-impact, reauthenticated, audited action

Deletion requires an administrator, an explicit `confirm=true`, and a **password
re-check** (recent reauthentication for a high-impact operation). It is audited
with the full manifest. Placing and lifting legal holds are admin-only and
audited.

### 5. Certificate rotation is preflight + guidance, not an in-app key operation

`GET /maintenance/certificate` reports certificate expiry and returns a rotation
**preflight** (backup present, Scouts reachable, recovery sheet handy) and
recovery guidance. The rotation itself is an operator action (re-enrollment, the
`vulna`/`vulnascout` CLIs), keeping key operations atomic and recoverable and out
of the web tier — the same posture as updates (Phase 24) and backups (Phase 25).

### 6. Storage budgets carry no sensitive labels

`GET /maintenance/storage` reports sizes per category (raw output, reports,
evidence, database, Scout queues, backups). Labels are category names only; no
asset or finding identifiers appear.

### 7. A health report, deliverable later

`GET /maintenance/health-report` summarizes updates, backups, feed age, storage,
failed scans, retention, and expiring certificates with an overall state and a
list of action items. It is the content of the "monthly self-hosting health
report"; delivery through notification channels arrives with Phase 29.

## Security constraints (how they are met)

- **Roles + reauthentication** — read views require authentication; cleanup and
  holds require an administrator, and cleanup additionally requires a password
  re-check and explicit confirmation, and is audited.
- **Referential safety** — cleanup refuses to delete anything referenced by a
  retained report, an active job, an active finding, or a legal hold.
- **Rotation is atomic/recoverable** — certificate/key rotation stays a
  CLI/re-enrollment operation with backups, never an in-app mutation.
- **No sensitive labels** — storage metrics expose only category names and sizes.

## Consequences

- An administrator can judge update/backup/feed/certificate/storage health from
  one page, each warning linked to an action.
- Disk can be reclaimed safely: the preview matches the deletion, and protected
  data is preserved with a stated reason.

## Rollback / migration

One additive table (`retention_holds`); everything else is new services, a new
API router, and a display page. No existing behavior changes.

## Alternatives considered

- **A second, independent health aggregation.** Rejected: it would drift from
  Phase 26 diagnostics. The Maintenance overview reuses those results.
- **Immediate deletion without a preview.** Rejected by the acceptance criteria:
  the preview must match deletion and produce an auditable manifest.
- **In-app CA rotation.** Deferred: high-impact key operations stay in the signed
  CLI so they remain atomic and recoverable.
