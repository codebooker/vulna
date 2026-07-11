# Maintenance center

The Maintenance center is one place to tell whether Vulna needs attention and to
keep a long-running deployment healthy: updates, Scouts, scanners, feeds, backups,
certificates, storage, retention, stuck jobs, and report failures. See
[ADR 0028](adr/0028-maintenance-center.md) for the design.

## Overview

`GET /api/v1/maintenance` returns every maintenance domain with a **green /
warning / action-required** state and, for anything not green, a specific next
step (never a generic "check the logs"). It aggregates the same checks as
[Vulna Doctor](diagnostics.md), so the two never disagree, and adds stuck-job and
reclaimable-storage signals. It works even when the optional monitoring stack is
not installed.

`GET /api/v1/maintenance/health-report` is a self-hosting health summary (updates,
backups, feed age, storage, failed scans, retention, expiring certificates) with
an overall state and action items — the content of a monthly maintenance report.
Delivery through notification channels arrives in a later phase.

## Storage budgets

`GET /api/v1/maintenance/storage` breaks down usage by category — raw scanner
output, reports, evidence, database, Scout queues, and backups — plus overall disk
free space. Labels are category names only; no asset or finding data appears.

## Retention and safe cleanup

Old raw scanner output and stale reports can be cleaned up to reclaim disk. The
workflow is deliberately conservative and **fails closed**.

1. **Preview** — `GET /api/v1/maintenance/retention/preview?raw_output_days=&report_days=`
   returns a manifest of exactly what a cleanup would delete (**eligible**) and
   what it would keep and why (**protected**). The preview matches the deletion.
2. **Run** — `POST /api/v1/maintenance/retention/cleanup` deletes only the eligible
   objects. It requires an administrator, `confirm=true`, and a **password
   re-check**, and is audited with the full manifest.

An object is **protected** (never deleted) when it is:

- still within its retention window,
- produced by a job that is still active,
- backing an **active (unresolved) finding**,
- referenced by a **retained report snapshot**, or
- under a **legal hold**.

A retention policy cannot be set below a hard floor, so cleanup can never purge
fresh data.

### Legal holds

Place a hold to exempt a report or a scan job (and the raw artifacts backing it)
from cleanup regardless of age:

```
POST   /api/v1/maintenance/holds      {"target_type": "scan_job", "target_id": "..."}
GET    /api/v1/maintenance/holds
DELETE /api/v1/maintenance/holds/{id}
```

Placing and lifting holds are admin-only and audited.

## Certificate rotation

`GET /api/v1/maintenance/certificate` reports internal-CA and Scout certificate
expiry, a rotation **preflight** (verified backup present, Scouts reachable,
recovery sheet handy), and recovery guidance. Rotation itself is an operator
action so it stays atomic and recoverable: rotate with the CLI, and if a Scout
cannot re-establish mutual TLS afterward, run `vulnascout reset` on it and
re-enroll with a fresh token. The internal CA and keys are backed up and restored
with `vulna backup`.
