# ADR 0026: Vulna Doctor, Diagnostics, and Safe Self-Healing

- **Status:** Accepted
- **Date:** 2026-07-11
- **Phase:** 26 (Vulna Doctor, Diagnostics, and Safe Self-Healing)

## Context

When something breaks in a multi-container deployment, a self-hoster should not
have to grep logs across eight containers to find which component is at fault. This
phase adds one place to see the health of everything, a redacted support bundle,
an event timeline, and a small set of safe repairs.

## Decisions

### 1. Two diagnostic surfaces: `vulna doctor` (host) and System Health (web)

`vulna doctor [--json]` diagnoses the **host** (a superset of `preflight`: OS/arch,
container runtime, disk, ports, clock, DNS/outbound, permissions) with a
human-readable or machine-readable report. The web **System Health** page
(`GET /diagnostics`) aggregates the full multi-component picture: application and
database, local and remote Scouts, scanner capabilities, feed freshness, CA and
Scout certificate expiry, storage use, failed jobs/reports, and update/backup
posture. Between them a user can identify a failing component without opening
container logs.

### 2. Every check names component, impact, data-safety, and next step

Each `DiagnosticResult` carries the component, a status (ok/warn/fail), the impact,
a **data-safety** status (safe / at_risk), a next step, and a documentation link.
Non-passing checks always populate impact and next step, so a diagnosis is
actionable on its own. Diagnostics are read-only.

### 3. Fault diagnosis is tested against seeded failures

Automated tests seed representative failures (e.g. an expired Scout certificate)
and assert the corresponding check reports `fail` with the right remediation,
demonstrating the diagnosis rather than just the happy path.

### 4. Safe self-healing: allowlisted, confirmed, audited, security-preserving

`POST /diagnostics/repair` runs only actions in a small **allowlist** of narrowly
defined, reversible operations over derived state (recreating a missing storage
directory). Every repair requires `confirm=true`, is admin-only, and is audited. A
repair never alters scopes, permissions, users, credentials, or retention, and
never weakens a security setting. Feed retries and worker restarts remain in their
existing, purpose-built surfaces (the Feeds panel, the container runtime).

### 5. Redacted support bundle: allowlist first, secret scan second

`GET /diagnostics/support-bundle` builds a bundle from an **allowlist** — only
explicitly listed, non-sensitive fields from each source (system info, diagnostics
summary, feed status, probe status/versions, and audit action/type/timestamp
only). It never includes passwords, tokens, private keys, authorization headers,
raw credentials, unrestricted evidence, or full scanner output. A pattern-based
secret scanner runs afterward as a **second** line of defense (not the primary
control), and the bundle is returned as a **preview** with a manifest of included
sections/fields for the operator to review before exporting. Generation is
admin-only and audited.

### 6. A local event timeline

`GET /diagnostics/timeline` combines recent audited actions (config changes,
updates, restarts) and failed jobs into one newest-first list, using only
action/type/timestamp — no secrets.

## Security constraints (how they are met)

- **Authorized and audited** — diagnostics require authentication; the support
  bundle and repairs require an administrator and emit audit events.
- **Self-healing preserves security** — repairs only recreate known derived state;
  they cannot change scopes, permissions, users, credentials, retention, or any
  security setting.
- **Allowlist-based redaction** — the bundle is built by copying only allowlisted
  fields; pattern matching is a secondary check, not the sole control.

## Consequences

- An operator can open System Health (or run `vulna doctor`) and see which
  component is failing, its impact, whether data is at risk, and what to do.
- A support bundle can be safely shared for help without leaking secrets.
- Repairs are confined to reversible derived-state fixes with confirmation and an
  audit trail.

## Rollback / migration

Additive and read-mostly: the diagnostics/timeline/support-bundle endpoints are
new and non-mutating; the single repair recreates missing directories. No schema
change.

## Alternatives considered

- **Regex-only redaction for the support bundle.** Rejected by the security
  constraint: pattern matching misses novel secret shapes. An allowlist is the
  primary control, with pattern scanning as backup.
- **A broad self-healing engine (restart workers, rewrite config).** Deferred:
  those actions are host-level and higher-risk; the safe, in-app repair set is kept
  deliberately narrow.
