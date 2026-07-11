# ADR 0031: Privacy, Data Ownership, and Portability

- **Status:** Accepted
- **Date:** 2026-07-11
- **Phase:** 31 (Privacy, Data Ownership, and Portability)

## Context

People self-host Vulna specifically to keep control of their data. Vulna already
has no mandatory account, license server, hosted control plane, or telemetry
endpoint, and the application never contacts a release server (updates are
CLI-run). This phase makes that concrete and inspectable, adds opt-in-only
anonymous telemetry, and gives operators a complete, verifiable export and a
supported host-move workflow.

## Decisions

### 1. Outbound transparency

`GET /privacy/outbound` enumerates every destination the deployment may contact:
intelligence feeds (NVD/KEV/EPSS), the SMTP and webhook channels the operator
configured, and telemetry (if opted in). It explicitly reports that update checks
contact nothing. The list is computed from actual configuration, so it always
reflects enabled features and destinations.

### 2. Telemetry is off, opt-in, anonymous, and previewable

Telemetry defaults to off and is never enabled by a preselected control.
`GET /privacy/telemetry/preview` shows the exact payload before opt-in: the
product version and **aggregate counts only**. It never contains IP addresses,
hostnames, usernames, findings, CVEs tied to assets, evidence, credentials, report
contents, or a stable cross-installation identifier. A **local analytics** option
reports the same counts and is never transmitted. Toggle changes are audited.

### 3. Disabling never breaks core function

Update checks, telemetry, and feeds are independent toggles in the organization's
`settings_json` (no schema change). Disabling any of them does not affect
scanning, reporting, remediation, or local intelligence import.

### 4. Complete, verifiable, non-secret export

`GET /portability/export` produces a versioned, checksummed JSON bundle of an
organization's non-secret data. It contains no keys, tokens, certificates,
passwords, or report file bytes. The bundle validates independently against the
published schema (`shared/schemas/export-bundle.schema.json`) and a SHA-256
checksum over the canonical JSON of every field except `checksum`.

### 5. Import is untrusted and never a cross-org bypass

`POST /portability/validate` checks schema version, checksum, ownership, and
conflicts and **never applies anything**. A bundle from a different organization is
refused. Trust roots, privileged users, and signing keys are never overwritten by
an import. The actual host move is a **backup/restore** (Phase 25), which restores
the internal CA and Scout identity so enrolled Scouts keep their mutual-TLS trust;
`GET /portability/migration-plan` returns that checklist.

### 6. A machine-readable data map

`shared/schemas/data-map.json` (and `docs/data-map.md`) document what Vulna stores,
where, its sensitivity, whether it appears in an export, and every way data can
leave. The threat model is updated with the privacy posture.

### 7. Secret inventory without values

`GET /privacy/secrets` reports which secrets are configured (application key,
admin account, internal CA key, signing key, NVD API key, notification secrets)
and never returns a value.

## Security constraints (how they are met)

- **Anonymous telemetry** — aggregate counts only; a field-level preview and an
  audit record on change; no PII or cross-installation identifier.
- **Untrusted imports** — validated, never auto-applied; trust roots/users/keys
  never overwritten; cross-organization data refused.
- **No authorization bypass** — export and validation are org-scoped and admin-only.

## Consequences

- An operator can see exactly what leaves the deployment and turn most of it off
  without breaking Vulna.
- Data can be exported and independently verified, and a host move preserves Scout
  trust.

## Rollback / migration

Additive: privacy toggles live in `settings_json` (no schema change); new
read/validate endpoints; a published export schema and data map. No existing
behavior changes.

## Alternatives considered

- **A full JSON re-import/merge for host moves.** Rejected as both risky (a merge
  that touched trust roots/users/keys would be an authorization hazard) and
  unnecessary — backup/restore already moves everything and preserves identity.
  Export/validate serves inspection and portability; restore serves migration.
- **Telemetry on by default with an opt-out.** Rejected by the constraint that no
  opt-in is obtained through preselected controls.
