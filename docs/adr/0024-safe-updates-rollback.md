# ADR 0024: Boring, Safe Updates and Rollback

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 24 (Boring, Safe Updates and Rollback)

## Context

Keeping a self-hosted app current should be less risky than leaving it outdated.
That requires updates that verify what they install, back up before changing
anything, refuse to run at a bad moment, and can be rolled back — without turning
the running application into a remote code-execution channel.

## Decisions

### 1. Updates are verified, operator-driven, and never forced

Updates are applied by the operator with the `vulna` CLI, not by the running
application. `vulna update check`, `vulna update`, `vulna update status`, and
`vulna rollback` fetch a **signed release manifest** for a channel and verify it
before doing anything. The web **Update Center** (`GET /system/update`) is
**display only** — it shows the current version, channel, and the CLI commands,
and never fetches or applies a release. This keeps the app from becoming an
arbitrary package-execution channel and means there is no forced remote update
path. Automatic installation is opt-in.

### 2. Signed manifest, rejected if unsigned, altered, expired, or incompatible

`cli/internal/release` verifies an Ed25519 signature over the `SHA256SUMS`
manifest and then confirms `release.json`'s SHA-256 matches its signed entry (the
same signing scheme as the release artifacts). The manifest is rejected if the
signature is invalid, the manifest bytes were altered, its `expires_at` has
passed, or its channel does not match the requested one. Verification is pure Go
(`crypto/ed25519`) and unit-tested; a smoke test proves a tampered manifest is
refused.

### 3. Pre-update safety checks; an active assessment blocks

`cli/internal/update` runs pre-update checks before any change: free disk, backup
status, database health, local modifications, and — blocking — an **incompatible
active assessment** (no update begins while one runs). Schema-changing releases
surface a migration warning. Hard failures stop the update; warnings require an
explicit `--yes`.

### 4. Automatic pre-update backup and a recorded rollback point

Unless the operator passes the documented `--no-backup` override, `vulna update`
takes an automatic backup first, then records the applied and prior versions plus
the backup path in an update-state file. This makes the change reversible.

### 5. Rollback restores a known-good state — never an incompatible one

`vulna rollback` reverts to the recorded prior version. For a **schema-changing**
release it requires the pre-update backup and instructs restoring it first, so a
rollback never leaves the database on an incompatible schema. If a schema-changing
update recorded no backup, rollback refuses rather than silently downgrading into
an incompatible state. Health-based rollback is the same mechanism: if the new
version cannot reach a healthy state, the operator rolls back to the recorded
point.

### 6. Separate update types and channels

Application, VulnaScout, scanner-binary, scanner-template, and intelligence-feed
updates are treated as separate concerns (the Update Center lists them; Scout
updates use the appliance's own side-by-side update/rollback from Phase 13, and
feed refreshes are the existing VulnaWatch sync). Channels are **stable**
(default), **candidate**, and **development**.

## Security constraints (how they are met)

- **No forced remote update path** — the app never self-updates; the operator runs
  the CLI (§1).
- **Not an arbitrary execution channel** — the manifest authorizes a download the
  operator applies; verification never executes anything (§1, §2).
- **Rollback never restores an incompatible/known-bad state** — schema-changing
  rollbacks require a backup restore; rollback refuses without one (§5). Secrets
  and certificates live on persistent volumes and are not overwritten by an
  application version change, so rollback does not resurrect old secrets.

## Consequences

- A supported update verifies its manifest, backs up, runs pre-checks, and records
  a rollback point; config, identity, scopes, findings, evidence, reports, and
  audit history persist on volumes across the version change.
- An interrupted or unhealthy update can be rolled back to the prior known-good
  version.
- Unsigned/altered/expired/incompatible release metadata is rejected.

## Rollback / migration

Additive. The CLI commands, the update-state file, and the display-only endpoint
introduce no schema change and do not alter existing behavior. The
`update_channel` setting defaults to `stable`.

## Known limitation

Prebuilt images are not yet published to a registry, so `vulna update` verifies the
manifest, runs pre-checks, backs up, records the rollback point, and prints the
exact `docker compose pull/build && up` steps rather than swapping images itself.
Full one-command apply lands with registry/release publishing (release
qualification, Phase 32). The verification, checks, backup, and rollback bookkeeping
are complete and tested.

## Alternatives considered

- **In-app "click to update".** Rejected: it would make the running application a
  remote code-execution channel. Updates are operator-driven via the verifying CLI.
- **Rolling back schema-changing releases by version pointer alone.** Rejected:
  downgrading code against a newer schema is unsafe; rollback requires the
  pre-update backup for schema changes.
