# ADR 0025: Backups, Restore, and Recovery

- **Status:** Accepted
- **Date:** 2026-07-11
- **Phase:** 25 (Backups, Restore, and Recovery That Users Will Actually Test)

## Context

Data ownership is only real if recovery is understandable and verifiable. The
existing checksummed backup/restore scripts (Phase 15) needed a versioned
manifest, encryption, richer verification, restore safety, and a recovery process
a non-expert can actually follow.

## Decisions

### 1. A `vulna backup` CLI with a versioned, secret-free manifest

`vulna backup create | list | verify | restore | prune | recovery-sheet` wrap the
DB-dump-plus-data archive from `deploy/backup/backup.sh` in a **bundle** with a
versioned `manifest.json`. The manifest records backup version, timestamps, app
and schema versions, organization ownership, the archive checksum, encryption
metadata, and the content classes present (database, config, CA + key material,
Scout identity metadata, reports, evidence, branding, presets). It never contains
passwords, tokens, private-key content, or evidence plaintext (enforced by
construction and tested).

### 2. Authenticated encryption with a user-controlled recovery passphrase

Bundles are encrypted with **AES-256-GCM**, keyed by **PBKDF2-HMAC-SHA256** from a
recovery passphrase the operator supplies via an environment variable (never argv,
never stored, never in the manifest or logs). Both primitives are implemented from
the Go standard library so the CLI keeps no third-party dependency. Encryption is
required for backups containing credentials, CA material, evidence, or application
secrets. A wrong passphrase or any tampering fails GCM authentication — decryption
never returns partial plaintext.

### 3. Verify marks a bundle unusable *before* any destructive step

`verify` (and a self-verify inside `create`) checks the manifest, the presence of
required content classes, and — after decrypting an encrypted bundle — the archive
checksum. A bundle missing required files or failing its checksum is marked
**UNUSABLE**; `restore` refuses it before touching anything.

### 4. Restore validates compatibility and ownership, and never overwrites silently

`restore` verifies integrity, then validates **schema-version compatibility** and
**organization ownership** (both must match, or it blocks), and refuses to
overwrite an existing deployment without an explicit `--confirm` — and takes a
safety backup of the current state first. (A UX guard also rejects flags placed
after the bundle path, so a validation flag can never be silently skipped.)

### 5. Losing the host does not mean re-enrolling every Scout

The **CA and required key material** are a required content class. Restoring a
backup that includes the CA plus the database (which holds probe certificate
metadata) brings back Scout identities, so a host loss does not force
re-enrollment.

### 6. A printable recovery sheet, and honesty about what cannot be recovered

`recovery-sheet` prints a sheet with only non-secret identifiers (org, versions,
backup location, contents), key-custody instructions, and the restore commands. It
states plainly that an encrypted backup **cannot** be restored without its recovery
passphrase, and that a lost, un-backed-up CA key means Scouts must re-enroll. No
secret ever appears on the sheet.

### 7. Display-only web backup center

`GET /system/backups` shows the retention policy, destinations (local default,
S3-compatible), content classes, encryption note, the CLI commands, and a
prominent warning to keep a recent verified off-host backup. The running app never
handles the recovery passphrase or performs the backup — the operator does, with
the CLI.

## Security constraints (how they are met)

- **Encryption required for sensitive backups** — credential/CA/evidence backups
  use AES-256-GCM with the operator's passphrase (§2).
- **Minimum-permission destinations** — bundles and manifests are written `0600`/
  `0700`; the local default keeps data on the host, and S3 uses the operator's own
  scoped credentials (documented).
- **Restore validates hashes, schema, and ownership** — checksum, schema version,
  and organization metadata are all checked before a restore proceeds (§3, §4).

## Consequences

- A verified backup restores a clean supported host to a functionally equivalent
  deployment; config, identity, scopes, findings, evidence metadata, reports, and
  audit history are all covered.
- A missing-file or checksum-failing backup is refused before any destructive step.
- A restore never clobbers an existing deployment without confirmation and a safety
  backup.

## Rollback / migration

Additive. The `vulna backup` commands, the manifest/encryption format, and the
display-only endpoint introduce no schema change and do not alter existing
behavior. The existing `deploy/backup/backup.sh`/`restore.sh` still work and are
what `create`/`restore` build on.

## Known limitation

`create` wraps an archive produced by `deploy/backup/backup.sh` (passed via
`--archive`); orchestrating the DB dump inline and pushing to S3 are thin wrappers
left for the release/ops layer. The manifest, encryption, verification, restore
safety, and recovery sheet — the security-critical core — are complete and tested.

## Alternatives considered

- **Storing the recovery key in the app.** Rejected: it would defeat encryption and
  make the app a single point of compromise. The passphrase is the operator's.
- **Skipping schema/ownership checks on restore.** Rejected: restoring an
  incompatible schema or another org's data is a data-integrity and isolation
  hazard; both are validated before restore.
