# Backups, restore, and recovery

Data ownership is only real if you can recover. Vulna backups are **versioned,
encrypted, verifiable, and safe to restore**. Backups are created, verified, and
restored by the operator with the `vulna backup` CLI; the web **Backups** panel is
display-only and never handles your recovery passphrase.

## Create a verified, encrypted backup

```sh
# 1. Produce the base archive (DB dump + data dir) with the existing script.
VULNA_DATA=/var/lib/vulna DATABASE_URL=postgres://... deploy/backup/backup.sh /tmp/out

# 2. Wrap it in an encrypted, manifested bundle (passphrase via env, never argv).
VULNA_BACKUP_PASSPHRASE='a strong recovery passphrase' \
  vulna backup create --archive /tmp/out/vulna-backup-*.tar.gz --encrypt \
  --schema-version "$(cd dash/backend && alembic heads | awk '{print $1}')" \
  --org-id <org-id> --org-slug <org-slug> --out /backups
```

`create` writes a bundle directory containing the (encrypted) archive, a
`manifest.json`, and a `RECOVERY-SHEET.txt`, then **self-verifies** it. Keep the
recovery passphrase somewhere separate from the backup — Vulna does not keep a
copy.

## Verify, list, prune

```sh
VULNA_BACKUP_PASSPHRASE='...' vulna backup verify /backups/vulna-backup-<ts>
vulna backup list  --out /backups
vulna backup prune --out /backups --keep 7        # keep the newest 7
vulna backup recovery-sheet /backups/vulna-backup-<ts>
```

A backup missing required files or failing its checksum is marked **UNUSABLE** —
`restore` refuses it before touching anything. Put flags **before** the bundle path.

## Restore to a clean (or existing) host

```sh
VULNA_BACKUP_PASSPHRASE='...' vulna backup restore \
  --schema-version "$(cd dash/backend && alembic heads | awk '{print $1}')" \
  --org-id <org-id> --dir /opt/vulna /backups/vulna-backup-<ts>
```

`restore` verifies integrity, validates **schema compatibility** and **organization
ownership**, and refuses to overwrite an existing deployment without `--confirm`
(taking a safety backup first). Because the **CA** and the database are backed up,
restoring does **not** require re-enrolling every Scout.

The database dump includes Phase 34 account status, site assignments, lifecycle
history, still-valid invitation/reset hashes, Phase 35 session/refresh state, and
Phase 36 encrypted TOTP factors, recovery-code hashes, WebAuthn public credentials,
MFA policy, authentication strength, and used/expired challenge state. Phase 37
adds identity-provider configuration, purpose-encrypted OIDC client secrets and
SAML certificates/private keys, external identity links, group mappings, SSO
policy/test history, and consumed protocol/replay state.
Phase 38 adds hashed SCIM bearer tokens, provisioned group membership and role/site
mappings, rate-limit windows, external directory ids, and sanitized provisioning
history. These records are required to keep a restored connector's old token,
revocation, ownership, and access decisions intact.
Phase 39 adds authorization roles/permissions, user and service-account scoped
grants, service-principal lifecycle, hashed personal/service API tokens, expiry/IP
restrictions, rotation links, and authorization versions. These records keep
least-privilege automation and immediate revocation intact after restore.
A restore test should verify
that an assigned user sees the same sites, a deactivated user remains unable to
sign in, consumed one-time links remain unusable, revoked sessions remain revoked,
and a refresh token cannot be reused after restore. Unlike the non-secret
portability export, backup data is sensitive and must remain encrypted.
A Phase 36 restore test must additionally verify that a used recovery code remains
used, WebAuthn sign counters do not move backward, and required-MFA grace state is
preserved.
A Phase 37 restore test must verify that provider secrets still decrypt only for
their original purpose, disabled providers remain disabled, enforcement retains a
strong-MFA break-glass user, external subjects stay linked to the same organization,
and consumed OIDC state or SAML assertion IDs remain unusable.
A Phase 38 restore test must verify that revoked/rotated SCIM tokens remain unusable,
active tokens still resolve only their original organization, deprovisioned users
remain inactive, group-derived role/site access is unchanged, and provisioning
logs contain no bearer values.
A Phase 39 restore test must verify that custom and built-in grants resolve to the
same sites and permissions, the last-administrator protection remains effective,
suspended service accounts remain unusable, revoked/rotated API tokens stay
unusable, active tokens retain their original organization and IP restrictions,
and no token value appears in logs or exports.
A Phase 40 restore test must verify that structured asset context, normalized tags,
static and dynamic group membership/explanations, site and department owners, and
effective-owner history are unchanged. Re-evaluating a restored dynamic group must
produce the same membership, and the legacy `tags_json` compatibility projection
must still match normalized assignments.
A Phase 41 restore test must verify that the active risk-profile version and every
score input hash/factor contribution survive unchanged, current findings still point
to their latest immutable snapshot, remediation membership and reviewed suggestions
are intact, and active/revoked/expired finding decisions retain their evidence,
expiry, and prior-status projection. Re-running the expiry sweep after restore must
be idempotent.

A Phase 42 restore test must verify that each vault ciphertext still decrypts only
under its SSH or WinRM purpose, version/retirement history and assignments are
unchanged, deactivated credentials do not resolve, and usage/software/EOL history
is intact. Scout public keys and opt-in state must remain bound to their original
Scout; Scout private X25519 keys live only in Scout state. A restored active vault
must create an envelope decryptable by that Scout without exposing plaintext in the
job row, export, report, evidence, or logs.

A Phase 43 restore test must verify that each finding still points to the same
latest immutable SLA calculation, all predecessor calculations, exceptions,
guidance, pause/resume and breach/completion events remain reconstructable, and the
`due_at` compatibility projection is unchanged. Connector secrets must decrypt only
with the ticket-specific purpose; disabled or untested connectors must remain
disabled, idempotency keys and external ticket identities must survive, and a
restored worker retry must not duplicate a successful remote ticket. No connector
secret may appear in portability, task payloads, audit metadata, or logs.

A Phase 44 restore test must verify connector ciphertext under its dedicated HKDF
purpose, append-only observations, source links, lifecycle events, daily aggregates,
reconciliation snapshots/splits, and report template schedules/runs. Report export
passwords must decrypt only under their separate purpose and must not appear in
task payloads, portability, audit metadata, or logs. Restored auto-merge decisions
must remain reversible without contacting the original source.

The same Phase 44 restore must preserve authoritative DNS public configuration and
decrypt its TSIG value only under the inventory-connector purpose. A restored DNS
connector remains disabled or retains its prior tested/enabled state exactly; its
secret must remain absent from portability, task payloads, test metadata, cursors,
audit metadata, and errors. Collection after restore must reproduce bounded
observations without contacting any destination until an operator explicitly runs
or schedules it.

Active Directory restore coverage must additionally prove that public controller,
base-DN, and CA trust configuration survives unchanged; the bind password decrypts
only with the inventory-connector purpose; and disabled/tested/enabled state is
preserved exactly. Bind material and ephemeral paging cookies remain absent from
portability, task state, observations, audit metadata, and errors after restore.

Microsoft Entra restore coverage must preserve tenant/app UUIDs, the code-defined
cloud selector, limits, and disabled/tested/enabled state exactly. The app client
secret must decrypt only with the inventory-connector purpose. Temporary Graph
bearer and pagination tokens are never backup data and must remain absent from
portability, task state, observations, audit metadata, and errors after restore.
A restore does not contact Microsoft until an operator explicitly tests, runs, or
schedules the connector.

UniFi restore coverage must preserve the exact public Integration API root, site
UUID, resource selectors, bounds, private-network opt-in, and
disabled/tested/enabled state. The API key must decrypt only with the
inventory-connector purpose and remain absent from portability, task state,
observations, cursors, audit metadata, errors, and logs. Restore must not contact a
controller until an operator explicitly tests, runs, or schedules the connector.

VMware vCenter restore coverage must preserve the exact public HTTPS origin,
username, resource selectors, limits, public CA trust, private-network opt-in, and
disabled/tested/enabled state. The password must decrypt only with the
inventory-connector purpose and remain absent from portability, task state,
observations, cursors, audit metadata, errors, and logs. Ephemeral API sessions are
never backup data, and restore must not contact vCenter until an operator explicitly
tests, runs, or schedules the connector.

Proxmox VE and XCP-ng/Xen Orchestra restore coverage must preserve their exact
public origins, selectors, limits, public CA trust, private-network opt-in, public
token identifiers where applicable, and disabled/tested/enabled state. AWS restore
coverage must preserve partition, explicit regions, expected account, limits, and
state; Azure must preserve cloud, tenant/client/subscription identifiers and state;
Google Cloud must preserve project identifiers and state. Every provider secret
must decrypt only with the inventory-connector purpose and remain absent from
portability, task state, observations, cursors, audit metadata, errors, and logs.
Ephemeral sessions, signatures, assertions, and access tokens are never backup
data. Restore must not contact any provider until an operator explicitly tests,
runs, or schedules that connector.

CSV source uploads are included only in encrypted database backups. Restore tests
must verify that source ciphertext decrypts under the CSV-specific purpose, its
SHA-256 and size metadata still match, and a restored worker can derive the same
bounded observations. Source bytes and ciphertext must remain absent from
portability, audit metadata, task payloads, errors, and logs.

Post-Phase-39 background tasks, lease/retry/dead-letter state, and worker heartbeats
are ordinary PostgreSQL records and are included in the encrypted database backup.
After restore, start the API/migrations before the scheduler and worker. Leases from
the old host expire and are reclaimed; do not edit lease rows manually.

## Destinations

Local filesystem is the default. Generic S3-compatible destinations are supported;
give the destination the **minimum** required permissions (write to the backup
prefix only) and use the operator's own scoped credentials.

## What cannot be recovered

- If you lose the **recovery passphrase**, an encrypted backup cannot be decrypted
  or restored. There is no backdoor.
- If the internal **CA key** was lost and was not in a backup, existing Scouts must
  be re-enrolled.

Keep a recent, verified, encrypted backup **off-host**, and test a restore
periodically.
