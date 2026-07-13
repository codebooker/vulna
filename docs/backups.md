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
