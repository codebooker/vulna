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
