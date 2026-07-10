#!/usr/bin/env bash
# Backup/restore smoke test: proves a backup round-trips the data dir + DB dump
# with an integrity check, and that a tampered archive is refused. No live
# PostgreSQL required — it exercises the archive/checksum/restore mechanics.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export VULNA_DATA="$WORK/data"
export VULNA_DB_DUMP="$WORK/source-db.dump"
BACKUPS="$WORK/backups"

check() { if [ "$2" = "$3" ]; then echo "  ok: $1"; else echo "  FAIL: $1 (expected '$2' got '$3')" >&2; exit 1; fi; }

echo "== seed a data dir (keys/config/reports) + a DB dump =="
mkdir -p "$VULNA_DATA/keys" "$VULNA_DATA/reports"
echo "ca-private-key" > "$VULNA_DATA/keys/ca_key.pem"
echo "signing-key"    > "$VULNA_DATA/keys/job_signing"
echo "report-bytes"   > "$VULNA_DATA/reports/r1.pdf"
echo "PGDUMP-CONTENTS" > "$VULNA_DB_DUMP"

echo "== back up =="
bash "$HERE/backup.sh" "$BACKUPS" >/dev/null
ARCHIVE="$(ls "$BACKUPS"/vulna-backup-*.tar.gz)"
check "checksum file exists" "yes" "$([ -f "$ARCHIVE.sha256" ] && echo yes || echo no)"

echo "== wipe the live data dir, then restore =="
rm -rf "$VULNA_DATA"
export VULNA_DATA="$WORK/restored"
bash "$HERE/restore.sh" "$ARCHIVE" >/dev/null
check "CA key restored"     "ca-private-key" "$(cat "$VULNA_DATA/keys/ca_key.pem")"
check "signing key restored" "signing-key"   "$(cat "$VULNA_DATA/keys/job_signing")"
check "report restored"     "report-bytes"   "$(cat "$VULNA_DATA/reports/r1.pdf")"
check "db dump restored"    "PGDUMP-CONTENTS" "$(cat "$VULNA_DATA/restored-db.dump")"

echo "== tampered archive is refused =="
printf 'corruption' >> "$ARCHIVE"   # invalidate the checksum
if bash "$HERE/restore.sh" "$ARCHIVE" >/dev/null 2>&1; then
	echo "  FAIL: restore accepted a tampered archive" >&2
	exit 1
fi
check "tampered backup refused" "refused" "refused"

echo ""
echo "BACKUP/RESTORE SMOKE TEST PASSED"
