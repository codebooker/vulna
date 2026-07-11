#!/usr/bin/env bash
# Back up VulnaDash: the PostgreSQL database plus the persistent data directory
# (CA + job-signing keys, reports, evidence, config). Produces a single
# checksummed tar.gz so a restore can verify integrity before applying.
#
#   VULNA_DATA=/var/lib/vulna DATABASE_URL=postgres://... deploy/backup/backup.sh /backups
#
# If DATABASE_URL/pg_dump are unavailable, a pre-made dump at $VULNA_DB_DUMP is
# included instead (used by the smoke test). The data dir is always included.
set -euo pipefail

VULNA_DATA="${VULNA_DATA:-/var/lib/vulna}"
OUT_DIR="${1:-${BACKUP_DIR:-/var/backups/vulna}}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$OUT_DIR" "$STAGE/data"

# 1. Database dump.
if [ -n "${DATABASE_URL:-}" ] && command -v pg_dump >/dev/null 2>&1; then
	pg_dump --format=custom "$DATABASE_URL" > "$STAGE/db.dump"
elif [ -n "${VULNA_DB_DUMP:-}" ] && [ -f "$VULNA_DB_DUMP" ]; then
	cp "$VULNA_DB_DUMP" "$STAGE/db.dump"
else
	echo "backup: no database dump source (set DATABASE_URL or VULNA_DB_DUMP)" >&2
	echo "backup: refusing to write a backup with no database dump." >&2
	exit 1
fi

# A zero-byte dump is a failed pg_dump, not a backup; fail rather than certify it.
if [ ! -s "$STAGE/db.dump" ]; then
	echo "backup: database dump is empty; aborting." >&2
	exit 1
fi

# 2. Persistent data directory (keys, reports, evidence, config).
if [ -d "$VULNA_DATA" ]; then
	cp -a "$VULNA_DATA/." "$STAGE/data/"
fi

# 3. Archive + checksum.
ARCHIVE="$OUT_DIR/vulna-backup-$STAMP.tar.gz"
tar -czf "$ARCHIVE" -C "$STAGE" .
( cd "$OUT_DIR" && sha256sum "$(basename "$ARCHIVE")" > "$ARCHIVE.sha256" )

echo "backup written: $ARCHIVE"
echo "checksum:       $ARCHIVE.sha256"
