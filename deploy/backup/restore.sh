#!/usr/bin/env bash
# Restore a VulnaDash backup produced by backup.sh. The archive's SHA-256 is
# verified before anything is applied, so a corrupted or tampered backup is
# refused rather than restored.
#
#   VULNA_DATA=/var/lib/vulna DATABASE_URL=postgres://... deploy/backup/restore.sh <archive.tar.gz>
set -euo pipefail

ARCHIVE="${1:?usage: restore.sh <archive.tar.gz>}"
VULNA_DATA="${VULNA_DATA:-/var/lib/vulna}"
[ -f "$ARCHIVE" ] || { echo "restore: archive not found: $ARCHIVE" >&2; exit 1; }

# 1. Verify integrity first.
if [ -f "$ARCHIVE.sha256" ]; then
	( cd "$(dirname "$ARCHIVE")" && sha256sum -c "$(basename "$ARCHIVE").sha256" ) \
		|| { echo "restore: checksum verification FAILED — refusing to restore" >&2; exit 1; }
else
	echo "restore: no .sha256 alongside archive; refusing to restore unverified backup" >&2
	exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
tar -xzf "$ARCHIVE" -C "$STAGE"

# 2. Restore the data directory.
mkdir -p "$VULNA_DATA"
if [ -d "$STAGE/data" ]; then
	cp -a "$STAGE/data/." "$VULNA_DATA/"
fi

# 2b. Restore the deployment .env (DB password + evidence master key) if it was
# captured. Written to VULNA_ENV_FILE when set, else left beside the data dir so
# the operator can place it — never silently discarded.
if [ -f "$STAGE/config/env" ]; then
	if [ -n "${VULNA_ENV_FILE:-}" ]; then
		install -m 0600 "$STAGE/config/env" "$VULNA_ENV_FILE"
		echo "restore: deployment .env restored to $VULNA_ENV_FILE"
	else
		install -m 0600 "$STAGE/config/env" "$VULNA_DATA/restored.env"
		echo "restore: deployment .env left at $VULNA_DATA/restored.env (set VULNA_ENV_FILE to place it automatically)" >&2
	fi
fi

# 3. Restore the database.
if [ -f "$STAGE/db.dump" ]; then
	if [ -n "${DATABASE_URL:-}" ] && command -v pg_restore >/dev/null 2>&1; then
		pg_restore --clean --if-exists --no-owner --dbname "$DATABASE_URL" "$STAGE/db.dump"
	else
		cp "$STAGE/db.dump" "$VULNA_DATA/restored-db.dump"
		echo "restore: DATABASE_URL/pg_restore unavailable; dump left at $VULNA_DATA/restored-db.dump" >&2
	fi
fi

echo "restore complete into $VULNA_DATA"
