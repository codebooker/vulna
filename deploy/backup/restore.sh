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

# 3. Restore the database. This is the whole point of a restore, so if we cannot
# actually load the dump we FAIL — never report success for a database that was not
# restored. (The Compose deployment restores the DB via `docker compose exec
# postgres pg_restore` in the CLI, not this host-mode path.)
if [ -f "$STAGE/db.dump" ]; then
	if [ -n "${DATABASE_URL:-}" ] && command -v pg_restore >/dev/null 2>&1; then
		# Atomic restore: --single-transaction (+ --exit-on-error) so a mid-way failure
		# rolls back and leaves the database unchanged, rather than partly dropped and
		# partly restored.
		pg_restore --clean --if-exists --no-owner --single-transaction --exit-on-error \
			--dbname "$DATABASE_URL" "$STAGE/db.dump"
	elif [ -n "${VULNA_DB_RESTORE_OUT:-}" ]; then
		# Explicit test hook: write the dump to a caller-named path. Used by the smoke
		# test to exercise the archive mechanics WITHOUT a live PostgreSQL. Not a real
		# database restore — the caller knows that.
		cp "$STAGE/db.dump" "$VULNA_DB_RESTORE_OUT"
		echo "restore: staged db.dump to $VULNA_DB_RESTORE_OUT (test hook; no live DB restored)" >&2
	else
		echo "restore: no way to restore the database (set DATABASE_URL with pg_restore, or use the CLI against a running Compose deployment)." >&2
		echo "restore: FAILED — the database was NOT restored." >&2
		exit 1
	fi
fi

echo "restore complete into $VULNA_DATA"
