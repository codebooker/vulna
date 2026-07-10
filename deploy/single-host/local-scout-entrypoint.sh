#!/bin/sh
# Auto-enroll entrypoint for the co-located local Scout (single-host, Phase 17).
#
# The VulnaDash API mints a one-time, auto-approve enrollment token at first-run
# bootstrap and writes it to the shared bootstrap volume. This script waits for
# that token (and for Caddy's internal root CA so the orchestrator's TLS is
# verified, never skipped), enrolls once, then runs the heartbeat loop. It is
# idempotent: on restart the persisted state directory already holds the probe
# identity, so it skips straight to "run".
#
# No secrets are baked into the image; the token arrives on a volume at runtime
# and is consumed on first use.
set -eu

SERVER_URL="${VULNA_SERVER_URL:-https://vulna-dash}"
STATE_DIR="${VULNA_STATE_DIR:-/var/lib/vulna}"
TOKEN_FILE="${VULNA_ENROLL_TOKEN_FILE:-/var/lib/vulna/bootstrap/local-scout-enroll.token}"
# Caddy's public internal root CA, published to the shared bootstrap volume by
# the scout-ca-export one-shot (Caddy itself stores it root-only).
SERVER_CA="${VULNA_SERVER_CA:-/var/lib/vulna/bootstrap/orchestrator-ca.crt}"
WAIT_TIMEOUT="${VULNA_WAIT_TIMEOUT_SECONDS:-180}"

log() { echo "local-scout: $*"; }

wait_for() {
	# wait_for <description> <path>
	desc="$1"
	path="$2"
	waited=0
	while [ ! -s "$path" ]; do
		if [ "$waited" -ge "$WAIT_TIMEOUT" ]; then
			log "timed out after ${WAIT_TIMEOUT}s waiting for $desc ($path)" >&2
			log "is the API up with VULNA_BOOTSTRAP_LOCAL_SCOUT=true, and has Caddy started?" >&2
			exit 1
		fi
		log "waiting for $desc ..."
		sleep 3
		waited=$((waited + 3))
	done
}

# Exact-line match: "status: not enrolled" also contains the word "enrolled".
if vulnascout status --state-dir "$STATE_DIR" 2>/dev/null | grep -qx "status: enrolled"; then
	log "already enrolled; starting heartbeat loop"
else
	wait_for "orchestrator CA" "$SERVER_CA"
	wait_for "enrollment token" "$TOKEN_FILE"
	log "enrolling with $SERVER_URL"
	vulnascout enroll \
		--server "$SERVER_URL" \
		--server-ca "$SERVER_CA" \
		--state-dir "$STATE_DIR" \
		--token "$(cat "$TOKEN_FILE")"
	log "enrolled; starting heartbeat loop"
fi

exec vulnascout run \
	--server "$SERVER_URL" \
	--server-ca "$SERVER_CA" \
	--state-dir "$STATE_DIR"
