#!/usr/bin/env bash
# Smoke test for `vulna update check`: it must verify a correctly signed release
# manifest and REFUSE a tampered one. Serves the release over HTTP (the CLI uses
# net/http, which does not support file://).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OPENSSL="${OPENSSL:-openssl}"
PORT="${PORT:-18723}"

work="$(mktemp -d)"
srv_pid=""
cleanup() {
	if [ -n "$srv_pid" ]; then
		kill "$srv_pid" 2>/dev/null || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT

echo "smoke: building vulna CLI"
(cd "$ROOT/cli" && go build -o "$work/vulna" ./cmd/vulna)

rel="$work/site/stable"
mkdir -p "$rel"
cat >"$rel/release.json" <<'JSON'
{
  "version": "9.9.9",
  "channel": "stable",
  "released_at": "2026-07-10T00:00:00Z",
  "security": "recommended",
  "migration": { "has_migrations": true, "notes": "adds an index" },
  "notes": "smoke test release"
}
JSON

echo "smoke: signing the checksum manifest"
"$OPENSSL" genpkey -algorithm ed25519 -out "$work/key.pem" 2>/dev/null
"$OPENSSL" pkey -in "$work/key.pem" -pubout -out "$work/pub.pem" 2>/dev/null
(cd "$rel" && sha256sum release.json >SHA256SUMS)
"$OPENSSL" pkeyutl -sign -inkey "$work/key.pem" -rawin -in "$rel/SHA256SUMS" -out "$rel/SHA256SUMS.sig"

echo "smoke: serving release over HTTP on :$PORT"
(cd "$work/site" && python3 -m http.server "$PORT" >/dev/null 2>&1) &
srv_pid=$!
sleep 1

check() {
	"$work/vulna" update check \
		--base-url "http://127.0.0.1:$PORT" \
		--channel stable \
		--pubkey "$work/pub.pem" \
		--dir "$work"
}

echo "smoke: (1) valid signed manifest must verify"
out="$(check)"
echo "$out" | grep -q "9.9.9" || {
	echo "smoke: FAIL — expected the manifest version to be shown" >&2
	exit 1
}
echo "smoke:   ok — verified and displayed"

echo "smoke: (2) tampered manifest must be refused"
printf '\n ' >>"$rel/release.json" # change bytes without re-signing
if check >/dev/null 2>&1; then
	echo "smoke: FAIL — tampered manifest was NOT refused" >&2
	exit 1
fi
echo "smoke:   ok — checksum mismatch refused"

echo "smoke: PASS"
