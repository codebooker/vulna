#!/usr/bin/env bash
# Verify the VulnaRelay bootstrap accepts signed assets and rejects tampering.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/install-relay.sh"
OPENSSL="${OPENSSL:-openssl}"
VER="v0.0.0-smoke"
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) echo "smoke: unsupported arch" >&2; exit 1 ;;
esac
asset="vulnarelay_${VER}_${os}_${arch}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rel="$work/release"
bindir="$work/bin"
mkdir -p "$rel" "$bindir"
(cd "$ROOT/scout" && go build -o "$rel/$asset" ./cmd/vulnarelay)
printf '%s\n' "$VER" >"$rel/VERSION"
(cd "$rel" && sha256sum "$asset" VERSION >SHA256SUMS)
"$OPENSSL" genpkey -algorithm ed25519 -out "$work/key.pem" 2>/dev/null
"$OPENSSL" pkey -in "$work/key.pem" -pubout -out "$work/pub.pem" 2>/dev/null
"$OPENSSL" pkeyutl -sign -inkey "$work/key.pem" -rawin \
	-in "$rel/SHA256SUMS" -out "$rel/SHA256SUMS.sig"

run_bootstrap() {
	VULNA_VERSION="$VER" VULNA_BASE_URL="file://$rel" \
		VULNA_RELEASE_PUBKEY="$work/pub.pem" VULNA_BIN_DIR="$bindir" \
		VULNA_RELAY_INSTALL_ONLY=1 VULNA_RELAY_SKIP_RUNTIME_CHECK=1 sh "$SCRIPT"
}

run_latest_bootstrap() {
	VULNA_VERSION=latest VULNA_BASE_URL="file://$rel" \
		VULNA_RELEASE_PUBKEY="$work/pub.pem" VULNA_BIN_DIR="$bindir" \
		VULNA_RELAY_INSTALL_ONLY=1 VULNA_RELAY_SKIP_RUNTIME_CHECK=1 sh "$SCRIPT"
}

echo "relay-smoke: valid release"
run_bootstrap
"$bindir/vulnarelay" version | grep -q '^vulnarelay '
echo "relay-smoke: latest channel"
run_latest_bootstrap
echo malicious >>"$rel/$asset"
if run_bootstrap >/dev/null 2>&1; then
	echo "relay-smoke: tampered artifact accepted" >&2
	exit 1
fi
echo "relay-smoke: PASS"
