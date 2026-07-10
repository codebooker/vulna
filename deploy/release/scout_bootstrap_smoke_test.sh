#!/usr/bin/env bash
# Smoke test for scripts/install-scout.sh: it must verify a correctly signed
# release and install it, and REFUSE a tampered artifact or signature.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="$ROOT/scripts/install-scout.sh"
OPENSSL="${OPENSSL:-openssl}"
VER="v0.0.0-smoke"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$(uname -m)" in
x86_64 | amd64) arch="amd64" ;;
aarch64 | arm64) arch="arm64" ;;
*)
	echo "smoke: unsupported arch $(uname -m)" >&2
	exit 1
	;;
esac
asset="vulnascout_${VER}_${os}_${arch}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rel="$work/release"
bindir="$work/bin"
mkdir -p "$rel" "$bindir"

echo "smoke: building VulnaScout as release asset $asset"
(cd "$ROOT/scout" && go build -o "$rel/$asset" ./cmd/vulnascout)

echo "smoke: creating signed checksum manifest"
(cd "$rel" && sha256sum "$asset" >SHA256SUMS)
"$OPENSSL" genpkey -algorithm ed25519 -out "$work/key.pem" 2>/dev/null
"$OPENSSL" pkey -in "$work/key.pem" -pubout -out "$work/pub.pem" 2>/dev/null
"$OPENSSL" pkeyutl -sign -inkey "$work/key.pem" -rawin \
	-in "$rel/SHA256SUMS" -out "$rel/SHA256SUMS.sig"

run_bootstrap() {
	VULNA_VERSION="$VER" \
		VULNA_BASE_URL="file://$rel" \
		VULNA_RELEASE_PUBKEY="$work/pub.pem" \
		VULNA_BIN_DIR="$bindir" \
		sh "$SCRIPT"
}

echo "smoke: (1) valid release must verify and install"
run_bootstrap
"$bindir/vulnascout" version | grep -q "^vulnascout " || {
	echo "smoke: FAIL — expected the Scout to be installed and runnable" >&2
	exit 1
}
echo "smoke:   ok — verified and installed"

echo "smoke: (2) tampered artifact must be refused"
echo "malicious" >>"$rel/$asset"
if run_bootstrap >/dev/null 2>&1; then
	echo "smoke: FAIL — tampered artifact was NOT refused" >&2
	exit 1
fi
echo "smoke:   ok — checksum mismatch refused"

echo "smoke: (3) invalid signature must be refused"
(cd "$rel" && sha256sum "$asset" >SHA256SUMS)
printf 'corrupt' >"$rel/SHA256SUMS.sig"
if run_bootstrap >/dev/null 2>&1; then
	echo "smoke: FAIL — invalid signature was NOT refused" >&2
	exit 1
fi
echo "smoke:   ok — invalid signature refused"

echo "smoke: PASS"
