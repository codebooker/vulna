#!/usr/bin/env bash
# Release-signing smoke test: signs dummy artifacts with an ephemeral Ed25519
# key, verifies them, and confirms that a tampered artifact or a tampered
# signature is rejected. Requires an OpenSSL with Ed25519 (OpenSSL 3.x).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pick an OpenSSL that supports Ed25519 (system openssl on CI; brew's locally).
pick_openssl() {
	for c in "${OPENSSL:-}" openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
		[ -n "$c" ] || continue
		if "$c" genpkey -algorithm ed25519 -out /dev/null >/dev/null 2>&1; then
			echo "$c"; return 0
		fi
	done
	echo "no OpenSSL with Ed25519 support found" >&2; exit 1
}
OPENSSL="$(pick_openssl)"
export OPENSSL
echo "using openssl: $OPENSSL ($("$OPENSSL" version))"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DIST="$WORK/dist"
mkdir -p "$DIST"
echo "vulnascout-binary" > "$DIST/vulnascout_1.0.0_amd64.deb"
echo "probe-image-digest" > "$DIST/image-digest.txt"

echo "== generate ephemeral release key =="
"$OPENSSL" genpkey -algorithm ed25519 -out "$WORK/key.pem"
"$OPENSSL" pkey -in "$WORK/key.pem" -pubout -out "$WORK/pub.pem"

echo "== sign =="
VULNA_RELEASE_KEY="$WORK/key.pem" bash "$HERE/sign.sh" "$DIST"
if [ ! -f "$DIST/SHA256SUMS" ] || [ ! -f "$DIST/SHA256SUMS.sig" ]; then
	echo "FAIL: manifest/sig missing" >&2
	exit 1
fi

echo "== verify (should pass) =="
VULNA_RELEASE_PUBKEY="$WORK/pub.pem" bash "$HERE/verify.sh" "$DIST"

echo "== tamper an artifact (verify should fail) =="
echo "backdoor" >> "$DIST/vulnascout_1.0.0_amd64.deb"
if VULNA_RELEASE_PUBKEY="$WORK/pub.pem" bash "$HERE/verify.sh" "$DIST" >/dev/null 2>&1; then
	echo "FAIL: verify accepted a tampered artifact" >&2; exit 1
fi
echo "  ok: tampered artifact rejected"

echo "== tamper the signature with a different key (verify should fail) =="
"$OPENSSL" genpkey -algorithm ed25519 -out "$WORK/rogue.pem"
# Re-sign the (restored) manifest with a rogue key, verify with the real pub.
echo "vulnascout-binary" > "$DIST/vulnascout_1.0.0_amd64.deb"
VULNA_RELEASE_KEY="$WORK/rogue.pem" bash "$HERE/sign.sh" "$DIST" >/dev/null
if VULNA_RELEASE_PUBKEY="$WORK/pub.pem" bash "$HERE/verify.sh" "$DIST" >/dev/null 2>&1; then
	echo "FAIL: verify accepted a signature from the wrong key" >&2; exit 1
fi
echo "  ok: wrong-key signature rejected"

echo ""
echo "RELEASE SIGNING SMOKE TEST PASSED"
