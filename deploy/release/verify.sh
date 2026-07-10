#!/usr/bin/env bash
# Verify signed release artifacts: check the Ed25519 signature over SHA256SUMS,
# then verify every artifact's checksum. Fails if either the signature or any
# checksum does not match.
#
#   VULNA_RELEASE_PUBKEY=release_ed25519.pub deploy/release/verify.sh dist/
set -euo pipefail

OPENSSL="${OPENSSL:-openssl}"
DIR="${1:?usage: verify.sh <artifacts-dir>}"
PUB="${VULNA_RELEASE_PUBKEY:?set VULNA_RELEASE_PUBKEY to the Ed25519 public key PEM}"
PUB="$(cd "$(dirname "$PUB")" && pwd)/$(basename "$PUB")"

cd "$DIR"
if [ ! -f SHA256SUMS ] || [ ! -f SHA256SUMS.sig ]; then
	echo "verify: missing SHA256SUMS(.sig)" >&2
	exit 1
fi

if ! "$OPENSSL" pkeyutl -verify -pubin -inkey "$PUB" -rawin \
	-in SHA256SUMS -sigfile SHA256SUMS.sig >/dev/null 2>&1; then
	echo "verify: SIGNATURE INVALID" >&2
	exit 1
fi
sha256sum -c SHA256SUMS >/dev/null || { echo "verify: CHECKSUM MISMATCH" >&2; exit 1; }

echo "verify: signature valid and all checksums match"
