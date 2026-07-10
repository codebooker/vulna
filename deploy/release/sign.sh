#!/usr/bin/env bash
# Sign a directory of release artifacts: write a SHA256SUMS manifest and an
# Ed25519 detached signature over it. Consumers verify the signature (proving
# authenticity) and then the checksums (proving integrity) with verify.sh.
#
#   VULNA_RELEASE_KEY=release_ed25519.pem deploy/release/sign.sh dist/
#
# Generate a release key once (keep the private key offline/secret):
#   openssl genpkey -algorithm ed25519 -out release_ed25519.pem
#   openssl pkey -in release_ed25519.pem -pubout -out release_ed25519.pub
set -euo pipefail

OPENSSL="${OPENSSL:-openssl}"
DIR="${1:?usage: sign.sh <artifacts-dir>}"
KEY="${VULNA_RELEASE_KEY:?set VULNA_RELEASE_KEY to the Ed25519 private key PEM}"
[ -d "$DIR" ] || { echo "sign: not a directory: $DIR" >&2; exit 1; }
KEY="$(cd "$(dirname "$KEY")" && pwd)/$(basename "$KEY")"

cd "$DIR"
# Checksum every artifact except the manifest/signature themselves.
find . -type f ! -name 'SHA256SUMS' ! -name 'SHA256SUMS.sig' -print0 \
	| sort -z | xargs -0 sha256sum > SHA256SUMS

"$OPENSSL" pkeyutl -sign -inkey "$KEY" -rawin -in SHA256SUMS -out SHA256SUMS.sig

echo "signed $(wc -l < SHA256SUMS) artifact(s): SHA256SUMS + SHA256SUMS.sig"
