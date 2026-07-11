#!/usr/bin/env bash
# Produce the hosted installer with the pinned release public key embedded.
#
# The release pipeline runs this once per release and publishes the result at the
# hosted install URL, so `curl … | sh` works without the operator supplying a key.
#
#   deploy/release/embed-release-pubkey.sh release_ed25519.pub > hosted-install.sh
#
# Reads scripts/install.sh, replaces the __VULNA_RELEASE_PUBKEY_PEM__ placeholder
# with the standard PEM public key, and writes the result to stdout.
set -euo pipefail

PUBKEY="${1:?usage: embed-release-pubkey.sh <release-ed25519.pub> [install.sh]}"
SCRIPT="${2:-$(cd "$(dirname "$0")/../.." && pwd)/scripts/install.sh}"

[ -f "$PUBKEY" ] || { echo "embed: public key not found: $PUBKEY" >&2; exit 1; }
[ -f "$SCRIPT" ] || { echo "embed: installer not found: $SCRIPT" >&2; exit 1; }
grep -q "__VULNA_RELEASE_PUBKEY_PEM__" "$SCRIPT" || {
	echo "embed: placeholder __VULNA_RELEASE_PUBKEY_PEM__ not found in $SCRIPT" >&2
	exit 1
}

# awk substitution reading the key as its own file: passing a multi-line value via
# -v is not portable (BSD awk mangles the newlines), so build it line by line
# instead. sed is avoided because the PEM's slashes would need escaping. The PEM
# is a single-quoted shell value, so it must not contain single quotes (it never
# does).
awk '
	FNR == NR { key = key (FNR > 1 ? "\n" : "") $0; next }
	{ gsub(/__VULNA_RELEASE_PUBKEY_PEM__/, key); print }
' "$PUBKEY" "$SCRIPT"
