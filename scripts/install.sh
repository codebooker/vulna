#!/bin/sh
# Vulna bootstrap installer.
#
# Downloads a PINNED release of the `vulna` CLI, verifies its SHA-256 checksum
# AND an Ed25519 signature over the checksum manifest, and only then runs it.
# Unverified remote content is never piped into a shell.
#
# Usage (after reviewing this script):
#   VULNA_VERSION=v1.0.0 sh install.sh -- install --non-interactive --answers answers.json
#
# Everything after `--` is passed through to `vulna install`. Override endpoints
# for testing/mirrors with VULNA_BASE_URL and VULNA_RELEASE_PUBKEY.
set -eu

VULNA_VERSION="${VULNA_VERSION:-v0.1.0}"
VULNA_BASE_URL="${VULNA_BASE_URL:-https://github.com/codebooker/vulna/releases/download/${VULNA_VERSION}}"
# Path to the pinned Ed25519 release public key (PEM). Release builds embed this;
# for testing/mirrors set VULNA_RELEASE_PUBKEY to a local PEM.
VULNA_RELEASE_PUBKEY="${VULNA_RELEASE_PUBKEY:-}"
VULNA_BIN_DIR="${VULNA_BIN_DIR:-/usr/local/bin}"
OPENSSL="${OPENSSL:-openssl}"

# Progress goes to stderr so stdout carries only the CLI's own output.
log() { echo "vulna-install: $*" >&2; }
die() { echo "vulna-install: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }

detect_asset() {
	os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	arch="$(uname -m)"
	case "$arch" in
	x86_64 | amd64) arch="amd64" ;;
	aarch64 | arm64) arch="arm64" ;;
	*) die "unsupported architecture: $arch (supported: amd64, arm64)" ;;
	esac
	[ "$os" = "linux" ] || echo "vulna-install: warning: $os is not a supported deployment OS (Linux is)" >&2
	echo "vulna_${VULNA_VERSION}_${os}_${arch}"
}

main() {
	need "$OPENSSL"
	need sha256sum
	if command -v curl >/dev/null 2>&1; then
		fetch() { curl -fsSL -o "$2" "$1"; }
	elif command -v wget >/dev/null 2>&1; then
		fetch() { wget -qO "$2" "$1"; }
	else
		die "need curl or wget to download the release"
	fi

	[ -n "$VULNA_RELEASE_PUBKEY" ] || die "no pinned release public key. Official release scripts embed it; \
for a mirror set VULNA_RELEASE_PUBKEY to the Ed25519 public key PEM path."
	[ -f "$VULNA_RELEASE_PUBKEY" ] || die "release public key not found: $VULNA_RELEASE_PUBKEY"

	asset="$(detect_asset)"
	work="$(mktemp -d)"
	trap 'rm -rf "$work"' EXIT

	log "downloading $asset ($VULNA_VERSION)"
	fetch "$VULNA_BASE_URL/$asset" "$work/$asset"
	fetch "$VULNA_BASE_URL/SHA256SUMS" "$work/SHA256SUMS"
	fetch "$VULNA_BASE_URL/SHA256SUMS.sig" "$work/SHA256SUMS.sig"

	# 1) Authenticity: Ed25519 signature over the checksum manifest.
	if ! "$OPENSSL" pkeyutl -verify -pubin -inkey "$VULNA_RELEASE_PUBKEY" -rawin \
		-in "$work/SHA256SUMS" -sigfile "$work/SHA256SUMS.sig" >/dev/null 2>&1; then
		die "SIGNATURE INVALID for SHA256SUMS — refusing to run downloaded artifact"
	fi

	# 2) Integrity: the asset's checksum must match the (now-trusted) manifest.
	if ! (cd "$work" && grep " $asset\$" SHA256SUMS | sha256sum -c - >/dev/null 2>&1); then
		die "CHECKSUM MISMATCH for $asset — refusing to run downloaded artifact"
	fi

	log "signature and checksum verified"
	chmod +x "$work/$asset"

	if [ -w "$VULNA_BIN_DIR" ]; then
		install -m 0755 "$work/$asset" "$VULNA_BIN_DIR/vulna"
		log "installed to $VULNA_BIN_DIR/vulna"
		bin="$VULNA_BIN_DIR/vulna"
	else
		log "note: $VULNA_BIN_DIR not writable; running the verified binary in place"
		bin="$work/$asset"
	fi

	# Pass through the caller's arguments to the verified CLI.
	exec "$bin" "$@"
}

# Strip a leading `--` separator so `sh install.sh -- install ...` works.
if [ "${1:-}" = "--" ]; then shift; fi
main "$@"
