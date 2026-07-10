#!/bin/sh
# VulnaScout bootstrap installer (remote Scout enrollment).
#
# Downloads a PINNED, signed VulnaScout release, verifies its SHA-256 checksum AND
# an Ed25519 signature over the checksum manifest, installs it, and (if a token is
# provided) enrolls with the orchestrator. Unverified remote content is never
# piped into a shell. No inbound port is opened on this host.
#
# Usage (typically produced by "Add VulnaScout" in VulnaDash):
#   VULNA_SERVER=https://vulna.example.com VULNA_ENROLL_TOKEN=... sh install-scout.sh
#
# The token is read from the environment (not argv) so it does not linger in
# persistent process listings. Override endpoints for testing with
# VULNA_BASE_URL and VULNA_RELEASE_PUBKEY.
set -eu

VULNA_VERSION="${VULNA_VERSION:-v0.1.0}"
VULNA_BASE_URL="${VULNA_BASE_URL:-https://github.com/codebooker/vulna/releases/download/${VULNA_VERSION}}"
VULNA_RELEASE_PUBKEY="${VULNA_RELEASE_PUBKEY:-}"
VULNA_BIN_DIR="${VULNA_BIN_DIR:-/usr/local/bin}"
VULNA_SERVER="${VULNA_SERVER:-}"
VULNA_ENROLL_TOKEN="${VULNA_ENROLL_TOKEN:-}"
OPENSSL="${OPENSSL:-openssl}"

log() { echo "install-scout: $*" >&2; }
die() { echo "install-scout: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }

detect_asset() {
	os="$(uname -s | tr '[:upper:]' '[:lower:]')"
	arch="$(uname -m)"
	case "$arch" in
	x86_64 | amd64) arch="amd64" ;;
	aarch64 | arm64) arch="arm64" ;;
	*) die "unsupported architecture: $arch (supported: amd64, arm64)" ;;
	esac
	[ "$os" = "linux" ] || echo "install-scout: warning: $os is not a supported deployment OS (Linux is)" >&2
	echo "vulnascout_${VULNA_VERSION}_${os}_${arch}"
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
	( cd "$work" && fetch "$VULNA_BASE_URL/$asset" "$asset" )
	fetch "$VULNA_BASE_URL/SHA256SUMS" "$work/SHA256SUMS"
	fetch "$VULNA_BASE_URL/SHA256SUMS.sig" "$work/SHA256SUMS.sig"

	# 1) Authenticity: Ed25519 signature over the checksum manifest.
	if ! "$OPENSSL" pkeyutl -verify -pubin -inkey "$VULNA_RELEASE_PUBKEY" -rawin \
		-in "$work/SHA256SUMS" -sigfile "$work/SHA256SUMS.sig" >/dev/null 2>&1; then
		die "SIGNATURE INVALID for SHA256SUMS — refusing to install"
	fi
	# 2) Integrity: the asset matches the now-trusted manifest.
	if ! (cd "$work" && grep " $asset\$" SHA256SUMS | sha256sum -c - >/dev/null 2>&1); then
		die "CHECKSUM MISMATCH for $asset — refusing to install"
	fi
	log "signature and checksum verified"

	chmod +x "$work/$asset"
	if [ -w "$VULNA_BIN_DIR" ]; then
		install -m 0755 "$work/$asset" "$VULNA_BIN_DIR/vulnascout"
		bin="$VULNA_BIN_DIR/vulnascout"
		log "installed to $bin"
	else
		bin="$work/$asset"
		log "note: $VULNA_BIN_DIR not writable; running the verified binary in place"
	fi

	if [ -n "$VULNA_SERVER" ] && [ -n "$VULNA_ENROLL_TOKEN" ]; then
		log "enrolling with $VULNA_SERVER"
		# Token via environment, consumed by `enroll`; not passed on the command line.
		VULNASCOUT_ENROLL_TOKEN="$VULNA_ENROLL_TOKEN" "$bin" enroll --server "$VULNA_SERVER"
		log "enrolled. Start the Scout with: $bin run"
	else
		log "installed. Enroll with: VULNASCOUT_ENROLL_TOKEN=<token> $bin enroll --server <url>"
	fi
}

main "$@"
