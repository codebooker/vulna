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
# Path to the pinned Ed25519 release public key (PEM). Release builds embed this
# below; for a mirror or testing set VULNA_RELEASE_PUBKEY to a local PEM path.
VULNA_RELEASE_PUBKEY="${VULNA_RELEASE_PUBKEY:-}"
VULNA_BIN_DIR="${VULNA_BIN_DIR:-/usr/local/bin}"
# Directory the deployment bundle (Compose files + overlay) is extracted into so
# `vulna install` has the files it needs.
VULNA_DIR="${VULNA_DIR:-$(pwd)/vulna}"
OPENSSL="${OPENSSL:-openssl}"

# The official hosted installer embeds the pinned release public key here: the
# release pipeline (deploy/release/embed-release-pubkey.sh) replaces the
# placeholder token with the standard PEM public key. When still the placeholder,
# fall back to $VULNA_RELEASE_PUBKEY.
VULNA_EMBEDDED_PUBKEY='__VULNA_RELEASE_PUBKEY_PEM__'

# resolve_pubkey writes the release public key PEM to $1, preferring the embedded
# key and falling back to $VULNA_RELEASE_PUBKEY. Dies if neither is available.
# The embedded value is a real PEM only in the official hosted installer (the
# release pipeline substitutes it), so detect it by its PEM header rather than by
# the placeholder token — that keeps substitution limited to the assignment.
resolve_pubkey() {
	out="$1"
	case "$VULNA_EMBEDDED_PUBKEY" in
	-----BEGIN*PUBLIC*KEY-----*)
		printf '%s\n' "$VULNA_EMBEDDED_PUBKEY" >"$out"
		;;
	*)
		# Not an official hosted installer: require an explicit key.
		[ -n "$VULNA_RELEASE_PUBKEY" ] || die "no pinned release public key. The official \
hosted installer embeds it; for a mirror set VULNA_RELEASE_PUBKEY to the Ed25519 public key PEM path."
		[ -f "$VULNA_RELEASE_PUBKEY" ] || die "release public key not found: $VULNA_RELEASE_PUBKEY"
		cp "$VULNA_RELEASE_PUBKEY" "$out"
		;;
	esac
}

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

	asset="$(detect_asset)"
	work="$(mktemp -d)"
	trap 'rm -rf "$work"' EXIT

	resolve_pubkey "$work/release.pub"

	log "downloading manifest ($VULNA_VERSION)"
	fetch "$VULNA_BASE_URL/SHA256SUMS" "$work/SHA256SUMS"
	fetch "$VULNA_BASE_URL/SHA256SUMS.sig" "$work/SHA256SUMS.sig"

	# Authenticity: Ed25519 signature over the checksum manifest. Everything else
	# is then trusted only via this now-verified manifest.
	if ! "$OPENSSL" pkeyutl -verify -pubin -inkey "$work/release.pub" -rawin \
		-in "$work/SHA256SUMS" -sigfile "$work/SHA256SUMS.sig" >/dev/null 2>&1; then
		die "SIGNATURE INVALID for SHA256SUMS — refusing to run downloaded artifacts"
	fi
	log "manifest signature verified"

	# fetch_verified <name>: download an asset and confirm its checksum against
	# the verified manifest. Refuses anything not listed or mismatched.
	fetch_verified() {
		name="$1"
		grep -q " $name\$" "$work/SHA256SUMS" || die "$name is not listed in the signed manifest"
		log "downloading $name"
		fetch "$VULNA_BASE_URL/$name" "$work/$name"
		(cd "$work" && grep " $name\$" SHA256SUMS | sha256sum -c - >/dev/null 2>&1) ||
			die "CHECKSUM MISMATCH for $name — refusing to use downloaded artifact"
	}

	fetch_verified "$asset"
	chmod +x "$work/$asset"

	if [ -w "$VULNA_BIN_DIR" ]; then
		install -m 0755 "$work/$asset" "$VULNA_BIN_DIR/vulna"
		log "installed to $VULNA_BIN_DIR/vulna"
		bin="$VULNA_BIN_DIR/vulna"
	else
		log "note: $VULNA_BIN_DIR not writable; running the verified binary in place"
		bin="$work/$asset"
	fi

	# For `install`, the CLI needs the deployment files (Compose + single-host
	# overlay). Fetch and verify the deployment bundle, extract it, and run from
	# there so the operator is not left with a binary that can't find its files.
	if [ "${1:-}" = "install" ]; then
		bundle="vulna-deploy_${VULNA_VERSION}.tar.gz"
		fetch_verified "$bundle"
		mkdir -p "$VULNA_DIR"
		tar -xzf "$work/$bundle" -C "$VULNA_DIR"
		log "deployment files extracted to $VULNA_DIR"
		# Run install from the deployment directory unless the caller set --dir.
		case " $* " in
		*" --dir "*) : ;;
		*) set -- "$@" --dir "$VULNA_DIR" ;;
		esac
	fi

	# Pass through the caller's arguments to the verified CLI.
	exec "$bin" "$@"
}

# Strip a leading `--` separator so `sh install.sh -- install ...` works.
if [ "${1:-}" = "--" ]; then shift; fi
main "$@"
