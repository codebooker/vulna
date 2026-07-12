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
VULNA_SERVER_CA="${VULNA_SERVER_CA:-}"
VULNA_SERVER_CA_B64="${VULNA_SERVER_CA_B64:-}"
VULNA_SCOUT_STATE_DIR="${VULNA_SCOUT_STATE_DIR:-/var/lib/vulna}"
OPENSSL="${OPENSSL:-openssl}"
VULNA_EMBEDDED_PUBKEY='__VULNA_RELEASE_PUBKEY_PEM__'

log() { echo "install-scout: $*" >&2; }
die() { echo "install-scout: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }

resolve_pubkey() {
	out="$1"
	case "$VULNA_EMBEDDED_PUBKEY" in
	-----BEGIN*PUBLIC*KEY-----*) printf '%s\n' "$VULNA_EMBEDDED_PUBKEY" >"$out" ;;
	*)
		[ -n "$VULNA_RELEASE_PUBKEY" ] || die "official release installer is missing its embedded public key"
		[ -f "$VULNA_RELEASE_PUBKEY" ] || die "release public key not found: $VULNA_RELEASE_PUBKEY"
		cp "$VULNA_RELEASE_PUBKEY" "$out"
		;;
	esac
}

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

install_runtime_dependencies() {
	[ "${VULNA_SCOUT_SKIP_RUNTIME_CHECK:-0}" = 1 ] && return 0
	command -v nmap >/dev/null 2>&1 && return 0
	[ "$(id -u)" -eq 0 ] || {
		log "warning: Nmap is not installed; the Scout binary was installed without a scanner"
		return 0
	}
	if command -v apt-get >/dev/null 2>&1; then
		log "installing the standard discovery scanner (Nmap)"
		DEBIAN_FRONTEND=noninteractive apt-get update -qq
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nmap ca-certificates
	elif command -v apk >/dev/null 2>&1; then
		apk add --no-cache nmap nmap-scripts ca-certificates
	else
		die "Nmap is required for discovery scans; install it and run this installer again"
	fi
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

	log "downloading $asset ($VULNA_VERSION)"
	( cd "$work" && fetch "$VULNA_BASE_URL/$asset" "$asset" )
	fetch "$VULNA_BASE_URL/SHA256SUMS" "$work/SHA256SUMS"
	fetch "$VULNA_BASE_URL/SHA256SUMS.sig" "$work/SHA256SUMS.sig"

	# 1) Authenticity: Ed25519 signature over the checksum manifest.
	if ! "$OPENSSL" pkeyutl -verify -pubin -inkey "$work/release.pub" -rawin \
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
	install_runtime_dependencies

	if [ "${VULNA_SCOUT_INSTALL_ONLY:-0}" = 1 ]; then
		log "verified Scout binary installed without enrollment"
		return 0
	fi

	if [ -n "$VULNA_SERVER" ] && [ -n "$VULNA_ENROLL_TOKEN" ]; then
		[ "$(id -u)" -eq 0 ] || die "run as root to enroll and install the Scout service"
		if ! id vulna >/dev/null 2>&1; then
			if command -v useradd >/dev/null 2>&1; then
				useradd --system --home "$VULNA_SCOUT_STATE_DIR" --shell /usr/sbin/nologin vulna
			elif command -v adduser >/dev/null 2>&1; then
				addgroup -S vulna 2>/dev/null || true
				adduser -S -D -H -G vulna -h "$VULNA_SCOUT_STATE_DIR" -s /sbin/nologin vulna
			else
				die "cannot create the unprivileged vulna service user"
			fi
		fi
		install -d -m 0700 -o vulna -g vulna "$VULNA_SCOUT_STATE_DIR"
		server_ca_arg=""
		if [ -n "$VULNA_SERVER_CA_B64" ]; then
			need base64
			printf '%s' "$VULNA_SERVER_CA_B64" | base64 -d >"$VULNA_SCOUT_STATE_DIR/server-ca.pem"
			chmod 0644 "$VULNA_SCOUT_STATE_DIR/server-ca.pem"
			server_ca_arg="--server-ca $VULNA_SCOUT_STATE_DIR/server-ca.pem"
		elif [ -n "$VULNA_SERVER_CA" ]; then
			install -m 0644 "$VULNA_SERVER_CA" "$VULNA_SCOUT_STATE_DIR/server-ca.pem"
			server_ca_arg="--server-ca $VULNA_SCOUT_STATE_DIR/server-ca.pem"
		fi
		chown -R vulna:vulna "$VULNA_SCOUT_STATE_DIR"
		log "enrolling with $VULNA_SERVER"
		# Token via environment, consumed by `enroll`; not passed on the command line.
		if [ -n "$server_ca_arg" ]; then
			runuser -u vulna -- env VULNASCOUT_ENROLL_TOKEN="$VULNA_ENROLL_TOKEN" \
				"$bin" enroll --server "$VULNA_SERVER" --state-dir "$VULNA_SCOUT_STATE_DIR" \
				--server-ca "$VULNA_SCOUT_STATE_DIR/server-ca.pem"
		else
			runuser -u vulna -- env VULNASCOUT_ENROLL_TOKEN="$VULNA_ENROLL_TOKEN" \
				"$bin" enroll --server "$VULNA_SERVER" --state-dir "$VULNA_SCOUT_STATE_DIR"
		fi
		if command -v systemctl >/dev/null 2>&1; then
			cat >/etc/systemd/system/vulnascout.service <<EOF
[Unit]
Description=VulnaScout remote assessment agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vulna
Group=vulna
ExecStart=$bin run --server $VULNA_SERVER --state-dir $VULNA_SCOUT_STATE_DIR $server_ca_arg
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$VULNA_SCOUT_STATE_DIR

[Install]
WantedBy=multi-user.target
EOF
			systemctl daemon-reload
			systemctl enable --now vulnascout
			log "enrolled and started vulnascout.service"
		else
			log "enrolled. Start with: $bin run --state-dir $VULNA_SCOUT_STATE_DIR $server_ca_arg"
		fi
	else
		log "installed. Enroll with: VULNASCOUT_ENROLL_TOKEN=<token> $bin enroll --server <url>"
	fi
}

main "$@"
