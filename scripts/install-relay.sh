#!/bin/sh
# Verified VulnaRelay bootstrap. Installs the scanner-free WireGuard endpoint
# agent, enrolls it with a one-time token, and starts a hardened systemd service.
set -eu

VULNA_VERSION="${VULNA_VERSION:-v1.0.0}"
VULNA_BASE_URL="${VULNA_BASE_URL:-https://github.com/codebooker/vulna/releases/download/${VULNA_VERSION}}"
VULNA_RELEASE_PUBKEY="${VULNA_RELEASE_PUBKEY:-}"
VULNA_SERVER="${VULNA_SERVER:-}"
VULNA_RELAY_TOKEN="${VULNA_RELAY_TOKEN:-}"
VULNA_SERVER_CA="${VULNA_SERVER_CA:-}"
VULNA_SERVER_CA_B64="${VULNA_SERVER_CA_B64:-}"
VULNA_BIN_DIR="${VULNA_BIN_DIR:-/usr/local/bin}"
VULNA_RELAY_STATE_DIR="${VULNA_RELAY_STATE_DIR:-/var/lib/vulna-relay}"
OPENSSL="${OPENSSL:-openssl}"
VULNA_EMBEDDED_PUBKEY='__VULNA_RELEASE_PUBKEY_PEM__'

log() { echo "install-relay: $*" >&2; }
die() { echo "install-relay: $*" >&2; exit 1; }
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
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "unsupported architecture: $arch (supported: amd64, arm64)" ;;
	esac
	[ "$os" = linux ] || die "unsupported OS: $os (Linux is required for WireGuard routing)"
	echo "vulnarelay_${VULNA_VERSION}_${os}_${arch}"
}

install_runtime_dependencies() {
	[ "${VULNA_RELAY_SKIP_RUNTIME_CHECK:-0}" = 1 ] && return 0
	missing=""
	for tool in wg ip iptables ping; do
		command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
	done
	[ -z "$missing" ] && return 0
	if command -v apt-get >/dev/null 2>&1; then
		log "installing WireGuard networking dependencies"
		DEBIAN_FRONTEND=noninteractive apt-get update -qq
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
			wireguard-tools iproute2 iptables iputils-ping ca-certificates curl openssl
	elif command -v apk >/dev/null 2>&1; then
		apk add --no-cache wireguard-tools iproute2 iptables iputils ca-certificates curl openssl
	else
		die "missing runtime tools:$missing; install WireGuard tools, iproute2, iptables, and ping"
	fi
}

main() {
	if [ "$(id -u)" -ne 0 ] && [ "${VULNA_RELAY_INSTALL_ONLY:-0}" != 1 ]; then
		die "run this installer as root"
	fi
	need "$OPENSSL"
	need sha256sum
	need curl
	install_runtime_dependencies

	asset="$(detect_asset)"
	work="$(mktemp -d)"
	trap 'rm -rf "$work"' EXIT
	resolve_pubkey "$work/release.pub"
	curl -fsSLo "$work/$asset" "$VULNA_BASE_URL/$asset"
	curl -fsSLo "$work/SHA256SUMS" "$VULNA_BASE_URL/SHA256SUMS"
	curl -fsSLo "$work/SHA256SUMS.sig" "$VULNA_BASE_URL/SHA256SUMS.sig"
	if ! "$OPENSSL" pkeyutl -verify -pubin -inkey "$work/release.pub" -rawin \
		-in "$work/SHA256SUMS" -sigfile "$work/SHA256SUMS.sig" >/dev/null 2>&1; then
		die "SIGNATURE INVALID for SHA256SUMS — refusing to install"
	fi
	if ! (cd "$work" && grep " $asset\$" SHA256SUMS | sha256sum -c - >/dev/null 2>&1); then
		die "CHECKSUM MISMATCH for $asset — refusing to install"
	fi
	install -m 0755 "$work/$asset" "$VULNA_BIN_DIR/vulnarelay"
	install -d -m 0700 "$VULNA_RELAY_STATE_DIR"
	server_ca_path=""
	if [ -n "$VULNA_SERVER_CA_B64" ]; then
		need base64
		printf '%s' "$VULNA_SERVER_CA_B64" | base64 -d >"$VULNA_RELAY_STATE_DIR/server-ca.pem"
		chmod 0644 "$VULNA_RELAY_STATE_DIR/server-ca.pem"
		server_ca_path="$VULNA_RELAY_STATE_DIR/server-ca.pem"
	elif [ -n "$VULNA_SERVER_CA" ]; then
		install -m 0644 "$VULNA_SERVER_CA" "$VULNA_RELAY_STATE_DIR/server-ca.pem"
		server_ca_path="$VULNA_RELAY_STATE_DIR/server-ca.pem"
	fi

	if [ "${VULNA_RELAY_INSTALL_ONLY:-0}" = 1 ]; then
		log "verified relay binary installed without enrollment"
		return 0
	elif [ -n "$VULNA_SERVER" ] && [ -n "$VULNA_RELAY_TOKEN" ]; then
		if [ -n "$server_ca_path" ]; then
			VULNA_RELAY_TOKEN="$VULNA_RELAY_TOKEN" "$VULNA_BIN_DIR/vulnarelay" enroll \
				--server "$VULNA_SERVER" --state-dir "$VULNA_RELAY_STATE_DIR" \
				--server-ca "$server_ca_path"
		else
			VULNA_RELAY_TOKEN="$VULNA_RELAY_TOKEN" "$VULNA_BIN_DIR/vulnarelay" enroll \
				--server "$VULNA_SERVER" --state-dir "$VULNA_RELAY_STATE_DIR"
		fi
	else
		die "VULNA_SERVER and VULNA_RELAY_TOKEN are required for enrollment"
	fi

	if command -v systemctl >/dev/null 2>&1; then
		if [ -n "$server_ca_path" ]; then
			service_ca_arg="--server-ca $server_ca_path"
		else
			service_ca_arg=""
		fi
		cat >/etc/systemd/system/vulnarelay.service <<EOF
[Unit]
Description=VulnaRelay scanner-free WireGuard endpoint
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$VULNA_BIN_DIR/vulnarelay run --state-dir $VULNA_RELAY_STATE_DIR $service_ca_arg
ExecStop=$VULNA_BIN_DIR/vulnarelay stop
Restart=always
RestartSec=5
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$VULNA_RELAY_STATE_DIR

[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable --now vulnarelay
		log "installed and started vulnarelay.service"
	else
		log "installed; start manually: $VULNA_BIN_DIR/vulnarelay run --state-dir $VULNA_RELAY_STATE_DIR${server_ca_path:+ --server-ca $server_ca_path}"
	fi
}

main "$@"
