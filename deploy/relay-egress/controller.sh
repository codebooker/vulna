#!/bin/sh
# Central WireGuard egress reconciler. It is the only privileged component in the
# Relay path: the scanner shares this network namespace but remains non-root and
# capability-free. Peer routes come exclusively from the API's validated scopes.
set -eu

API_URL="${VULNA_RELAY_EGRESS_API_URL:-http://api:8000/api/v1/relays/egress/config}"
TOKEN="${VULNA_RELAY_EGRESS_TOKEN:?VULNA_RELAY_EGRESS_TOKEN is required}"
STATE_DIR="${VULNA_RELAY_STATE_DIR:-/var/lib/vulna/relay}"
INTERFACE="${VULNA_RELAY_INTERFACE:-vulna-wg0}"
INTERVAL="${VULNA_RELAY_RECONCILE_SECONDS:-2}"
ONCE="${VULNA_RELAY_RECONCILE_ONCE:-false}"

mkdir -p "$STATE_DIR"
umask 077
if [ ! -s "$STATE_DIR/server.key" ]; then
	wg genkey >"$STATE_DIR/server.key"
fi
wg pubkey <"$STATE_DIR/server.key" >"$STATE_DIR/server.pub"
chmod 0600 "$STATE_DIR/server.key"
# The unprivileged API container reads only the public key from this shared,
# read-only volume when building endpoint configuration.
chmod 0644 "$STATE_DIR/server.pub"

cleanup_routes() {
	[ -f "$STATE_DIR/routes" ] || return 0
	while IFS= read -r cidr; do
		if [ -n "$cidr" ]; then
			ip route del "$cidr" dev "$INTERFACE" 2>/dev/null || true
		fi
	done <"$STATE_DIR/routes"
	: >"$STATE_DIR/routes"
}

fail_closed() {
	if ip link show "$INTERFACE" >/dev/null 2>&1; then
		for peer in $(wg show "$INTERFACE" peers); do
			wg set "$INTERFACE" peer "$peer" remove
		done
	fi
	cleanup_routes
}

apply_config() {
	config="$1"
	server_address="$(jq -er '.server_address' "$config")" || return 1
	listen_port="$(jq -er '.listen_port' "$config")" || return 1

	if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
		ip link add dev "$INTERFACE" type wireguard || return 1
	fi
	ip address replace "$server_address" dev "$INTERFACE" || return 1
	wg set "$INTERFACE" private-key "$STATE_DIR/server.key" listen-port "$listen_port" \
		|| return 1
	ip link set up dev "$INTERFACE" || return 1

	# Reconcile peers against the authoritative API snapshot. Remove only peers
	# that disappeared: deleting and re-adding every active peer each interval
	# discards WireGuard's learned endpoint and handshake state, preventing a
	# tunnel from ever becoming usable.
	desired_peers="$STATE_DIR/desired-peers"
	jq -r '.peers[].public_key' "$config" >"$desired_peers" || return 1
	for peer in $(wg show "$INTERFACE" peers); do
		grep -Fxq "$peer" "$desired_peers" \
			|| wg set "$INTERFACE" peer "$peer" remove || return 1
	done
	cleanup_routes || return 1
	iptables -N VULNA_RELAY_DENY 2>/dev/null || true
	iptables -F VULNA_RELAY_DENY || return 1
	iptables -C OUTPUT -o "$INTERFACE" -j VULNA_RELAY_DENY 2>/dev/null \
		|| iptables -I OUTPUT -o "$INTERFACE" -j VULNA_RELAY_DENY || return 1

	jq -c '.peers[]' "$config" | while IFS= read -r peer; do
		public_key="$(printf '%s' "$peer" | jq -er '.public_key')" || exit 1
		tunnel="$(printf '%s' "$peer" | jq -er '.tunnel_address')" || exit 1
		allowed="$tunnel"
		for cidr in $(printf '%s' "$peer" | jq -r '.approved_cidrs[]'); do
			allowed="$allowed,$cidr"
		done
		wg set "$INTERFACE" peer "$public_key" allowed-ips "$allowed" || exit 1
		for cidr in $(printf '%s' "$peer" | jq -r '.approved_cidrs[]'); do
			ip route replace "$cidr" dev "$INTERFACE" || exit 1
			printf '%s\n' "$cidr" >>"$STATE_DIR/routes" || exit 1
		done
		for cidr in $(printf '%s' "$peer" | jq -r '.denied_cidrs[]'); do
			iptables -A VULNA_RELAY_DENY -d "$cidr" -j REJECT || exit 1
		done
	done || return 1
	iptables -A VULNA_RELAY_DENY -j RETURN || return 1

	# Replies return through the tunnel address rather than the Docker bridge source.
	iptables -t nat -C POSTROUTING -o "$INTERFACE" -j MASQUERADE 2>/dev/null \
		|| iptables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE || return 1
}

while :; do
	status=0
	tmp="$STATE_DIR/config.tmp"
	if curl -fsS --max-time 10 -H "X-Vulna-Relay-Egress-Token: $TOKEN" \
		"$API_URL" -o "$tmp"; then
		if apply_config "$tmp"; then
			mv "$tmp" "$STATE_DIR/config.json"
		else
			echo "relay-egress: configuration apply failed; removing all peers/routes (fail closed)" >&2
			rm -f "$tmp"
			fail_closed
			status=1
		fi
	else
		echo "relay-egress: configuration fetch failed; removing all peers/routes (fail closed)" >&2
		rm -f "$tmp"
		fail_closed
		status=1
	fi
	[ "$ONCE" = "true" ] && exit "$status"
	sleep "$INTERVAL"
done
