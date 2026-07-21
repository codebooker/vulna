#!/bin/sh
# Privileged disposable test of the real WireGuard Relay data plane.
set -eu
umask 077

[ "$(id -u)" -eq 0 ] || {
	echo "relay integration test must run as root" >&2
	exit 1
}

if [ -n "${VULNA_REPO_ROOT:-}" ]; then
	ROOT="$VULNA_REPO_ROOT"
else
	unset CDPATH
	ROOT="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
fi
CONTROLLER="$ROOT/deploy/relay-egress/controller.sh"
WORK="$(mktemp -d)"
STATE="$WORK/state"
mkdir -p "$STATE"

cleanup() {
	ip netns del vulna-relay-hub 2>/dev/null || true
	ip netns del vulna-relay-a 2>/dev/null || true
	ip netns del vulna-relay-b 2>/dev/null || true
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

for namespace in vulna-relay-hub vulna-relay-a vulna-relay-b; do
	ip netns add "$namespace"
	ip -n "$namespace" link set lo up
done

ip link add hub-a type veth peer name site-a
ip link set hub-a netns vulna-relay-hub
ip link set site-a netns vulna-relay-a
ip -n vulna-relay-hub address add 192.0.2.1/30 dev hub-a
ip -n vulna-relay-a address add 192.0.2.2/30 dev site-a
ip -n vulna-relay-hub link set hub-a up
ip -n vulna-relay-a link set site-a up

ip link add hub-b type veth peer name site-b
ip link set hub-b netns vulna-relay-hub
ip link set site-b netns vulna-relay-b
ip -n vulna-relay-hub address add 192.0.2.5/30 dev hub-b
ip -n vulna-relay-b address add 192.0.2.6/30 dev site-b
ip -n vulna-relay-hub link set hub-b up
ip -n vulna-relay-b link set site-b up

wg genkey >"$STATE/server.key"
wg pubkey <"$STATE/server.key" >"$STATE/server.pub"
wg genkey >"$WORK/site-a.key"
wg pubkey <"$WORK/site-a.key" >"$WORK/site-a.pub"
wg genkey >"$WORK/site-b.key"
wg pubkey <"$WORK/site-b.key" >"$WORK/site-b.pub"
chmod 0600 "$STATE/server.key" "$WORK/site-a.key" "$WORK/site-b.key"

server_public="$(cat "$STATE/server.pub")"
site_a_public="$(cat "$WORK/site-a.pub")"
site_b_public="$(cat "$WORK/site-b.pub")"

for site in a b; do
	ip -n "vulna-relay-$site" link add wg0 type wireguard
	ip -n "vulna-relay-$site" link set wg0 up
done
ip -n vulna-relay-a address add 10.255.0.2/32 dev wg0
ip -n vulna-relay-b address add 10.255.0.3/32 dev wg0
ip -n vulna-relay-a address add 10.10.0.10/32 dev lo
ip -n vulna-relay-b address add 10.20.0.10/32 dev lo
ip -n vulna-relay-b address add 10.20.0.99/32 dev lo

ip netns exec vulna-relay-a wg set wg0 \
	private-key "$WORK/site-a.key" listen-port 51821 \
	peer "$server_public" allowed-ips 10.255.0.1/32 \
	endpoint 192.0.2.1:51820 persistent-keepalive 1
ip netns exec vulna-relay-b wg set wg0 \
	private-key "$WORK/site-b.key" listen-port 51822 \
	peer "$server_public" allowed-ips 10.255.0.1/32 \
	endpoint 192.0.2.5:51820 persistent-keepalive 1
ip -n vulna-relay-a route add 10.255.0.1/32 dev wg0
ip -n vulna-relay-b route add 10.255.0.1/32 dev wg0

write_config() {
	include_a="$1"
	jq -n \
		--arg a "$site_a_public" \
		--arg b "$site_b_public" \
		--argjson include_a "$include_a" \
		'{
			server_address: "10.255.0.1/24",
			listen_port: 51820,
			peers: ((if $include_a then [{
				public_key: $a,
				tunnel_address: "10.255.0.2/32",
				approved_cidrs: ["10.10.0.0/24"],
				denied_cidrs: []
			}] else [] end) + [{
				public_key: $b,
				tunnel_address: "10.255.0.3/32",
				approved_cidrs: ["10.20.0.0/24"],
				denied_cidrs: ["10.20.0.99/32"]
			}])
		}' >"$WORK/config.json"
}

run_controller() {
	url="${1:-file://$WORK/config.json}"
	ip netns exec vulna-relay-hub env \
		VULNA_RELAY_EGRESS_API_URL="$url" \
		VULNA_RELAY_EGRESS_TOKEN=integration-test \
		VULNA_RELAY_STATE_DIR="$STATE" \
		VULNA_RELAY_INTERFACE=vulna-wg0 \
		VULNA_RELAY_RECONCILE_ONCE=true \
		sh "$CONTROLLER"
}

wait_for_handshake() {
	namespace="$1"
	interface="$2"
	peer="$3"
	attempt=0
	while [ "$attempt" -lt 10 ]; do
		handshake="$(ip netns exec "$namespace" wg show "$interface" latest-handshakes \
			| awk -v peer="$peer" '$1 == peer {print $2}')"
		[ "${handshake:-0}" -gt 0 ] && return 0
		attempt=$((attempt + 1))
		sleep 1
	done
	echo "Relay peer did not complete a WireGuard handshake" >&2
	return 1
}

write_config true
run_controller
wait_for_handshake vulna-relay-a wg0 "$server_public"
wait_for_handshake vulna-relay-b wg0 "$server_public"
ip netns exec vulna-relay-a ping -q -c 2 -W 2 10.255.0.1 >/dev/null
ip netns exec vulna-relay-b ping -q -c 2 -W 2 10.255.0.1 >/dev/null
ip netns exec vulna-relay-hub ping -q -c 2 -W 2 10.10.0.10 >/dev/null
ip netns exec vulna-relay-hub ping -q -c 2 -W 2 10.20.0.10 >/dev/null

if ip netns exec vulna-relay-hub ping -q -c 1 -W 1 10.20.0.99 >/dev/null 2>&1; then
	echo "denied Relay address unexpectedly passed the egress filter" >&2
	exit 1
fi

capture="$WORK/relay.pcap.txt"
ip netns exec vulna-relay-hub timeout 4 tcpdump -ln -i vulna-wg0 icmp >"$capture" 2>&1 &
capture_pid=$!
sleep 1
ip netns exec vulna-relay-hub ping -q -c 1 -W 2 10.10.0.10 >/dev/null
wait "$capture_pid" || true
grep -q '10.10.0.10' "$capture" || {
	echo "packet capture did not observe traffic on the WireGuard interface" >&2
	exit 1
}

for peer in "$site_a_public" "$site_b_public"; do
	handshake="$(ip netns exec vulna-relay-hub wg show vulna-wg0 latest-handshakes \
		| awk -v peer="$peer" '$1 == peer {print $2}')"
	[ "${handshake:-0}" -gt 0 ] || {
		echo "Relay peer did not complete a WireGuard handshake" >&2
		exit 1
	}
done

# Revoking site A removes both its peer and route without disrupting site B.
write_config false
run_controller
if ip netns exec vulna-relay-hub wg show vulna-wg0 peers | grep -Fxq "$site_a_public"; then
	echo "revoked Relay peer remains installed" >&2
	exit 1
fi
ip -n vulna-relay-hub route show 10.10.0.0/24 | grep -q . && {
	echo "revoked Relay route remains installed" >&2
	exit 1
}
ip netns exec vulna-relay-hub ping -q -c 1 -W 1 10.20.0.10 >/dev/null

# A controller/API outage removes every peer and route immediately.
if run_controller "file://$WORK/missing.json"; then
	echo "failed Relay configuration fetch unexpectedly succeeded" >&2
	exit 1
fi
[ -z "$(ip netns exec vulna-relay-hub wg show vulna-wg0 peers)" ] || {
	echo "Relay fail-closed path left a peer installed" >&2
	exit 1
}
[ -z "$(ip -n vulna-relay-hub route show 10.20.0.0/24)" ] || {
	echo "Relay fail-closed path left a route installed" >&2
	exit 1
}

# Reconciliation after restart restores only the current authoritative peer.
# Re-applying the site's authoritative peer state forces a fresh handshake just
# as its agent does after observing a central data-plane restart.
run_controller
ip netns exec vulna-relay-b wg set wg0 peer "$server_public" remove
ip netns exec vulna-relay-b wg set wg0 \
	peer "$server_public" allowed-ips 10.255.0.1/32 \
	endpoint 192.0.2.5:51820 persistent-keepalive 1
wait_for_handshake vulna-relay-hub vulna-wg0 "$site_b_public"
ip netns exec vulna-relay-b ping -q -c 2 -W 2 10.255.0.1 >/dev/null
ip netns exec vulna-relay-hub ping -q -c 2 -W 2 10.20.0.10 >/dev/null

echo "relay WireGuard data-plane integration: PASS"
