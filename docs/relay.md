# VulnaRelay (advanced, opt-in)

VulnaRelay is a **thin-site tunnel** mode for constrained sites: instead of
running scanners at the edge, the site runs a minimal authenticated tunnel with
**no scanners**, and a central scanner reaches the site's network through it (the
"thin dropbox" model).

> **Off by default.** Relay mode must be turned on in Settings. The smart
> VulnaScout probe — which runs scanners at the edge and enforces its signed scope
> and kill switch **locally** — remains the default and recommended deployment.

See [ADR 0016](adr/0016-vulnarelay.md) and the deployment-models overview in the
[docs home](README.md).

## When to use it (and when not to)

Use VulnaRelay only for deliberate thin-site deployments: ultra-constrained
hardware that cannot run scanners, or a policy of central scan origination. It
trades the smart probe's **local** cryptographic scope/kill-switch boundary for
lighter site hardware.

Because a relay has no local boundary, its safety depends on the **central
egress** enforcing scope. Prefer the smart VulnaScout probe whenever the site can
run it.

## Safety model

- **Scope is enforced at the central egress.** A relay may only carry scan traffic
  to its **approved IPv4 CIDRs**; out-of-scope and explicitly denied destinations
  are blocked. The Relay also installs a matching allow/deny forwarding policy.
  Overlapping approved ranges on two active Relays are rejected because WireGuard
  cannot route the same destination safely to two peers.
- **Kill switch.** Tearing the tunnel — or an administrator engaging the kill
  switch — immediately blocks all scanning through the relay. A killed relay's
  heartbeat is refused so the tunnel stays down.
- **No secrets on the relay.** Enrollment issues only an mTLS control certificate;
  the relay **never** receives job-signing private keys or scanner credentials. It
  carries traffic, nothing more.
- **mTLS control channel.** The relay enrolls with a single-use token and a CSR,
  reusing the same enrollment + mutual-TLS machinery as Scouts.
- **Central-scanner binding.** Saving Relay scope makes the configured central
  scanner the primary Scout for that network. Other Scouts do not receive the
  Relay-managed ranges in their signed policy, and explicitly selecting another
  Scout does not bypass that restriction.

## Requirements

- A Linux `amd64` or `arm64` endpoint at the remote site.
- Root access for WireGuard, IP forwarding, routing, and `iptables` rules.
- Outbound reachability from the Relay to the appliance's control URL and UDP
  WireGuard endpoint.
- TCP `8443` and UDP `51820` reachable on the appliance by default. Both are
  configurable.
- An enrolled central Scout named by `VULNA_RELAY_SCANNER_PROBE_NAME`
  (`local-scout` by default). The supported single-host deployment supplies it.

The verified installer supports `apt` and `apk` dependency installation. Other
Linux distributions must provide `wg`, `ip`, `iptables`, `ping`, `curl`, OpenSSL,
and CA certificates before enrollment.

## Install and link a Relay

1. Create the site in VulnaDash.
2. Open **Management → Appliances → Relay** and enable
   **Organization relay mode**. This is off on a fresh organization.
3. Select **Add Relay**, enter a name, choose the site, and generate the install
   command.
4. Run the displayed command as root on the remote endpoint. It downloads the
   exact release's `install-relay.sh`, verifies the Ed25519-signed checksum
   manifest and binary checksum, installs `vulnarelay`, consumes the one-time
   enrollment token, and starts `vulnarelay.service`.
5. Return to the Relay tab and wait for the endpoint to show **Tunnel up**.

The dashboard command is authoritative because it includes the correct release,
control URL, token, and private CA material when required. Its general form is:

```sh
curl -fsSLo /tmp/install-relay.sh \
  https://github.com/codebooker/vulna/releases/download/vX.Y.Z/install-relay.sh
VULNA_SERVER=https://vulna.example.com:8443 \
  VULNA_RELAY_TOKEN=replace-with-the-shown-token \
  VULNA_VERSION=vX.Y.Z sh /tmp/install-relay.sh
```

Do not reuse an example token. Enrollment tokens are short-lived, single-use,
and assigned to the site chosen when the command is generated.

## Configure scope and scan

For each Relay, enter comma-separated **Approved CIDRs** and optional
**Denied CIDRs**, then select **Save scope**. A deny wins whenever it overlaps a
requested target. Public ranges are rejected unless **Allow public addresses** is
explicitly enabled; that control is not evidence of authorization.

Saving scope creates managed network-scope records for the Relay's site and binds
that network to the appliance's central Scout. Create scans normally against that
network. The central Scout runs the scanner stages inside the Relay egress network
namespace, and matching traffic follows the WireGuard route.

The tunnel must be enrolled, current, and up at dispatch and egress time. A down,
killed, revoked, disabled, out-of-scope, or denied path fails closed.

## Kill switch

Engage the kill switch from the relay list at any time. It sets the relay to
`killed`, tears the tunnel, and blocks all scanning immediately. Use *Resume* to
clear it.

The organization switch is a broader emergency control: turning Relay mode off
blocks egress for every enrolled Relay without deleting their records.

## Revoke or replace a Relay

Use **Revoke** when an endpoint is retired, lost, or suspected compromised.
Revocation invalidates its certificate, tears down the tunnel, clears its ranges,
removes its managed network scopes, and increments the affected network policy.
Reinstalling the old certificate cannot restore access. To replace the endpoint,
generate a new Relay enrollment command and approve its scope again.

On the endpoint, `vulnarelay status` reports local state and `vulnarelay stop`
tears down its interface and forwarding rules. Central revocation remains the
authoritative retirement action.

## Troubleshooting

- **No enrolled central scanner:** confirm the appliance's local Scout is
  connected or update `VULNA_RELAY_SCANNER_PROBE_NAME` to the intended enrolled
  central Scout.
- **Tunnel never comes up:** verify the generated control URL, system time, CA
  trust, outbound UDP reachability, and the appliance's published Relay endpoint.
- **Approved scope will not save:** Relay scope is IPv4-only; remove overlaps with
  another Relay and confirm the central scanner exists.
- **Targets are rejected:** check the approved and denied ranges, public-address
  setting, organization switch, per-Relay kill switch, and tunnel status.
