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
  to its **approved CIDRs**; out-of-scope destinations are blocked. The decision is
  fail-closed and authoritative on the central side.
- **Kill switch.** Tearing the tunnel — or an administrator engaging the kill
  switch — immediately blocks all scanning through the relay. A killed relay's
  heartbeat is refused so the tunnel stays down.
- **No secrets on the relay.** Enrollment issues only an mTLS control certificate;
  the relay **never** receives job-signing private keys or scanner credentials. It
  carries traffic, nothing more.
- **mTLS control channel.** The relay enrolls with a single-use token and a CSR,
  reusing the same enrollment + mutual-TLS machinery as Scouts.

## Setup

1. **Enable relay mode** — Settings → VulnaRelay → *Enable relay mode* (admin).
2. **Add a relay** — generate an enrollment command (shown once) and run it on the
   relay host. It installs the tunnel-only relay image (no scanners).
3. **Approve an egress scope** — set the relay's approved CIDRs. Only these
   destinations are reachable through the relay.
4. **Bring the tunnel up** — the relay heartbeats its tunnel state; the central
   egress opens for in-scope targets only.

## Kill switch

Engage the kill switch from the relay list at any time. It sets the relay to
`killed`, tears the tunnel, and blocks all scanning immediately. Use *Resume* to
clear it.
