# ADR 0016: VulnaRelay (optional thin-site tunnel mode)

- **Status:** Accepted
- **Date:** 2026-07-11
- **Phase:** 16 (VulnaRelay — optional tunnel/relay mode)

## Context

Some sites are too constrained to run scanners, or an operator wants central scan
origination. VulnaRelay serves them with a thin tunnel appliance: the site runs a
minimal authenticated tunnel with no scanners, and a central scanner reaches the
site through it. This trades the smart VulnaScout probe's **local** cryptographic
scope/kill-switch boundary for lighter site hardware, so it is specialized and
must not become the default. It was deferred until there was demand.

## Decisions

### 1. Off by default; the smart probe stays the default

Relay mode is disabled unless an administrator explicitly enables it in settings
(stored in the organization's `settings_json`, no schema change). Every relay
operation is refused while disabled. The smart VulnaScout probe — which enforces
its signed scope and kill switch locally — remains the recommended deployment.

### 2. Scope is enforced at the central egress

A relay has no local boundary, so scope enforcement moves to the central side.
`app/services/relay.egress_decision` is the authority: it **fails closed**,
allowing scan traffic to a target only when the relay is `ENROLLED`, its tunnel is
up, and the target is within the relay's approved CIDRs and not in a denied range.
Every block states why. The pure decision is unit-tested; a deployment's egress
packet filter is generated from the same approved CIDRs.

### 3. Kill switch is immediate and authoritative

An administrator can engage the kill switch, which sets the relay to `KILLED`,
tears the tunnel, and blocks all egress. A killed relay's heartbeat is refused so
the tunnel cannot come back up until an admin resumes it.

### 4. The relay never holds secrets

Enrollment reuses the single-use token + CSR + mutual-TLS machinery (as Scouts do)
and issues only an mTLS control certificate. The registration response contains
the control certificate and CA only — **never** job-signing private keys or
scanner credentials. A relay runs no scanners and therefore needs neither.

### 5. Control channel and lifecycle

A `Relay` record tracks status (`pending_enrollment` / `enrolled` / `killed` /
`revoked`), the mTLS certificate fingerprint, the relay's WireGuard public key
(non-secret), the live tunnel state, and the approved/denied egress CIDRs.
Heartbeat authenticates over the same trusted-proxy mTLS-fingerprint mechanism as
Scouts.

## Security constraints (how they are met)

- **Out-of-scope blocked at egress** — `egress_decision` refuses any target outside
  the approved CIDRs.
- **Kill switch stops scanning immediately** — killed status blocks egress and
  refuses heartbeats.
- **No signing keys / scanner credentials on the relay** — the enrollment response
  excludes them by construction (tested).
- **Default remains the smart probe** — relay mode is strictly opt-in.

## Consequences

- A site with no scanners can be assessed end to end through a relay, within its
  approved scope, with an immediate kill switch.
- The relay is a low-trust traffic carrier; the central deployment holds all
  scanning secrets and enforces all scope.

## Scope note

The backend control plane and the fail-closed egress/kill-switch logic are
implemented and tested here. The relay appliance image (a WireGuard tunnel
endpoint with no scanners) and the central egress packet filter that consumes the
approved CIDRs are deployment artifacts documented in `docs/relay.md`; the backend
is the policy authority they enforce.

## Alternatives considered

- **Enforcing scope on the relay.** Rejected: the whole point of a relay is that
  the site is too constrained for a local cryptographic boundary. Central egress
  enforcement is the correct trust placement.
- **Making relay a first-class default path.** Rejected by the constraint that the
  smart probe stays the default; relay is opt-in and off by default.
