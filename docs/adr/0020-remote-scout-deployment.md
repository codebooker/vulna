# ADR 0020: Frictionless Remote VulnaScout Deployment

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 20 (Frictionless Remote VulnaScout Deployment)

## Context

Adding the co-located local Scout is now one command (Phases 17–19). Adding a
Scout at a *second* site should be nearly as easy, while keeping the boundary that
makes remote Scouts safe: outbound-only communication, a private key that never
leaves the Scout, single-use hashed enrollment tokens, and locally-enforced signed
policy. Phase 20 wires the existing enrollment, packaging, and signing machinery
into a frictionless remote-deployment flow and adds the operational commands a
remote operator needs.

## Decisions

### 1. Per-site "Add VulnaScout" produces one copy-paste command

`POST /probes/enrollment-command` mints a single-use enrollment token for a site
(reusing the unchanged Phase 2 flow: high-entropy secret, only the SHA-256 hash
stored, short TTL) and returns ready-to-copy install commands plus a short code
for out-of-band verification. The token is passed to the installer via an
**environment variable, not argv**, so it does not linger in persistent process
listings after use. The response never exposes key material.

### 2. Convenience commands verify signatures before installing

Every install path routes through `scripts/install-scout.sh`, a thin bootstrap
that downloads a **pinned** VulnaScout release plus its `SHA256SUMS` manifest and
detached Ed25519 signature, verifies the signature and then the checksum, and only
then installs and enrolls. Unverified remote content is never piped into a shell.
This mirrors the Phase 18 dashboard bootstrap and satisfies the security
constraint against installing unverified releases. A smoke test proves it runs a
valid release and refuses a tampered artifact or signature.

### 3. A staged connection test with actionable remediation

`vulnascout doctor` runs the checks a remote operator actually needs — DNS, TLS
(with private-CA/MTU/firewall guidance), clock skew vs. the server's clock,
enrollment, mTLS heartbeat, local signed-policy presence, scanner health, and
authenticated result-upload reachability — and prints a concrete remediation for
each non-passing check covering the common causes (proxy, custom CA, DNS, clock,
MTU, outbound firewall). No token or key material appears in the output. Failed
enrollment gives an actionable reason without leaking secrets.

### 4. A local emergency stop that works offline

`vulnascout stop` writes a local `stop.flag` and `resume` clears it. The run loop
refuses to start and cancels any running job while the flag is present. This kill
switch is **purely local**: it needs no network and is authoritative even when the
orchestrator is unreachable or compromised — the local signed policy and this
switch, not the central service, are the last word on what a Scout does.

### 5. Reset self-revokes and wipes, preserving diagnostics

`vulnascout reset` makes a best-effort authenticated call to
`POST /probes/self-revoke` (mTLS) so the old identity is marked revoked centrally
and can no longer poll or upload, then deletes the local key, certificate, and
state so the host can re-enroll cleanly. Before wiping it preserves a **non-secret**
diagnostics snapshot (prior probe/site/fingerprint/timestamps). The private key is
removed in place — it never leaves the Scout. If the central call fails (offline),
the local wipe still happens and the operator is told to revoke in VulnaDash.

### 6. Site-network detection stays advisory

The remote Scout reports its private (RFC1918) ranges via the same heartbeat
mechanism as the local Scout (Phase 19 `netdetect`); the wizard suggests them but
never approves them. Enrollment does not authorize any target.

## Security constraints (how they are met)

- **Verify before install** — the bootstrap checks the Ed25519 signature and
  checksum before running anything (§2).
- **Enrollment ≠ authorization** — the command response and the wizard both state
  it; a scope must still be approved afterward (§1, §6).
- **Local authority** — the emergency stop and local signed policy remain
  authoritative even if the central service is unavailable or compromised (§4).
- **No inbound port** — all communication is Scout-initiated outbound; the flow
  opens nothing on the remote host.
- **Key custody** — the private key is generated on and never leaves the Scout;
  reset removes it locally.

## Consequences

- A supported remote host installs and enrolls from one copied command.
- Revoking or resetting a Scout stops the old identity from polling or uploading.
- Operators can diagnose connectivity failures and stop a Scout without the
  dashboard.

## Rollback / migration

Additive: the enrollment-command and self-revoke endpoints and the new Scout
subcommands do not change existing behavior. The one new backend setting
(`public_base_url`) is optional and falls back to the request base URL. Existing
Scouts and tokens are unaffected.

## Alternatives considered

- **Passing the token on the command line.** Rejected: argv is visible in process
  listings; the token goes through the environment and is consumed once.
- **A server-driven remote kill.** Kept as revoke, but the *local* emergency stop
  is the authoritative fail-safe precisely because it does not depend on the
  central service being reachable or trustworthy.
- **Embedding scanners in the base image only.** Unchanged from Phase 17; the
  standard pack is documented and `doctor` reports missing scanners as warnings.
