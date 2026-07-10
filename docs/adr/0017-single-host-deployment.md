# ADR 0017: First-Class Single-Host Deployment

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 17 (First-Class Single-Host Deployment)

## Context

The self-hoster-first roadmap makes a one-machine deployment the default, fully
supported starting point: a non-expert should reach the login page and have a
working local VulnaScout **without** manually creating a site, an enrollment
token, or a Scout record — while the local Scout still enforces exactly the same
signed policy, job signatures, certificate identity, scope, expiration,
cancellation, and least-privilege controls as a remote Scout (roadmap Phase 17).

## Decisions

### 1. Auto-enrollment via an internal one-time token on a shared file, not the browser

On first-run bootstrap (when the single-host profile sets
`VULNA_BOOTSTRAP_LOCAL_SCOUT=1`), VulnaDash ensures a default site exists, mints a
**single-use, auto-approve** enrollment token, and writes the token secret to a
file in a bootstrap directory (`/var/lib/vulna/bootstrap/local-scout-enroll.token`,
mode 0600) shared read-only with the local Scout container. The local Scout reads
it on first boot and enrolls (generating its own key + CSR). The token is
**single-use server-side** — consumed the moment it is redeemed — so the file that
lingers on the volume is a spent, unusable secret; the Scout mounts the volume
read-only and cannot (and need not) delete it. The secret never passes through the
API response, the UI, or browser logs. This is the "internal one-time enrollment
mechanism that is never reused or exposed in browser logs."

### 2. Auto-approve the local Scout, but never auto-approve a scope

The token carries an `auto_approve` flag; enrolling with it yields an **enrolled**
(not pending-approval) probe, because the local Scout on the operator's own host
is trusted to connect. But it gets **no approved network scope** — the operator
must still explicitly approve one (a hard safety rule: suggested ranges are never
authorized automatically). So auto-enrollment produces a connected-but-idle Scout
that can scan nothing until the operator approves a scope, and the Scout still
rejects any out-of-scope target locally.

### 3. Enrollment automation does not bypass any security control

Auto-enrollment reuses the ordinary enrollment path: a real CSR, a CA-signed
client certificate whose private key never leaves the Scout, signed local policy,
signed jobs, job expiry, and scope checks all apply unchanged. The only
difference from a remote Scout is where the one-time token comes from (an internal
file vs. an admin-minted token in the UI) and that it is auto-approved. The
`auto_approve` path is gated to token consumption; it cannot approve a scope,
widen a policy, or skip signing.

### 4. Same mTLS boundary, verified in both directions

The co-located Scout authenticates through the same Caddy reverse proxy as a
remote Scout: Caddy terminates mutual TLS, verifies the Scout's client
certificate against the internal CA, and forwards the verified fingerprint to the
API. The single-host Caddyfile uses client-auth mode **`verify_if_given`**, not
`require_and_verify`: enrollment (`POST /probes/enroll`) is certless by design —
a fresh probe has no certificate yet — so requiring a client certificate at the
TLS layer would make enrollment impossible, while `verify_if_given` still rejects
a rogue or self-signed certificate at the handshake and heartbeat/poll endpoints
still reject a certless request at the application layer (no fingerprint → 401).
`request` is not used (it does not verify at all).

For the reverse direction, the Scout **verifies the orchestrator's TLS** rather
than skipping it: a one-shot init copies Caddy's *public* internal root CA (which
Caddy stores root-only) to the shared bootstrap volume, world-readable, and the
Scout pins it as its server CA. Caddy's CA private key is never shared with the
Scout. To materialize the trust before the proxy loads it, first-run bootstrap
eagerly creates the internal CA (otherwise it is created lazily on first
enrollment, after the proxy has already tried to read its trust pool).

The API container applies database migrations (`alembic upgrade head`, idempotent)
at startup before serving, so a fresh single-host stack comes up with no manual
migration step — no mystery "relation does not exist" failure. Advanced operators
who run migrations as a separate job opt out with `VULNA_RUN_MIGRATIONS=false`.

### 5. Least privilege: no Docker socket, isolated scanner boundary, split volumes

VulnaDash and its workers run with **no scanner network capabilities** and **no
Docker socket**. The local Scout/scanner service is the only component that needs
network reach for discovery, and it holds **no** database credentials, signing
keys, or report keys — only its own enrolled identity. Persistent state is split
across separate named volumes (database, queue, reports, evidence, Scout state,
certificates/CA, config, bootstrap) so recreating application containers never
loses identity, findings, reports, or Scout state. No component runs privileged.

### 6. Standard capability pack; heavy/intrusive off by default

The single-host Scout image bundles the **standard safe pack** — Nmap, safe
Nuclei checks, and testssl.sh TLS checks. Active ZAP profiles and Metasploit are
**not** in the default image and are disabled by default, consistent with the
cross-phase safe-defaults rule. Missing capabilities degrade gracefully (a stage
is skipped with an explanation), never a mysterious failure.

### 7. Clean local-to-distributed growth path

Single-host uses the same data model and enrollment mechanism as a distributed
deployment. Adding a remote Scout later is the normal `Add VulnaScout` flow
against the same database and organization — no migration, no asset/finding loss,
no deployment-model change. The single-host profile is a packaging choice, not a
different product.

## Secret / volume / capability / trust-transition inventory

- **Secrets:** DB password, `VULNA_SECRET_KEY` (session/JWT), internal CA key,
  Ed25519 job-signing key, the one-time local-Scout token. Only VulnaDash/workers
  see the app secrets; only the Scout sees its own key and the one-time token.
- **Volumes:** `postgres_data`, `redis_data`, `reports`, `evidence`,
  `scout_state`, `keys` (internal CA + Ed25519 signing keys), `caddy_data` /
  `caddy_config`, and `bootstrap` (token + published orchestrator CA hand-off,
  Scout-readable). `bootstrap` is the only volume shared between VulnaDash (writer)
  and the Scout (reader); `keys` is shared with Caddy **read-only** so it can load
  the CA into its mTLS trust pool (the CA private key never reaches the Scout).
- **Capabilities:** VulnaDash/workers drop all; the Scout runs unprivileged
  (Nmap connect-scan, no raw sockets) with only its data/state paths writable.
- **Trust transitions:** bootstrap writes token → Scout reads token (one-time) →
  Scout enrolls (CSR → CA-signed cert) → token consumed + auto-approved → Scout
  polls signed jobs and enforces signed scope. No transition weakens signing,
  scope, or least privilege.

## Consequences

- A fresh single-host deployment reaches login with a connected local Scout and no
  manual object creation, while the Scout stays scope-gated and least-privileged.
- Recreating application containers is safe; identity and data persist on volumes.
- The same deployment grows to distributed Scouts without a data migration.

## Rollback / migration for existing distributed installs

The single-host behavior is entirely opt-in via `VULNA_BOOTSTRAP_LOCAL_SCOUT`.
Existing distributed installations leave it unset and are unaffected — bootstrap
does not create a default site or local Scout, and the `auto_approve` column
defaults to false for every existing token. Reverting the single-host profile to
distributed is a compose change; the database is unchanged.

## Alternatives considered

- **Passing the enrollment token via an environment variable to the Scout:**
  rejected; env vars leak into `docker inspect`, process listings, and logs. A
  0600 file on a dedicated volume, consumed once, is tighter.
- **Auto-approving a default local scope for zero-click scanning:** rejected
  outright; it violates the rule that scope is never authorized automatically and
  would let a fresh install scan a network the operator never approved.
- **Running the Scout inside the VulnaDash container to simplify wiring:**
  rejected; it would collapse the privilege boundary that keeps scanner network
  capability and app secrets apart.
