# ADR 0003: Probe Enrollment and Mutual-TLS Authentication

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 2 (VulnaScout enrollment and heartbeat)

## Context

VulnaScout probes are remote appliances that must authenticate to the
orchestrator strongly, communicate outbound-only, and never expose an inbound
management port. Phase 2 establishes how a probe obtains an identity and how it
authenticates on every subsequent request.

## Decisions

### 1. Internal CA + CSR-based enrollment; the probe key never leaves the probe

The orchestrator runs a small internal CA (ECDSA P-256). Enrollment:

1. An administrator mints a **single-use, 15-minute** token for a site. The
   token secret is shown once and stored only as a SHA-256 hash.
2. The probe generates its own P-256 key pair locally and sends a **CSR** plus
   the token.
3. The server validates/consumes the token, signs the CSR into a
   bounded-validity (default 90-day) client certificate, assigns the probe's
   identity (the CN is the server-chosen probe id — never taken from the CSR),
   and returns the certificate + CA certificate.

The private key never transits the network. ECDSA P-256 is used (not Ed25519)
for the widest mTLS client-auth compatibility.

### 2. mTLS terminated at the proxy; identity forwarded as a trusted header

Caddy terminates mutual TLS, verifies the client certificate against the
internal CA, and forwards the certificate's SHA-256 fingerprint in
`X-Vulna-Client-Cert-Fingerprint`. The API authenticates a probe by matching
that fingerprint to a `Probe` row.

**Trust boundary:** the API is never published directly — only the proxy can
reach it — so the header can only originate from the proxy after a successful
handshake. The proxy strips any client-supplied value of the header. This is
recorded as a security assumption in the threat model. Terminating mTLS at the
proxy (rather than in the app) keeps the Python service simple and keeps probe
authentication unit-testable without real TLS in the test suite.

### 3. Stored lifecycle status; derived connectivity

A probe's stored `status` is an administrative lifecycle value
(`pending_enrollment` → `enrolled`, or `disabled`/`revoked`). Live connectivity
(online/offline) is **derived** from `last_seen_at` against a configurable
threshold rather than persisted, because it is purely time-dependent. Revoked or
disabled probes are rejected at authentication, so a revoked probe cannot
heartbeat or poll for jobs.

### 4. The agent is standard-library-only (static, CGO-free)

The Go agent uses only the standard library so it cross-compiles to a single
static binary for `amd64` and `arm64` without CGO. Consequences: local state is
stored as files (client key `0600`, certificate, CA, and a small `state.json`)
rather than SQLite, and configuration is JSON with `VULNASCOUT_*` environment
overrides rather than YAML. A SQLite-backed durable job queue and a YAML config
loader can be added later if a dependency is justified; enrollment and heartbeat
need neither.

## Consequences

- No inbound port on the probe; all communication is probe-initiated over HTTPS
  with mTLS.
- Losing the CA private key requires re-enrolling every probe, so it must be
  backed up and access-controlled (documented in `.env.example` and packaging).
- The proxy is part of the security boundary: a deployment that exposes the API
  directly would allow fingerprint-header spoofing. This is called out in the
  threat model and the deployment docs.

## Alternatives considered

- **mTLS terminated in the FastAPI app:** rejected for the MVP; it complicates
  the ASGI server/TLS setup and makes tests require real certificates, for
  little gain over proxy termination behind a non-exposed API.
- **Ed25519 client certificates:** rejected for now due to less uniform mTLS
  client-auth support than ECDSA P-256.
- **Bundling a SQLite driver in the agent:** rejected for Phase 2 to preserve a
  dependency-free, CGO-free static build; revisited when durable job queuing
  lands.
