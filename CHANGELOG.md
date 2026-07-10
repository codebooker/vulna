# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase 5: Change detection

The orchestrator compares each scan against the current inventory and records
what changed, so operators can see a delta over time.

- `ChangeEvent` model (append-only) + migration.
- Change detection during ingestion: `asset_discovered` on first sight,
  `new_port_opened` / `port_closed` as ports change between scans, and
  `service_version_changed` when a product/version changes.
- Delta read API (`/api/v1/changes`) filterable by site, asset, scan, and type.
- Frontend "Recent changes" panel listing recent change events.

Verified: opening a port produces an event, closing it produces a second, and a
scan comparison for an asset shows both. ADR 0006 records the design.

### Added — Phase 4: Nmap discovery

Real network discovery: probes run Nmap and the orchestrator normalizes the
results into an asset/service inventory.

Orchestrator (VulnaDash):

- `Asset`, `AssetIdentifier`, `Service`, and `ScanArtifact` models (+ migrations).
- Defensive Nmap XML parser (`defusedxml` — rejects XXE and entity-expansion
  attacks) that normalizes up hosts and open services.
- Result-upload endpoint (size-bounded) that retains raw output verbatim, parses
  it, and upserts assets/identifiers/services — deduplicating by identifier (IP
  then MAC) so repeated scans update rather than duplicate.
- Asset/service read API (list, detail with services, per-asset services).

VulnaScout agent (Go):

- Nmap scanner adapter with an allowlisted, argument-injection-safe command
  builder (only typed flags; targets validated as IP/CIDR) and a
  context-cancellable runner producing XML (safe `-sT` discovery profile, no raw
  sockets/root).
- Executor generalized to a `JobRunner` interface; the agent uploads scanner
  output before reporting completion; the run loop uses the Nmap worker.

Validated end-to-end with **real nmap 7.99**: the probe's adapter scans a
loopback target, the output parses and ingests, assets/services appear, repeated
scans deduplicate, and out-of-scope targets are rejected. ADR 0005 records the
discovery/adapter design.

### Added — Phase 3: Signed jobs and local policy

Ed25519-signed job envelopes and local policy, verified and enforced
independently by the probe.

Orchestrator (VulnaDash):

- Ed25519 signing service over a canonical JSON form (sorted keys, compact, no
  HTML escaping, integer fidelity) shared by policy and job envelopes.
- Signed local-policy builder (approved CIDRs, allowed modes/plugins, limits
  from a probe's scopes); client-cert-authenticated `/policy` endpoint; signing
  public key delivered at enrollment; heartbeat advertises the policy hash.
- `ScanJob` model + migration; operator job creation that validates targets
  against approved scopes and signs the job envelope (stored verbatim for
  byte-identical delivery); `/jobs/next` delivery (expiring stale jobs); probe
  status reporting; cancellation (immediate for queued jobs, advertised via
  heartbeat for active ones).

VulnaScout agent (Go):

- `policy` package independently verifies signatures and enforces scope, mode,
  and job expiry — rejecting altered, expired, not-yet-valid, out-of-scope, and
  wrong-key jobs.
- Cancellable test worker (the kill switch until real scanners land in Phase 4).
- `agent` package orchestrates policy sync, job polling/verification, worker
  execution, cancellation, and status reporting; wired into the `run` loop.
- Enrollment stores the signing public key; policy and signing key persisted
  locally.

Cross-language proofs: Python-signed policy and job vectors verify in the Go
probe, and the Go/Python document hashes agree (byte-identical canonicalization).
ADR 0004 records the signing design.

### Added — Phase 2: VulnaScout enrollment and heartbeat

Orchestrator (VulnaDash):

- Internal ECDSA P-256 certificate authority that signs probe client
  certificates from a CSR (the probe's private key never leaves the probe).
- `Probe` and one-time `EnrollmentToken` models (token secrets stored only as
  SHA-256 hashes) and their Alembic migration.
- Enrollment flow: admins mint single-use, 15-minute tokens per site; probes
  submit a token + CSR and receive a bounded-validity client certificate, the
  CA certificate, and their assigned identity.
- Mutual-TLS probe authentication via a proxy-forwarded client-certificate
  fingerprint header, with an explicit documented trust boundary.
- Heartbeat endpoint that records inventory/health and returns server
  directives; job-poll endpoint (returns 204 for now) — both reject revoked or
  disabled probes.
- Probe lifecycle management (list, get, approve, revoke, disable) and derived
  online/offline connectivity from `last_seen_at`.

VulnaScout agent (Go, standard-library-only, static amd64/arm64):

- `enroll` (local key generation + CSR + token exchange), `status`, and `run`
  (mutual-TLS heartbeat loop with graceful shutdown) commands.
- File-based local state (client key `0600`, certificate, CA, `state.json`) and
  JSON configuration with `VULNASCOUT_*` environment overrides.
- Hardened systemd unit (build-plan Section 18.4) and install docs.

Caddy configuration strips any spoofed client-cert fingerprint header and
documents the production mTLS block. ADR 0003 records the enrollment/mTLS design.
Verified end-to-end: the real Go binary enrolls against the orchestrator, the
issued certificate's fingerprint authenticates heartbeats, and a revoked probe
is rejected.

### Added — Phase 1: Authentication and core inventory

- VulnaDash backend data layer: async SQLAlchemy 2.0 models for organizations,
  users, sites, network scopes, and audit events; a portable `Base` (works on
  PostgreSQL and SQLite); Alembic migration environment and the initial schema
  migration.
- Local authentication: Argon2id password hashing, JWT access tokens (HS256),
  `POST /api/v1/auth/login`, and `GET /api/v1/auth/me`.
- Role-based access control (administrator, security_operator, pentest_approver,
  remediation_owner, auditor, viewer) enforced via `require_roles` dependencies
  (401 unauthenticated, 403 unauthorized), with organization scoping on every
  query.
- Administrator bootstrap from the environment on startup and via a new `vulna`
  CLI (`vulna bootstrap-admin`, `vulna version`).
- REST endpoints for organizations, users, sites, and network scopes (CRUD),
  plus a read-only audit-log endpoint.
- Network-scope safety: CIDR normalization, rejection of `0.0.0.0/0` and `::/0`,
  public-range denial by default, overlap detection, and a `policy_version`
  bump on every change — implemented as unit-tested pure functions.
- Append-only audit logging written in-transaction for logins and all
  site/scope/user/organization mutations.
- Basic authenticated frontend: auth context with token persistence, a login
  page, a sites list with an admin-only create form, and sign-out.
- Tests: 50 backend tests (auth, RBAC negatives, CRUD, scope validation,
  cross-organization isolation, bootstrap, startup/lifespan) and frontend
  auth-flow tests; backend CI now checks migration/model drift.
- ADR 0002 (authentication, RBAC, and the data access layer).

### Added — Phase 0: Repository foundation

- Monorepo directory structure for VulnaDash, VulnaScout, and supporting
  components (`watch/`, `verify/`, `forge/`, `pulse/`, `lab/`, `shared/`).
- VulnaDash backend: FastAPI application with `/health`, `/api/v1/system/info`,
  and `/api/v1/system/health` endpoints; pinned dependencies; Ruff + mypy
  configuration; pytest suite; non-root Dockerfile.
- VulnaDash frontend: Vite + React + TypeScript application with a health page
  that reports backend connectivity; ESLint + Prettier; Vitest test; non-root
  Dockerfile served by nginx with a `/health` route.
- VulnaScout probe: Go module with `version` and `self-test` subcommands,
  internal package skeleton, unit test, and multi-arch Dockerfile.
- Development stack: `docker-compose.dev.yml` (Postgres, Redis, API, frontend)
  and a production-oriented `docker-compose.yml` skeleton with health checks.
- Shared JSON Schemas for job, result, plugin, and policy documents (drafts).
- `Makefile` with `dev`, `test`, `lint`, and component targets.
- GitHub Actions CI for backend, frontend, and probe (including `amd64` and
  `arm64` cross-compilation), plus issue and pull-request templates.
- Documentation: architecture overview, threat-model skeleton, authorized-use
  and rules-of-engagement guides, and ADR 0001 (initial architecture).

[Unreleased]: https://github.com/codebooker/vulna/commits/main
