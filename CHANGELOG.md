# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase 43 connector: GLPI

- GLPI legacy REST v1 now supports user-token/App-Token session setup and cleanup,
  profile tests, entity-bound ticket create/update/verified-close, severity mapping,
  and deterministic title-marker lookup before create. Session tokens remain
  ephemeral and never enter connector storage, task payloads, or result metadata.

### Added — Phase 43 connector: GitLab Issues

- GitLab.com and self-managed GitLab projects now support token/bearer connection
  tests, issue create/update/verified-close, labels, assignees, milestones, encoded
  nested project paths, sanitized responses, and stable idempotency headers.

### Added — Phase 43 connector: GitHub Issues

- GitHub.com and GitHub Enterprise issue synchronization now implements the
  common connector contract with repository tests, create/update/verified-close,
  labels, assignees, milestones, and sanitized outcome metadata.
- Creation retries search for a stable non-secret body marker before posting, while
  updates use the stored issue number. HTTPS requests reject redirects, pin the
  validated connection IP against DNS rebinding, preserve TLS hostname validation,
  bound response size/time, and never include provider response bodies in errors.

### Added — Phase 43 core: remediation SLAs and ticket synchronization

- Uniquely prioritized, first-match SLA policies now create immutable deadline
  calculations with a fixed severity fallback, append-only exceptions and history,
  breach/completion metrics, and structured remediation guidance.
- Accepted risk leaves SLA time running unless the selected policy explicitly opts
  into pausing it. Resumption appends a calculation that extends the deadline by the
  exact paused duration; existing `due_at` remains a compatibility projection.
- Ticket configuration uses a common idempotent `test`/`upsert`/`close` contract,
  purpose-bound one-way secrets, step-up-protected management, and worker-backed
  synchronization that cannot roll back finding persistence on a remote outage.
- Ticket payloads contain only selected finding fields and exclude evidence and raw
  scanner output. Normal closure requires a successful verification; explicit
  policy closure records an audited reason.
- The additive migration safely backfills existing deadlines, portability advances
  to schema v7 without connector ciphertext, and backup/restore, data-map, OpenAPI,
  isolation, UI, migration, and release-gate coverage are included. Provider
  adapters follow as separate stacked changes; production readiness remains false.

### Added — Phase 42: authenticated scanning and software inventory

- Purpose-bound SSH and WinRM vault records now use append-only encrypted secret
  versions, deterministic asset/group/tag/network/site/preset assignments,
  conflict-blocking resolution previews, one-way API responses, rotation, tests,
  usage audit, and step-up-protected lifecycle operations.
- Scout enrollment now creates an X25519 encryption key. Credential jobs are
  single-host, signed, scope-checked, and encrypted to one explicitly opted-in
  Scout with ephemeral X25519, HKDF-SHA256, and ChaCha20-Poly1305 binding the job,
  Scout, and expiry. Secrets exist only in collector memory.
- Built-in SSH Linux and WinRM Windows collectors use fixed read-only command
  allowlists, strict host-key/TLS verification, time/output limits, and normalized
  OS/package output. Scanner output, evidence, state, argv, environment, and logs
  never contain reusable credentials.
- Materialized software inventory retains append-only add/change/remove history,
  provider-neutral EOL intelligence, and expiring audited manual overrides. The new
  UI covers vault metadata, assignments, resolution, Scout opt-in, usage, and
  software state.
- The additive migration, backup/restore guidance, portability schema v6,
  capability matrix, OpenAPI/job schema, Go/backend/frontend security tests, and
  release gate are updated. Production readiness remains false pending final
  qualification.

### Added — Phase 41: explainable priority and remediation grouping

- Versioned organization risk profiles now score findings from a fixed factor
  catalogue. Inputs are normalized to `[-1,1]`, weighted, divided by the profile's
  positive maximum, and clamped to `0–100`; every source value, contribution,
  profile version, and canonical input hash is stored in an immutable snapshot.
- Friendly fix-now/plan/watch/informational priority remains a derived presentation.
  Ingest and intelligence enrichment refresh the score only when inputs change, and
  the finding detail UI exposes the complete contribution explanation.
- Remediation units group only exact CVE, package, product, and remediation keys.
  Token-similarity proposals are stored separately and cannot create membership
  until an authorized reviewer accepts them.
- False-positive, duplicate, and suppression decisions are append-only,
  evidence-backed, time-bounded, step-up protected, audited, and restored to the
  prior workflow state on revocation or worker-driven expiry.
- Migration backfill/fresh-install/downgrade tests, site/org isolation, portability
  schema v5, backup guidance, capability status, frontend coverage, and release-gate
  regressions are included. Production readiness remains false pending final
  qualification.

### Added — Phase 40: asset context, groups, and ownership

- Assets now carry structured department, business-function, environment,
  criticality, data-classification, exposure, owner, and bounded custom context.
  Inventory and reports provide server-side context, normalized-tag, and group
  filters without weakening organization/site authorization.
- Organization-owned tags replace the legacy array as the normalized source of
  truth while retaining `tags_json` as a compatibility projection. Upgrade safely
  backfills original tag values, order, and metadata without loss.
- Static groups and safely evaluated dynamic groups provide previewable,
  explainable, materialized membership. Rules use a bounded allowlisted JSON AST;
  executable expressions and regular expressions are rejected.
- Effective ownership follows finding, asset, highest-priority group, site,
  department, then unassigned. Potential group-owner ties are rejected and changes
  append effective-owner history.
- The Assets page adds context filtering, bulk editing, tags, group previews, and
  ownership detail. SCIM can now validate asset-group mapping targets, report
  snapshots retain filters/context, and portability schema v4 carries non-secret
  context records.
- The additive migration, backup/restore notes, data map, capability matrix,
  OpenAPI, audit, permission, isolation, frontend, and release-gate coverage are
  included. Production readiness remains false pending final qualification.

### Added — post-Phase-39 worker and scheduler gate

- Dedicated scheduler and worker services now use a durable database-backed task
  queue with idempotency keys, scheduled execution, expiring leases, lease renewal,
  retry/backoff, cancellation, dead letters, and process heartbeats.
- PostgreSQL advisory-lock leader election serializes scheduler replicas. Queue
  backpressure prevents unbounded scheduling, and expired worker leases are safely
  reclaimed after a crash.
- Scheduled scans, stale-job reaping, pentest timeout/evidence retention, and
  notification dispatch run through the queue. Feed sync and report generation also
  expose additive queued APIs while their existing synchronous `/api/v1` interfaces
  remain backward-compatible.
- Administrators can inspect task health/history, cancel work, and retry dead letters
  from the Task operations page. Fresh/upgrade migration coverage, Compose services,
  release-gate regressions, backup guidance, and security documentation are included.

### Added — Phase 39: granular RBAC and service accounts

- A source-controlled permission catalogue now drives database roles and
  organization/site-scoped user and service-account grants. Permission-aware query
  predicates prevent permissions from different site grants from combining.
- Existing roles and Phase 34 site assignments migrate into immutable built-in
  grants. The `/api/v1` `role`, `is_active`, `site_access_mode`, and site-assignment
  shapes remain derived compatibility fields while endpoints use permissions.
- Service accounts cannot sign in interactively. Personal and service API tokens
  expire, may be IP-restricted, rotate/revoke immediately, are shown once, and are
  stored only as hashes. Authorization changes invalidate sessions and issued
  tokens; high-risk step-up operations reject API-token authentication.
- The Authorization page manages roles, grants, service principals, and tokens.
  Audit attribution distinguishes service principals, the last administrator is
  protected, capability status is public, and OpenAPI/isolation/security tests are
  release-gated.
- The additive migration, encrypted backup guidance, privacy inventory, and
  portability schema v3 cover the new records without exporting token values or
  hashes.

### Added — Phase 38: SCIM 2.0 provisioning

- Organization-specific bearer tokens are displayed once, stored only as SHA-256
  hashes, expire, rotate with immediate predecessor revocation, and use durable
  database-backed per-token rate limits.
- `/scim/v2` now provides Users, Groups, ServiceProviderConfig, ResourceTypes, and
  Schemas resources with one-based pagination, safe filtering, attribute projection,
  standard PATCH operations, ETags, SCIM media types, and RFC-shaped errors.
- SCIM owns only SCIM-created users. Local and JIT accounts remain invisible and
  immutable to provisioning tokens; deprovisioning deactivates accounts, revokes
  credentials immediately, and preserves attribution and lifecycle history.
- Provisioned groups map explicitly to compatibility roles and assigned/all-site
  access. Administrators preview the affected users before applying a mapping;
  effective access is recalculated across all memberships and changed sessions are
  revoked. Asset-group targets remain stored but hidden until Phase 40.
- The Provisioning page manages one-time tokens, rotation/revocation, group mappings,
  previews, and sanitized request history. The migration, capability matrix,
  portability schema v2, backup guidance, OpenAPI, isolation, and release-gate tests
  are updated.

### Added — Phase 37: OIDC and SAML single sign-on

- Organization-scoped OIDC and SAML providers now keep encrypted client secrets,
  IdP/SP certificates and SP keys in separate HKDF contexts. APIs expose only
  `has_secret`/certificate metadata; provider material remains backup-only.
- OIDC uses Authorization Code with PKCE S256 and durable, single-use state/nonce
  records. Discovery, token, and JWKS destinations are HTTPS-validated and IP-pinned;
  ID-token signature, issuer, audience, expiry, nonce, authorized-party, and access-
  token binding checks use Authlib's maintained OIDC implementation.
- SAML uses the OneLogin toolkit and containerized xmlsec in strict mode. Authn
  requests and SP metadata are signed, assertions must be signed and may be required
  encrypted, metadata import rejects DTD/entities, request IDs are checked, response/
  assertion IDs reject replay, and two signing certificates support rollover.
- Verified-email JIT provisioning creates passwordless external accounts and stable
  subject links. Exact group mappings can assign compatibility roles and Phase 34
  sites; conflicting role mappings fail closed.
- SSO enforcement cannot be enabled until provider validation, a successful same-
  administrator test login, provider enablement, and an active local administrator
  with strong MFA are all present. Break-glass use raises a critical alert, and user,
  role, invitation, or MFA changes cannot remove the final recovery path.
- The Identity & SSO page and login choices preserve local break-glass sign-in, while
  the migration, capability matrix, OpenAPI, isolation, replay, portability, backup,
  and release-gate coverage are updated.

### Added — Phase 36: MFA, WebAuthn, and step-up authentication

- Authenticator-app TOTP seeds are purpose-bound encrypted, recovery codes are
  stored as independent Argon2 hashes and shown once, and replayed TOTP timecodes
  or used recovery codes are rejected.
- WebAuthn passkey/security-key registration and authentication use strict relying
  party, origin, challenge, user-verification, signature, and sign-counter checks.
  Challenges expire after five minutes and are scoped to one user and session.
- Organization MFA policy defaults to optional. Administrators may require MFA for
  selected roles or everyone with a configurable seven-day default grace period;
  expired unenrolled users can reach only the enrollment APIs.
- Sessions record authentication methods and MFA strength. A reusable recent-step-up
  dependency now protects scope, pentest, retention/hold, evidence/report, repair,
  Scout enrollment/certificate, and MFA-policy operations.
- Login and MFA failures use generic responses plus durable, hashed per-account and
  per-IP exponential backoff. Security events feed the existing audited notification
  path without making authentication depend on delivery.
- The Security page manages authenticators, passkeys, recovery codes, and policy.
  Browser coverage uses a Chromium virtual authenticator, and migration, export,
  backup/restore, capability, OpenAPI, and release-gate coverage are updated.

### Added — Phase 35: revocable sessions

- Sign-in now creates a database-backed user session and a family of hashed,
  rotating refresh tokens. Reusing an already rotated token immediately revokes
  the family and records a security audit event.
- Access tokens last 15 minutes and stay in browser memory. Session restoration
  uses an HttpOnly, SameSite=Lax refresh cookie that is Secure in production;
  legacy stateless tokens are rejected after upgrade, requiring one sign-in.
- Organization session policies default to a 12-hour idle timeout, 30-day absolute
  lifetime, 15-minute privileged window, 10 concurrent sessions, and 30-day
  trusted-device duration. Administrators can update these audited defaults.
- Users can review and revoke their sessions or sign out everywhere. Administrators
  can inspect and revoke a user's sessions from the Users page. Password, role,
  status, and site-access changes revoke all active sessions immediately.
- Additive migration, rotation/reuse and cross-organization security regressions,
  browser integration coverage, OpenAPI checks, documentation, and release-gate
  coverage are included. Session/refresh records remain backup-only and never
  appear in portability exports.

### Added — Phase 34: user administration and lifecycle

- Administrators now invite users with hashed, expiring, single-use links instead
  of assigning permanent passwords. When SMTP is absent, the link is shown once
  for copying. Active local users use the same one-time pattern for password reset.
- Accounts have authoritative invited, active, suspended, locked, and deactivated
  states plus local/JIT/SCIM source metadata. Compatibility `is_active` and `role`
  fields remain available; deletion is a soft deactivation that preserves history.
- Site assignments are enforced immediately by shared organization/site query
  guards across inventory, scans, reports, findings, dashboards, workflows,
  maintenance, privacy analytics, relays, and pentest surfaces.
- The Users page includes role and site assignment controls, status actions, MFA
  readiness, login history, lifecycle history, and one-time invitation/reset links.
- Role, site, status, and credential changes revoke Phase 34 access credentials;
  unsafe self-deactivation and removal of the last active administrator are blocked.
- Additive migration, prior-head/fresh-install tests, OpenAPI and release-gate
  coverage, non-secret portability metadata, and backup/restore documentation.

### Added — Phase 33: adaptive installation and experience profiles

- Installer answer schema v2 adds `deployment_profile`; schema v1 remains
  readable and defaults to Small Business. Interactive installs offer the 1/2
  profile choice, `--deployment-profile` supports automation, and dry-run/final
  summaries name the effective profile.
- Organizations now store a typed experience profile and allowlisted navigation
  overrides. Existing organizations backfill to Small Business; only a newly
  bootstrapped organization consumes `VULNA_DEPLOYMENT_PROFILE`.
- A centralized, role-aware route catalogue presents Small Business core routes
  with a collapsed Advanced section, all implemented Enterprise routes, or Custom
  visibility. Presentation never substitutes for API authorization and hidden
  routes remain directly addressable when authorized.
- General Settings provides an audited preview/confirmation flow; the administrator
  Users inventory is now upgraded by Phase 34 lifecycle controls.
- New installations include an advisory profile-planning onboarding step.
  Answers stay in onboarding state, unavailable recommendations are labelled
  `planned`, and no high-impact policy is automatically applied.
- A public [capability status matrix](docs/capabilities.md), migration/portability
  updates, and release-gated profile security regressions.

### Added — Phase 32: release qualification and self-hosting ecosystem packaging

Make the easy path consistently work across a small, honest support matrix and
make community packaging sustainable.

- A **published support matrix** (`deploy/release/support-matrix.json`,
  `docs/support-matrix.md`): supported Linux distros, container-runtime/Compose
  versions, `amd64`/`arm64`, single-host resource tiers, browsers, Dashboard/Scout
  compatibility, and scanner versions — intentionally limited to what is tested
  continuously.
- A **release-blocking regression gate** (`release_gate` pytest marker +
  `deploy/release/release_gate.sh`): a release cannot be promoted if the
  security-critical suite fails — setup/enrollment, target/scope enforcement, job
  signatures and signed policy, cancellation, backup/restore, relay egress + kill
  switch, and data authorization (RBAC + cross-org isolation). A meta-test enforces
  the gate keeps its coverage.
- A **packaging policy** (`docs/packaging-policy.md`): official / community /
  experimental tiers; community templates can't pose as official; no packaging may
  require privileged containers, host networking/FS, or Docker socket access beyond
  the Scout/scanner boundary; signed images are never silently replaced.
- **Release-process docs** (`docs/release-process.md`): stable + maintenance
  channels, signed artifacts (signatures/checksums/SBOMs/migration+compat notes/
  recovery), and signing-key rotation + compromise recovery.
- A privacy-safe **install-diagnostics issue template** (redacted support bundle +
  `vulna doctor --json`, privacy attestation), **reference benchmarks**
  (`docs/benchmarks.md`), a "**preserve the simple path**" contributor guide, and
  ADR 0032.

### Added — Phase 16: VulnaRelay (optional thin-site tunnel mode)

A thin-site tunnel for constrained sites, **off by default** and enabled in
Settings; the smart VulnaScout probe stays the default.

- **Off-by-default feature flag** (`app/services/relay.py`, `/relays/settings`):
  relay mode lives in the org `settings_json` (no schema change) and every relay
  operation is refused while disabled.
- **Central egress enforcement** (`relay.egress_decision`): a relay may carry scan
  traffic to a target only when it is enrolled, its tunnel is up, and the target is
  within the relay's approved CIDRs and not denied — **fails closed**, out-of-scope
  blocked at the egress. Pure and unit-tested.
- **Immediate kill switch** (`/relays/{id}/kill`): tears the tunnel and blocks all
  scanning; a killed relay's heartbeat is refused so the tunnel stays down.
- **mTLS enrollment reusing the Scout machinery** (single-use token + CSR + CA):
  the registration response contains only the control certificate and CA — **never**
  job-signing keys or scanner credentials (tested). A relay runs no scanners.
- A `Relay` model + heartbeat, scope approval, resume, and revoke endpoints; a
  Relay settings page (frontend); `docs/relay.md`; and ADR 0016.

### Added — Phase 31: privacy, data ownership, and portability

Make Vulna trustworthy for people who self-host to keep control of their data.

- **Outbound transparency** (`app/services/privacy.py`, `/privacy/outbound`):
  lists every destination the deployment may contact — intelligence feeds, the
  SMTP/webhook channels you configured — and states that **update checks contact
  nothing** (the app never phones home; updates are CLI-run). Computed from actual
  config so it always reflects enabled features.
- **Opt-in-only, anonymous telemetry**: off by default and never preselected. A
  field-level **preview** (`/privacy/telemetry/preview`) shows the exact
  aggregate-counts-only payload, which never contains IPs, hostnames, usernames,
  findings, CVEs, evidence, credentials, report contents, or a cross-installation
  identifier. A **local analytics** option reports the same counts and is never
  transmitted. Toggle changes are audited.
- **Disabling never breaks core function**: update-check/telemetry/feed toggles
  live in `settings_json` (no schema change) and are independent of scanning,
  reporting, remediation, and local intelligence import.
- **Secret inventory** (`/privacy/secrets`, admin): which secrets are configured,
  **never their values**.
- **Complete, verifiable export** (`app/services/export.py`,
  `/portability/export`): a versioned, checksummed JSON bundle of non-secret data
  (no keys/tokens/certs/passwords/report bytes) that validates independently
  against a **published schema** (`shared/schemas/export-bundle.schema.json`).
- **Untrusted-import validation** (`/portability/validate`): checks schema,
  checksum, ownership, and conflicts and **never applies anything**; a bundle from
  another organization is **refused** (no cross-org bypass). The host move is a
  backup/restore that preserves CA and Scout identity (`/portability/migration-plan`).
- A **machine-readable data map** (`shared/schemas/data-map.json`,
  `docs/data-map.md`), a Privacy page (frontend), a threat-model update, and ADR
  0031.

### Added — Phase 30: documentation, demo, and guided learning

Documentation as part of the product, plus a safe way to evaluate the interface.

- A **documentation home** (`docs/README.md`) with **Simple** and **Advanced**
  paths, the three **deployment models** (single-host, distributed Scouts, Relay)
  on one page, and a task-guide index. New guides: **quick start**
  (`docs/quickstart.md`), **terminology**, **understanding/fixing/verifying
  findings**, **troubleshooting** (symptom-first), **demo mode**, **exposure
  checklist**, and **migration notes**.
- **Safe demo mode** (`app/services/demo.py`, `/demo` API): seeds a self-contained
  Demo Environment with sample assets/services/findings using only **reserved
  documentation address ranges**, and **blocks real scan-job creation** while on,
  so the demo can never contact a target. Admin-only, audited; disabling removes
  the sample data. The flag lives in the org `settings_json` (no schema change).
- A **contextual help catalogue** (`app/services/help_topics.py`, `/help` API):
  topic → title/summary/doc, plus lookups by job error code and maintenance
  domain, and the administrator exposure checklist, so the UI deep-links to the
  right guide instead of a generic log page.
- **Documentation is tested**: every help-topic doc must exist (a renamed guide
  fails CI), and a lint forbids the new/security-sensitive guides from
  recommending insecure practices (disabling TLS verification, privileged runs,
  open database ports, default secrets).
- A Help & demo page (frontend), and ADR 0030.

### Added — Phase 29: simple notifications and self-hosted integrations

Get notified where you already work, without an enterprise ticketing deployment.

- **Email and signed-webhook channels** (`app/services/notify.py`,
  `app/api/v1/notifications.py`) configured and tested from the UI — no env-file
  editing. A channel subscribes to events and has a delivery policy.
- **Signed, replay-resistant webhook payloads** (`app/services/notifications.py`):
  versioned JSON, `HMAC-SHA256(secret, "<ts>.<body>")` in `X-Vulna-Signature`,
  per-delivery id, **selected fields only** — never evidence, scanner output,
  credentials, or report files.
- **SSRF-safe destinations**: webhook URLs must be `https` and must not resolve to
  loopback, link-local, cloud-metadata, multicast, or reserved addresses; private
  addresses require an explicit opt-in; validated at config, test, and send time.
- **Event catalogue**: Scout offline, scan completed/failed, new critical/high
  finding, KEV match, verification succeeded/failed, backup stale, feed stale,
  certificate expiring, storage pressure, update available.
- **Policies, quiet hours, dedup**: immediate or hourly/daily/weekly digests;
  quiet hours **delay** (never drop) non-emergency events; repeated identical
  events are deduplicated.
- **Non-blocking delivery**: emission only **persists** a pending delivery and is
  suppressed at its call site, so a notification problem never blocks scan
  completion or finding persistence; a separate dispatch sends, records history,
  attempts, and errors.
- **Credentials encrypted at rest**, never returned by the API (reads show only
  `has_secret`), and rotatable through a dedicated audited endpoint.
- A Notifications page (frontend), a representative emit point (scan
  completed/failed), ADR 0029, and `docs/notifications.md`.

### Added — Phase 28: Unified Maintenance Center

One place for a self-hoster to tell whether Vulna needs attention.

- A **maintenance overview** (`GET /maintenance`, `app/services/maintenance.py`)
  that reuses the Phase 26 diagnostics (so the two never disagree) and maps every
  domain — updates, Scouts, scanners/templates, feeds, backups, certificates,
  storage, retention, failed scans/reports, stuck jobs — to a **green / warning /
  action-required** state with a specific next step. No dependency on the optional
  monitoring stack.
- **Storage budgets** (`GET /maintenance/storage`) broken down by category (raw
  output, reports, evidence, database, Scout queues, backups) with no sensitive
  labels.
- A **fail-closed retention cleanup** (`app/services/retention.py`): one planner
  drives both the **preview** (`GET /maintenance/retention/preview`) and the
  execution (`POST /maintenance/retention/cleanup`), so the manifest matches the
  deletion. Cleanup deletes only old, unreferenced objects and **refuses** to
  delete anything within retention, backing an active finding, referenced by a
  retained report, or under a **legal hold** (`retention_holds`). A policy floor
  prevents purging fresh data.
- Cleanup is a **high-impact action**: administrator, explicit confirmation, a
  **password re-check** (reauthentication), and an audit record with the manifest.
  Legal holds are placed/lifted admin-only and audited.
- A **certificate-rotation preflight** (`GET /maintenance/certificate`) with expiry
  status and recovery guidance; rotation stays a CLI/re-enrollment operation so it
  is atomic and recoverable.
- A **self-hosting health report** (`GET /maintenance/health-report`) summarizing
  updates, backups, feed age, storage, failed scans, retention, and expiring
  certificates.
- A Maintenance page (frontend), ADR 0028, and `docs/maintenance.md`.

### Added — Phase 27: low-resource, ARM64, intermittent, and offline operation

Make Vulna practical on the hardware and connectivity common in homelabs.

- A resource-aware **operating profile** (Lite / Standard / Full) chosen from the
  Scout's reported CPU, memory, and disk (`app/services/resources.py`): dynamic
  concurrency/queue limits **clamped to signed policy**, one-heavy-stage-at-a-time
  on constrained hosts, per-stage hard budgets, and expensive components (active
  ZAP, full-text indexing, large report rendering, high-frequency feed matching)
  disabled under Lite. The Scout reports resources via a stdlib-only, build-tagged
  probe (`scout/internal/telemetry`).
- **Fail-closed backpressure** (`resources.admit`): heavy work pauses at low disk
  and is refused at critical disk to protect evidence and the database; a full
  queue or large ingestion backlog pauses admission. Intrusive/scope-sensitive
  stages are refused under any pressure. Every decision names component, impact,
  and next step.
- A **durable, idempotent Scout result queue** (`scout/internal/queue`) for
  intermittent WAN links: finished work is kept on disk (surviving restarts),
  drained when connectivity returns, capped for backpressure, and reported as a
  visible backlog. A content-derived `Idempotency-Key` plus a server-side record
  (`probe_result_uploads`) makes resumed uploads exactly-once — no duplicate
  observations.
- **Signed, data-only offline bundles** (`app/services/offline_bundle.py`,
  `GET/POST /resources/offline-bundle/...`) for air-gapped sites: Ed25519-verified,
  restricted to an `intel`/`feeds`/`templates`/`update` allowlist (never an
  executable or plugin), exposing creation time, feed age, and content versions,
  admin-only and audited (which is the import history). Fails closed on a bad
  signature.
- A **capability warning** on the preset preview when a preset exceeds the Scout's
  recommended tier, and a display-only operating-profile endpoint
  (`GET /resources`).
- ADR 0027 and `docs/low-resource.md` (profiles, architecture baselines, offline
  bundles, tuning knobs).

### Added — Phase 26: Vulna Doctor, diagnostics, and safe self-healing

See which component is failing without grepping logs across containers.

- **`vulna doctor`** (host) with human-readable and `--json` output, diagnosing
  OS/arch, container runtime, disk, ports, clock, DNS/outbound, and permissions.
- A **System Health** aggregation (`GET /diagnostics`, `app/services/diagnostics.py`)
  covering application/database, local and remote Scouts, scanner capabilities,
  feed freshness, CA and Scout certificate expiry, storage use, failed
  jobs/reports, and update/backup posture. Every check names the component,
  impact, **data-safety** status, and next step, linked to docs. Read-only.
- A **redacted support bundle** (`GET /diagnostics/support-bundle`) built from an
  **allowlist** (never passwords, tokens, private keys, authorization headers, raw
  credentials, unrestricted evidence, or full scanner output), with a secret
  scanner as a second check and a preview + manifest to review before export.
  Admin-only and audited.
- A small set of **safe, confirmed, audited repairs** (`POST /diagnostics/repair`)
  over derived state (recreate a missing storage directory) that never alter
  scopes, permissions, users, credentials, retention, or any security setting.
- A local **event timeline** (`GET /diagnostics/timeline`) of recent audited
  actions and failed jobs (action/type/timestamp only).
- A frontend System Health page, ADR 0026, `docs/diagnostics.md`, and backend + Go
  tests (including a seeded expired-certificate failure verifying the diagnosis).

### Added — Phase 25: Backups, restore, and recovery

Make data ownership real with an understandable, verifiable recovery process.

- New `vulna backup` CLI: `create`, `list`, `verify`, `restore`, `prune`, and
  `recovery-sheet`, wrapping the DB-dump-plus-data archive from
  `deploy/backup/backup.sh` in a bundle with a **versioned, secret-free manifest**
  (content classes, app/schema versions, org ownership, archive checksum).
- **Encrypted bundles**: AES-256-GCM keyed by PBKDF2-HMAC-SHA256 from a
  user-controlled recovery passphrase supplied via the environment (never argv,
  never stored, never in the manifest or logs). Both implemented from the Go
  standard library (no third-party dependency). Wrong passphrase or tampering fails
  authentication.
- **Verify before restore**: a bundle missing required files or failing its
  checksum is marked UNUSABLE; `restore` refuses it before any destructive step,
  and `create` self-verifies what it wrote.
- **Restore safety**: validates schema-version compatibility and organization
  ownership, and refuses to overwrite an existing deployment without `--confirm`
  (taking a safety backup first). A UX guard rejects flags placed after the bundle
  path so a validation flag can never be silently skipped.
- Because the **CA** and database are backed up, restoring does not require
  re-enrolling every Scout.
- A printable **recovery sheet** with only non-secret identifiers, key-custody
  instructions, restore commands, and a clear statement of what cannot be recovered
  if the passphrase or CA key is lost.
- A **display-only** web backup center (`GET /system/backups`): retention,
  destinations (local default, S3-compatible), content classes, encryption note,
  CLI commands, and a prominent keep-a-verified-off-host-backup warning.
- ADR 0025, `docs/backups.md`, a frontend Backup Center panel, a CI backup smoke
  test (usable vs corrupted/wrong-passphrase), and Go + backend tests.

### Added — Phase 24: Boring, safe updates and rollback

Keep Vulna current with verified, operator-driven, reversible updates — without
the running app becoming a remote code-execution channel.

- New `vulna` CLI commands: `update check`, `update`, `update status`, and
  `rollback`.
- **Signed release-manifest verification** (`cli/internal/release`): an Ed25519
  signature over the `SHA256SUMS` manifest plus a checksum match for `release.json`.
  A manifest that is unsigned, altered, expired, or on the wrong channel is
  **rejected** (pure-Go verification, unit-tested; a smoke test proves a tampered
  manifest is refused).
- **Pre-update safety checks** (`cli/internal/update`): free disk, backup status,
  database health, local modifications, and — blocking — an incompatible **active
  assessment** (no update begins while one runs). Schema-changing releases surface
  a migration warning.
- An **automatic pre-update backup** (unless `--no-backup`) and a recorded rollback
  point (applied + prior version + backup path).
- **Rollback** that never restores an incompatible state: a schema-changing release
  requires restoring the pre-update backup first, and rollback refuses if a
  schema-changing update recorded no backup.
- A **display-only** web Update Center (`GET /system/update`): current version,
  channel (stable/candidate/development), the separate update types
  (app/Scout/scanner-binary/scanner-template/feeds), and the CLI commands. The app
  never fetches or applies releases; automatic installation is opt-in and there is
  no forced remote update path.
- ADR 0024, `docs/updates.md`, a frontend Update Center panel, and backend + Go
  tests (release verification, pre-update checks, rollback bookkeeping).

### Added — Phase 23: Networking, URL, TLS, and reverse-proxy assistant

Eliminate one of the most common self-hosting failure points: reaching the
application securely from the intended network.

- Five supported **access modes** (localhost, private LAN, public DNS with
  automatic TLS, existing reverse proxy, manual certificate), each with settings,
  warnings, and a documented recovery path in `docs/networking.md`.
- **Trusted-proxy hardening** (security): the API honors `X-Forwarded-For` and the
  Scout client-cert fingerprint header **only** from a peer in
  `VULNA_TRUSTED_PROXIES` (default: loopback + RFC1918/ULA). An untrusted peer that
  reaches the API directly cannot spoof the source address or a Scout identity —
  the headers are ignored (`app/api/context.py`, `app/api/probe_auth.py`).
- A **networking assistant** (`/networking/validate`, `/test-browser`,
  `/test-scout`, `/proxy-snippet`): validates hostname, certificate chain/expiry
  (public parts only), and name match, and detects split-DNS / NAT-loopback, mixed
  HTTP/HTTPS, clock skew, and certificate-name mismatch with plain-language
  remediation. Private key material is never accepted or returned.
- A **safe URL-change plan** (`/networking/url-change`): returns the exact `VULNA_*`
  values plus rollback, without mutating live config; the prior URL keeps working
  until applied. Application TLS is kept separate from VulnaScout mutual TLS, so a
  browser-certificate change never invalidates an enrolled Scout.
- A generated **reverse-proxy snippet** for advanced users, and confirmation that
  no PostgreSQL/Redis/metrics/internal ports are exposed by default.
- A frontend Networking & access panel, ADR 0023, and backend + frontend tests
  (including that an untrusted peer cannot spoof a probe identity).

### Added — Phase 22: Everyday UX for homelabs and small teams

Make the product useful to people who do not read CVEs or scanner output all day,
without discarding the formal data.

- A plain-language **priority model** (`app/services/priority.py`): fix now / plan
  a fix / watch / informational, computed from severity + KEV + EPSS + validation +
  detection confidence. The security-critical rule: a **low-confidence match is
  never presented as a confirmed, fix-now vulnerability** — uncertain findings are
  capped at "watch". Formal severity/CVSS/confidence stay on the record.
- A **home dashboard** (`GET /dashboard/summary`): what needs attention (by
  priority), what changed recently, which systems weren't assessed, whether Vulna
  is healthy, and a single next recommended action.
- A consistent **seven-section finding layout** (observed → why → confidence →
  affected → remediation → verify → references/evidence) with plain-language
  summaries and an expandable technical view; detection confidence and evidence
  source are always shown. Evidence is **sanitized** for display
  (`app/services/evidence.py`).
- **One-click workflows**: *Mark fixed & verify* (does not close the finding until
  the configured verification succeeds), *False positive*, and *Assign*.
- **Bulk actions** (`POST /findings/bulk`) that enforce **per-object
  authorization** (findings outside the caller's org are skipped, never touched)
  and emit a per-finding audit event.
- A **global search** (`GET /search`) across assets, findings, sites, scans, and
  reports, scoped to the organization.
- Accessible, responsive markup (semantic landmarks, labeled controls, native
  buttons/`<details>`), a keyboard-only review in `docs/accessibility.md`, ADR
  0022, and backend + frontend tests.

### Added — Phase 21: Opinionated scan presets and automatic tuning

A small set of safe, understandable scan *outcomes* instead of scanner flags,
built on the same signed-job and local-policy controls.

- A versioned preset registry (`app/services/presets.py`): Quick Check, Standard
  Security Check, Fragile / IoT Safe, Web and TLS Check, Deep Safe Check, plus a
  validated Custom path. Each preset pins a `(key, version)` so historical reports
  stay reproducible and updating a preset never silently changes a schedule.
- Built-in presets contain **only** passive/safe stages; intrusive and active-web
  checks are never part of a preset and cannot be enabled by a custom preset.
- A `GET /presets/capabilities` capability manager: the Scout now reports its
  installed scanners and CPU count in the heartbeat, so each known scanner shows as
  installed/missing/unhealthy.
- `POST /presets/preview` resolves a preset against a Scout's real capabilities and
  returns exactly which stages will run and a plain-language reason for each
  skipped stage. A missing scanner **blocks** the job (a clear preflight result)
  unless the operator explicitly approves downgrade.
- Hardware-aware `recommend_tuning` suggests concurrency/rate from the Scout's
  resources, **hard-clamped** to the `maximum_packets_per_second` /
  `maximum_concurrency` in local Scout policy — tuning can never exceed the signed
  limits.
- `POST /presets/custom/validate`: expert custom presets are validated structured
  choices only — they cannot introduce arbitrary executable paths, shell fragments,
  unrestricted Nmap scripts, or unreviewed Nuclei template sets.
- Scan estimates are workload classes and duration *ranges*, not false precision.
- A frontend Scan Presets panel with the why-skipped preview; onboarding now
  offers the full preset set from the same registry. ADR 0021; backend, Go, and
  frontend tests.

### Added — Phase 20: Frictionless remote VulnaScout deployment

Adding a Scout at a second site is now nearly as simple as the local one, while
keeping outbound-only communication, single-use hashed tokens, a private key that
never leaves the Scout, and locally-enforced signed policy.

- A per-site **Add VulnaScout** command: `POST /probes/enrollment-command` mints a
  single-use, hashed, short-lived token and returns copy-paste install commands
  plus a short verification code. The token is passed via the environment (not
  argv), so it does not linger in process listings; enrolling never authorizes a
  target.
- A verifying scout bootstrap (`scripts/install-scout.sh`) that checks a pinned
  release's Ed25519 signature and checksum before installing/enrolling — no
  inbound port is opened. A smoke test proves it refuses a tampered artifact or
  signature.
- `vulnascout doctor` — a staged connection test (DNS, TLS, clock skew, enrollment,
  heartbeat, policy, scanner health, authenticated upload reachability) with a
  concrete remediation for each failure (proxy, custom CA, DNS, clock, MTU,
  outbound firewall); no secrets in output.
- `vulnascout stop` / `resume` — a **local** emergency stop that works with no
  network and is authoritative even when VulnaDash is unreachable; the run loop
  refuses to start and cancels a running job while it is set.
- `vulnascout reset` — best-effort central self-revocation
  (`POST /probes/self-revoke`, mTLS) so the old identity can no longer poll or
  upload, then a local wipe of key/cert/state that preserves a non-secret
  diagnostics snapshot for clean re-enrollment. The private key is removed in
  place and never leaves the Scout.
- A frontend "Add VulnaScout" panel and ADR 0020; backend, Go (`doctor`, storage
  stop/reset, `SelfRevoke`), and frontend tests.

### Added — Phase 19: Guided first run and first safe assessment

A short, understandable route from first login to a first **safe** assessment,
without requiring the operator to understand scopes, jobs, or scanner syntax — and
without weakening any control.

- A resumable first-run wizard (frontend) whose progress lives server-side in a
  new `onboarding_states` table, so refreshing or reopening the browser never
  loses progress or creates duplicate scans. It can be skipped and resumed.
- An `/onboarding` API that only *assists*: scope approval and job launch still go
  through the ordinary, audited `/scopes` and `/jobs` paths, so the wizard cannot
  bypass any signature, scope, approval, or least-privilege control.
- **Advisory** local network detection: the Scout reports the private (RFC1918)
  ranges it can see in its heartbeat; the wizard surfaces them as suggestions
  only. Nothing is ever saved or scanned from detection.
- Scope previews reuse the real `validate_cidr`, so `0.0.0.0/0`, `::/0`, malformed
  input, and (by default) public ranges are rejected before anything is saved;
  public and unusually broad ranges raise a warning and require explicit
  confirmation.
- One-time account recovery codes generated with a CSPRNG, shown once, and stored
  only as Argon2 hashes on the user, consumed one at a time.
- The single safe **Standard Security Check** preset plus a pre-scan summary
  (targets, host estimate, checks, resource/duration class, data retention).
- An isolated **demo target** (`127.0.0.1/32`, the Scout self-scanning over
  loopback) so the full workflow can be tried without scanning a real network — it
  still goes through explicit scope approval, so it exercises the real path.
- ADR 0019, backend + Go (`netdetect`) + frontend tests.

### Added — Phase 18: Safe installer and environment preflight

One supported installation workflow that detects problems before changing files
or starting services, generates strong secrets, and is safe to re-run and
uninstall.

- A small, statically linked `vulna` installer/administration CLI (`cli/`,
  stdlib-only Go, linux/amd64 + linux/arm64): `install`, `preflight`,
  `uninstall`, `version`.
- A verifying bootstrap (`scripts/install.sh`) that downloads a **pinned** CLI
  release and verifies its SHA-256 checksum and Ed25519 signature before running
  it; unverified remote content is never piped into a shell. A smoke test proves
  it runs a valid release and refuses a tampered artifact or signature.
- Preflight checks for OS/architecture, container runtime and Compose, CPU /
  memory / free disk, port conflicts, time synchronization, DNS/outbound
  reachability, filesystem permissions, and an incompatible existing install.
  Every non-passing result names the problem, impact, and next step; failures
  block, warnings need `--force` (loss of connectivity is a warning — Vulna runs
  offline).
- Cryptographically strong secret generation into a `0600` env file in a `0700`
  config directory; secrets are never printed or logged.
- Idempotent install (existing secrets are never rotated and manual edits are
  preserved), a faithful `--dry-run` that lists files/dirs/services/ports/
  capabilities, and a `--non-interactive` mode driven by a versioned answer file.
- A clean `uninstall` that preserves data volumes; `--purge` must name the data
  directory to also delete data.
- ADR 0018, an installation guide with a manual (no-pipeline) path, a new
  `installer` CI workflow (build, vet, test, cross-build, govulncheck, shellcheck,
  bootstrap smoke test), and `make cli-build|cli-test|cli-lint` targets.

### Added — Phase 17: First-class single-host deployment

A one-command, self-contained deployment on a single machine, with a co-located
VulnaScout that just works — while staying scope-gated and least-privileged.

- A single-host Compose overlay (`docker-compose.single-host.yml`) that layers a
  co-located **local Scout** onto the base stack. It auto-enrolls over the same
  mutual-TLS boundary as a remote Scout and comes up **connected but idle** — no
  approved network scope, so it can scan nothing until the operator approves one.
- First-run bootstrap, gated by `VULNA_BOOTSTRAP_LOCAL_SCOUT`, ensures a default
  site and mints a **single-use, auto-approve** enrollment token written to a
  0600 file on an internal volume (never the API, UI, or logs). A new
  `auto_approve` flag on enrollment tokens yields an *enrolled* (not
  pending-approval) probe on redemption, without ever approving a scope or
  weakening signing/scope checks.
- A `GET /system/component-health` endpoint distinguishing application, database,
  local-Scout, scanner-capability, and intelligence-feed health, so an operator
  can see *which* component needs attention.
- The single-host Caddy config enables probe mTLS with `verify_if_given` (certless
  enrollment still works; rogue certs are rejected). The Scout **verifies** the
  orchestrator's TLS via Caddy's public internal root CA, published to the shared
  volume by a one-shot init — the CA private key is never shared with the Scout.
- The local-Scout image bundles the standard safe scanner pack (Nmap, Nuclei,
  testssl.sh), pinned and integrity-checked.
- The API container now applies database migrations (`alembic upgrade head`,
  idempotent) before serving, so a fresh stack starts with no manual step
  (opt out with `VULNA_RUN_MIGRATIONS=false`).

### Fixed

- Frontend container health check used `localhost`, which busybox `wget` resolves
  to IPv6 while nginx listens IPv4-only, so the frontend never became healthy and
  blocked the reverse proxy. It now uses `127.0.0.1`.
- API data directories (`keys`, `bootstrap`, `reports`, `evidence`) are
  pre-created in the image owned by the non-root user, so empty named volumes
  mounted onto them are writable.

### Added — Phase 15: Hardening and public release

Supply-chain, backup, and release-integrity hardening ahead of a public release.

- Dependency scanning is clean: `pip-audit` (backend), `npm audit --audit-level=high`
  (frontend), and `govulncheck` (probe) all report no known vulnerabilities, run
  by a new `security` CI workflow.
- Backup/restore scripts (`deploy/backup/`) that archive the database dump and
  data directory into a single checksummed tar.gz, verify the SHA-256 before
  restoring, and refuse a tampered archive — proven by a smoke test.
- Release signing (`deploy/release/`): a `SHA256SUMS` manifest with an Ed25519
  detached signature; `verify.sh` checks authenticity then integrity and rejects
  a tampered artifact or a wrong-key signature — proven by a smoke test.
- SBOM generation for all three components (`deploy/sbom/generate-sbom.sh`); an
  external security-review checklist (`docs/security-review-checklist.md`); a
  release-verification section in `SECURITY.md`; and an isolated, intentionally-
  vulnerable sample lab (`deploy/lab/`).

### Changed

- Backend dependencies bumped to advisory-clean versions (cryptography 49,
  starlette 1.3.1 pinned explicitly, pytest 9, fastapi 0.139); all 193 tests pass
  on the new versions.

### Added — Phase 14: VulnaPulse observability

Operational monitoring for the stack, with a strict no-sensitive-data guarantee.

- A VulnaDash `/metrics` endpoint in Prometheus format exposing **aggregate,
  non-sensitive** metrics only: findings by severity/status, known-exploited
  count, probe/scan-job/pentest/workflow counts, per-probe heartbeat/liveness, and
  intelligence-feed freshness. Labels are limited to enum values and opaque UUIDs;
  no finding title, description, evidence, or IP address appears anywhere. The
  public proxy does not route `/metrics` (internal scrape only).
- A `monitoring` Docker Compose profile (Prometheus, Grafana, Postgres/Redis/host/
  container exporters), provisioned Grafana datasource + "Vulna Overview"
  dashboard (auto-loaded, no manual import), and Prometheus alert rules including
  a stale-CVE-feed alert.

Verified: `/metrics` exposes the aggregates and is asserted to contain no finding
titles, IPs, or CVE ids; the compose monitoring profile parses; and all monitoring
config is valid. ADR 0015 records the design.

### Added — Phase 13: Appliance packaging

VulnaScout ships as a turnkey appliance, and upgrades never lose a probe's
identity or policy.

- Multi-arch Docker probe image (`deploy/probe/Dockerfile`, amd64 + arm64) with
  Nmap bundled; nfpm config for Debian `.deb` packages (amd64 + arm64 /
  Raspberry Pi-class); a hardened systemd unit; a cloud-init template for
  unattended provisioning; and a package build script.
- An update/rollback engine (`update.sh`) that installs releases side by side and
  flips a single symlink, keeping identity, policy, and config in a separate
  `/var/lib/vulna` that updates never touch — so an upgrade preserves the enrolled
  identity and signed policy, and a rollback re-points to the previous release.
- An operator console (`vulna-appliance`: enroll, status, update, rollback, logs)
  and a `docs/deployment.md` with the documented fresh-VM and Raspberry-Pi ARM64
  enrollment commands.
- A `packaging` CI job: shellchecks the appliance scripts and runs a smoke test
  proving upgrade preserves identity/policy and rollback restores the prior
  version.

### Added — Phase 12: Full-spectrum workflow

A multi-stage assessment engine that composes discovery, assessment, controlled
validation, and reporting into one run.

- `WorkflowRun` model (+ migration) with a per-stage trail. A deterministic engine
  owns stage ordering, conditional skipping (web/TLS only when requested), the
  approval pause, and safe continuation: an intrusive stage denied at the approval
  gate — or any stage that fails — never skips the tail, so cleanup (when a
  validation ran), the verification scan, and reporting always run when applicable.
  A failed stage is reflected in the run status while the tail still completes.
- API: create a run, advance/fail the current stage, and approve/deny the
  intrusive gate (approver/administrator); every transition is audited.
- A combined full-spectrum PDF report (executive posture, vulnerability results,
  validation summary, exposure changes, remediation roadmap, cleanup/verification
  summary) added to the report engine.

Verified: a full run completes; an intrusive stage can be denied while reports
still generate; stage failures are reflected and the tail still runs; and cleanup
and verification always run when applicable. ADR 0013 records the design.

### Added — Phase 11: Controlled pentest framework

A safety-first control plane for approval-gated validation. VulnaDash never runs
an exploit itself; it authorizes (or refuses) an allowlisted, probe-side
validation and records what happened.

- Allowlisted module policy: only allowlisted modules may be requested,
  denial-of-service and exploit categories are categorically blocked, and every
  module requires approval before it can run. The default pack ships
  **auxiliary/validation (detection) modules only** — no exploit modules or
  exploit-specific lists in the repository. The same allowlist is mirrored on the
  probe (`scout/internal/pentest`), so an unapproved or non-allowlisted module is
  also rejected locally.
- `RulesOfEngagement` and `PentestSession` models (+ migration). A session is
  created `pending_approval`; only an approver/administrator may approve it, which
  starts the session clock and sets a hard expiry (session timeout).
- A validation-candidate list (high/critical, unvalidated, open findings), a
  timeout sweep (`POST /pentest/sessions/run-timeouts`) that terminates
  timed-out sessions, and cleanup recording that closes out a session.
- A controlled-pentest PDF report (rules of engagement, methodology, validated
  weaknesses, cleanup confirmation, limitations, sign-off).

Verified: a non-allowlisted/DoS/exploit module is rejected (server and probe); a
session cannot run without approval; a session is terminated at timeout; cleanup
state is recorded; and a pentest PDF is generated. ADR 0012 records the design.

### Added — Phase 10: Remediation and verification

Findings gain a full remediation workflow and automatic verification.

- Finding fields for `owner_user_id`, `due_at`, `last_verified_at`,
  `risk_acceptance_id`, and `false_positive_reason`; append-only `FindingNote`s;
  and `RiskAcceptance` records (+ migration).
- Assignment, due dates, and status transitions via the finding PATCH, now
  authorized for operators/administrators *or the assigned owner* (so an owner can
  mark their finding ready for verification). Notes are readable by any org member
  and appended by any org member.
- Targeted verification rescan (`POST /findings/{id}/rescan`) creates a scan job
  for the finding's asset, tagged with the finding it verifies. When a scanner's
  results arrive, a verified finding that scanner no longer observes is
  automatically resolved as fixed; a reintroduced issue reopens via the existing
  recurrence logic.
- Risk acceptance: request (`POST /findings/{id}/risk-acceptances`), approve/reject
  (`PATCH /risk-acceptances/{id}`, approver/administrator), and an expiry sweep
  (`POST /risk-acceptances/run-expiry`) that reopens the finding and raises a
  `risk_acceptance_expired` change event — acceptances expire by default.

Verified: an owner marks a finding ready for verification; a verification rescan
resolves a fixed finding; a reintroduced issue reopens; and a risk-acceptance
expiry reopens the finding and raises an alert. ADR 0011 records the design.

### Added — Phase 9: ZAP web assessment

Web-application assessment via OWASP ZAP's Automation Framework, with scope
controls and an approval gate for active scanning.

- Probe ZAP adapter (`scout/internal/scanners/zap`): generates a scoped
  automation plan and runs ZAP with only allowlisted arguments. The passive
  profile spiders + passively analyzes only (no active attacks); the
  limited-active profile adds an active scan whose policy enables just an
  allowlisted set of rules (every other rule left off). The context's include
  paths are bound to the in-scope hosts, so the crawler/scanner cannot follow a
  redirect outside the authorized scope, and out-of-scope start URLs are rejected
  before ZAP runs.
- Backend: a `WebScanProfile`, an optional `web_scan` block on job creation that
  appends a ZAP `web` stage to the workflow, start-URL scope validation, and an
  approval gate — the active profile may only be requested by an administrator or
  pentest approver (a plain operator gets 403). A defensive ZAP `traditional-json`
  report parser normalizes alerts into web-application findings, wired into the
  result-upload routing (`scanner=zap`).

Verified: passive plans contain no active-scan job; limited-active plans use the
rule allowlist; include paths are bound to scope (redirects out of scope don't
match); active scans require approval; and a ZAP report ingests into deduplicated
web findings. ADR 0010 records the design.

### Fixed

- `deploy/Caddyfile` probe-mTLS guidance, after live validation against Caddy
  v2.11: use `client_auth mode require_and_verify` (the previously documented
  `mode request` neither requires nor verifies the client certificate, proxying
  no-cert and rogue-CA clients through), and inject the fingerprint with a lone
  `header_up` set (a delete + set together drop the header and 401 every probe).
  Confirmed that Caddy's `{http.request.tls.client.fingerprint}` matches the
  fingerprint the API stores per probe, so the mTLS handoff works end to end.

### Added — Phase 8: Reports

Every completed scan can be exported to PDF, CSV, and JSON (VulnaReport).

- `Report` model (+ migration) with type/format/status, storage path, SHA-256,
  size, and a parameters snapshot.
- A single point-in-time snapshot builder feeds every format, so artifacts are
  internally consistent and a stored report is reproducible even if the database
  changes afterward.
- Executive and technical PDFs (fpdf2, pure-Python, no system libraries;
  Latin-1-safe); findings/assets/services/CVE-exposure CSVs with stable,
  documented columns; and a versioned JSON bundle with a published JSON Schema.
- Generation renders each artifact, stores it with a SHA-256 checksum, and
  records a `Report`. API: `POST /reports`, `GET /reports`, `GET /reports/{id}`,
  and `GET /reports/{id}/download`, all organization-scoped so an unauthorized or
  cross-organization caller cannot download a report.
- Frontend Reports panel listing reports with authenticated downloads.

Verified: a completed scan produces all requested formats; PDFs render with
every section; CSVs use stable columns; a report is byte-identical when
re-downloaded after the underlying data changes; and cross-organization or
unauthenticated download is rejected. ADR 0009 records the design.

### Changed

- `httpx` moved from a dev-only to a runtime dependency (Phase 7's feed fetchers
  import it at runtime).
- `.gitignore` runtime-artifact rules (`/data/`, `/reports/`, `/evidence/`) are
  now anchored to the repository root so they no longer shadow source packages.

### Added — Phase 7: VulnaWatch CVE intelligence

Continuous vulnerability-intelligence monitoring: the server maintains a local
CVE/KEV/EPSS database and layers those signals onto findings.

- `CveRecord`, `ThreatIntelEnrichment`, and `FeedHealth` models (+ migration),
  plus `known_exploited`/`epss_score`/`epss_percentile` columns on findings.
- Defensive parsers for the NVD CVE API 2.0, the CISA KEV catalog, and the FIRST
  EPSS CSV (gzip-aware); malformed entries are skipped.
- A fetcher abstraction with bounded exponential-backoff retry, so syncs respect
  upstream rate limits and survive transient failures.
- Sync service that upserts intelligence, records per-feed health (including on
  failure), and enriches existing findings with CVSS/KEV/EPSS. A CVE newly added
  to KEV raises a `cve_added_to_kev` change event and flags the finding as known
  exploited; an EPSS score crossing the alert threshold raises
  `epss_threshold_crossed`.
- Conservative CPE matching engine assigning high/medium/low confidence.
- API: feed-health dashboard (`/feeds/health`), admin sync trigger
  (`/feeds/{source}/sync`), and CVE lookup (`/cve/{id}`). Frontend feed-health
  panel that surfaces a failing feed and offers an admin "Sync now" control.

Verified: an existing finding receives CVSS/KEV/EPSS enrichment; a simulated KEV
update raises a change event; a feed failure is recorded and visible; retries
degrade-but-succeed. ADR 0008 records the design.

### Added — Phase 6: Nuclei vulnerability and TLS scanning

The assessment workflow gains vulnerability and TLS stages, and the
orchestrator normalizes their output into a deduplicated findings database.

- `Finding` model (+ severity/type/validation/status enums + migration) with a
  canonical finding key (`org|asset|service|scanner|weakness`) for dedup.
- Defensive parsers: Nuclei JSONL and testssl.sh JSON are mapped to a
  scanner-agnostic finding shape; malformed lines are skipped.
- Ingestion maps findings to assets/services (by IP + port), deduplicates by
  the canonical key, and reopens resolved findings that recur — emitting
  `new_finding` / `finding_resolved` / `finding_reopened` change events.
- Result-upload endpoint routes by scanner (`nmap` → discovery ingest;
  `nuclei` / `testssl` → artifact store + finding ingest).
- Findings read API plus a workflow PATCH (validation/status, operator/admin).
- VulnaScout: a scanner-plugin interface and Workflow runner dispatch each job
  stage to the matching adapter, collecting per-stage output. Nuclei and
  testssl.sh adapters join the refactored Nmap adapter, all using allowlisted,
  typed arguments and a shared IP/CIDR target validator. Nuclei applies a safe
  template policy (excludes dos/intrusive/fuzzing/brute-force, limits
  severities); testssl scans the first single host on 443. A probe skips any
  stage whose scanner it lacks, and a failing stage does not fail the job.

Verified: a discovery scan followed by Nuclei/testssl uploads produces
normalized findings; a repeat upload deduplicates; a recurring resolved finding
reopens. ADR 0007 records the design.

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
