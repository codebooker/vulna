# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
