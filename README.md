<p align="center">
  <img src="brand/vulna-logo.png" alt="Vulna" width="440">
</p>

<p align="center">
  <strong>Self-hosted security assessment across every site.</strong>
</p>

<p align="center">
  <a href="https://vulna.dev"><strong>vulna.dev</strong></a>
  ·
  <a href="#single-host-deployment">Install</a>
  ·
  <a href="docs/">Docs</a>
  ·
  <a href="https://github.com/codebooker/vulna/releases">Releases</a>
</p>

<p align="center">
  <a href="https://github.com/codebooker/vulna/actions/workflows/backend.yml"><img src="https://img.shields.io/github/actions/workflow/status/codebooker/vulna/backend.yml?branch=main&style=flat-square" alt="CI Status"></a>
  <a href="https://github.com/codebooker/vulna/releases"><img src="https://img.shields.io/github/v/release/codebooker/vulna?style=flat-square" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg?style=flat-square" alt="License"></a>
</p>

Vulna is an open-source, self-hosted, distributed platform for vulnerability
detection, authorized penetration testing, continuous CVE monitoring, and
multi-location security assessment. It is an orchestration, safety,
asset-correlation, evidence, remediation, and reporting layer around proven
open-source security tools — **not** another vulnerability engine.

> **⚠️ Authorized use only.** Vulna must only assess systems and networks the
> operator owns or has explicit written permission to test. See
> [`docs/authorized-use.md`](docs/authorized-use.md) and
> [`SECURITY.md`](SECURITY.md).

## Project status

**Pre-release / active development.** Vulna is being built in reviewed, testable
phases; each phase lands on `main` via a pull request with green CI. Current progress:

<details>
<summary><strong>View detailed development roadmap and phase status</strong></summary>

<br>

| Phase | Scope | Status |
|---|---|---|
| 0 | Repository foundation, CI, scaffolding | ✅ Done |
| 1 | Authentication, RBAC, orgs, sites, network scopes, audit log | ✅ Done |
| 2 | VulnaScout enrollment, internal CA, mTLS, heartbeat, revocation | ✅ Done |
| 3 | Ed25519-signed jobs & local policy, probe enforcement, cancellation | ✅ Done |
| 4 | Nmap discovery — assets/services, safe discovery profile, XML parsing | ✅ Done |
| 5 | Change detection — asset/port/version change events, delta view | ✅ Done |
| 6 | Nuclei vulnerability + testssl.sh TLS scanning — findings model, normalization, dedup, multi-stage workflow | ✅ Done |
| 7 | VulnaWatch CVE intelligence — NVD/KEV/EPSS sync, feed health, finding enrichment, CVE watch events | ✅ Done |
| 8 | Reports — executive/technical PDF, findings/assets/services/CVE CSVs, JSON bundle, storage, checksums, download authz | ✅ Done |
| 9 | ZAP web assessment — passive + limited-active profiles, generated automation YAML, scope controls, approval gate, result parsing | ✅ Done |
| 10 | Remediation & verification — assignment, due dates, notes, risk acceptance + expiry, targeted rescan, auto resolve/reopen | ✅ Done |
| 11 | Controlled pentest — rules of engagement, allowlisted (auxiliary-only) module policy, approval-gated sessions, timeouts, cleanup records, pentest report | ✅ Done |
| 12 | Full-spectrum workflow — multi-stage engine, conditional stages, approval pause, safe continuation on denial/failure, combined report, audit trail | ✅ Done |
| 13 | Appliance packaging — Docker probe, Debian/ARM64 packages, cloud-init, appliance console, update/rollback (identity & policy preserved) | ✅ Done |
| 14 | VulnaPulse observability — /metrics (no sensitive labels), Prometheus + Grafana + exporters, provisioned dashboards/alerts, monitoring compose profile | ✅ Done |
| 15 | Hardening & release — dependency scans (clean), SBOMs, backup/restore, signed+checksummed releases, security review checklist, sample lab | ✅ Done |
| 16 | VulnaRelay — optional thin tunnel/relay mode for constrained sites: off-by-default, central-egress scope enforcement, immediate kill switch, mTLS enrollment, no signing keys/scanner creds on the relay (opt-in; smart probe stays the default) | ✅ Done |
| 17 | First-class single-host deployment — one-command stack with an auto-enrolled, scope-gated local Scout, per-component health, migrate-on-start | ✅ Done |
| 18 | Safe installer & environment preflight — signed `vulna` CLI, verifying bootstrap, preflight checks, generated secrets, idempotent install, dry-run, clean uninstall | ✅ Done |
| 19 | Guided first run — resumable wizard, recovery codes, advisory network detection, scope guardrails, safe preset, pre-scan summary, isolated demo target | ✅ Done |
| 20 | Frictionless remote VulnaScout — per-site Add VulnaScout command, verified bootstrap, `doctor` connection test, local emergency stop, reset + self-revoke | ✅ Done |
| 21 | Opinionated scan presets & tuning — versioned presets, capability manager, why-skipped preview, hardware-aware tuning clamped to policy, validated custom presets | ✅ Done |
| 22 | Everyday UX — home dashboard, plain-language priority (fix now/plan/watch), consistent finding layout, one-click workflows, global search, sanitized evidence, a11y | ✅ Done |
| 23 | Networking/URL/TLS assistant — five access modes, trusted-proxy anti-spoofing, cert/DNS/clock validation, reverse-proxy snippet, safe URL-change plan, browser/Scout tests | ✅ Done |
| 24 | Boring, safe updates & rollback — signed release-manifest verification, `vulna update`/`rollback`, pre-update checks + auto backup, display-only update center | ✅ Done |
| 25 | Backups, restore & recovery — `vulna backup` (create/verify/restore/prune), versioned secret-free manifest, AES-256-GCM encryption, restore safety, recovery sheet | ✅ Done |
| 26 | Vulna Doctor & diagnostics — `vulna doctor` (human/JSON), System Health page, per-check impact/data-safety/next-step, allowlist-redacted support bundle, safe repairs, timeline | ✅ Done |
| 27 | Low-resource / ARM64 / offline — Lite/Standard/Full profiles + per-stage budgets, fail-closed storage backpressure, durable idempotent Scout result queue for intermittent links, signed data-only offline bundles, preset capability warnings | ✅ Done |
| 28 | Unified Maintenance Center — one health overview (green/warn/action) across updates, feeds, backups, certs, storage & stuck jobs, storage budgets, fail-closed retention cleanup with preview manifest + legal holds + reauth, certificate-rotation preflight, self-hosting health report | ✅ Done |
| 29 | Notifications & self-hosted integrations — email + signed webhooks (versioned, HMAC, replay-resistant, selected-fields-only), SSRF-validated destinations, event subscriptions, immediate/digest policies, quiet hours + dedup, encrypted write-only credentials + rotation, decoupled non-blocking delivery, history + test | ✅ Done |
| 30 | Documentation, demo & guided learning — docs home with Simple/Advanced paths + deployment models, task guides (quick start, terminology, findings, troubleshooting), safe demo mode (documentation-range sample data, real scans blocked), contextual help catalogue, exposure checklist, CI doc-integrity + insecure-recommendation lint | ✅ Done |
| 31 | Privacy, data ownership & portability — outbound-connections transparency (never phones home for updates), opt-in-only anonymous telemetry with field-level preview + local-only analytics, secret inventory (no values), versioned+checksummed data export with published schema + untrusted-import validation (no cross-org bypass), move-host plan, machine-readable data map | ✅ Done |
| 32 | Release qualification & ecosystem packaging — published support matrix, release-blocking regression gate (setup/scope/signing/cancellation/backup+restore/authorization), packaging policy (official/community/experimental), release-process + artifact/key-rotation docs, install-diagnostics issue template, reference benchmarks, simple-path contributor guide | ✅ Done |

</details>

Not yet ready for production use. See the [CHANGELOG](CHANGELOG.md) for details.

## Product family

| Name | Purpose |
|---|---|
| **Vulna** | Overall project, product family, and repository identity |
| **VulnaDash** | Self-hosted web app, API, scheduler, findings database, reporting, and central orchestration |
| **VulnaScout** | Remote assessment appliance (VM, mini PC, Raspberry Pi-class device, container, or Linux service) |
| **VulnaWatch** | CVE / CISA KEV / EPSS / advisory intelligence synchronization and matching |
| **VulnaVerify** | Remediation workflow, targeted rescanning, resolution confirmation, reopen detection |
| **VulnaForge** | Scanner plugin SDK, adapter manifests, and parser contracts |
| **VulnaPulse** | Prometheus metrics, Grafana dashboards, alerting, and health telemetry |
| **VulnaLab** | Isolated development, demonstration, and intentionally vulnerable target environment |
| **VulnaReport** | PDF / CSV / JSON report and artifact generation |

## Repository layout

```text
vulna/
├── dash/        # VulnaDash — FastAPI backend + React/TS frontend
├── scout/       # VulnaScout — Go probe agent, plugins, packaging
├── cli/         # vulna — host installer & administration CLI (Go)
├── watch/       # VulnaWatch — CVE/KEV/EPSS intelligence workers
├── verify/      # VulnaVerify — remediation & correlation logic
├── forge/       # VulnaForge — plugin SDK and schemas
├── pulse/       # VulnaPulse — dashboards and metrics
├── lab/         # VulnaLab — integration / demo environment
├── shared/      # Shared JSON schemas and examples
├── scripts/     # Install, backup, restore, appliance build
├── deploy/      # Reverse-proxy and deployment config
└── docs/        # Architecture, threat model, ADRs, guides
```

## Quick start (development)

Prerequisites: Docker + Docker Compose. For running services individually you
also need Python 3.12+, Node 20+, and Go 1.22+.

```bash
# Copy environment template and adjust as needed
cp .env.example .env

# Start the development stack (Postgres, Redis, API, frontend)
make dev
# or: docker compose -f docker-compose.dev.yml up --build

# Backend health:   http://localhost:8000/health
# Frontend:         http://localhost:5173
```

Run components directly during development:

```bash
make backend-dev     # FastAPI with autoreload on :8000
make frontend-dev    # Vite dev server on :5173
make probe-build     # build the VulnaScout binary
./scout/bin/vulnascout version
./scout/bin/vulnascout self-test
```

Run tests and linters:

```bash
make test    # backend pytest, frontend vitest, go test
make lint    # ruff + mypy, eslint, go vet
```

## Single-host deployment

The supported way to install Vulna on one host is the `vulna` installer CLI. It
runs environment preflight, generates strong secrets, and materializes the
deployment; it is safe to re-run, dry-run, and uninstall without deleting data.

```bash
# Verified bootstrap: downloads a pinned, signed release and checks it before running.
curl -fsSLO https://vulna.dev/install.sh
less install.sh                       # review it first
sh install.sh -- install
```

The bootstrap is hosted at [`vulna.dev/install.sh`](https://vulna.dev/install.sh)
(and, for enrolling a remote probe, [`vulna.dev/install-scout.sh`](https://vulna.dev/install-scout.sh)).
Both are mirrored verbatim from [`scripts/`](scripts/), so what you review at that
URL is exactly what this repository ships. They are verify-first: each downloads a
pinned, signed release and checks a SHA-256 checksum plus an Ed25519 signature
before running anything, so they refuse to run until a signed release is published
rather than executing unverified content. The equivalent from a checkout is
`sh scripts/install.sh -- install`.

See [`docs/installation/`](docs/installation/README.md) for the manual
(no-pipeline) path and [ADR 0018](docs/adr/0018-installer-and-preflight.md).

Under the hood this brings up the single-host overlay directly if you prefer:

```bash
cp .env.example .env    # set POSTGRES_PASSWORD, VULNA_SECRET_KEY, VULNA_ADMIN_*
docker compose -f docker-compose.yml -f docker-compose.single-host.yml up -d
```

Either way, the stack migrates its database, seeds an admin and a local site, and
**auto-enrolls a co-located Scout** over the same mutual-TLS boundary as a remote
one. The local Scout comes up connected but **scope-gated** — it can scan nothing
until you approve a network scope. See
[`deploy/single-host/README.md`](deploy/single-host/README.md) and
[ADR 0017](docs/adr/0017-single-host-deployment.md).

## Security

Vulna is security-sensitive software. Please read
[`SECURITY.md`](SECURITY.md), [`docs/threat-model.md`](docs/threat-model.md),
and [`docs/authorized-use.md`](docs/authorized-use.md) before deploying.

Report vulnerabilities responsibly per [`SECURITY.md`](SECURITY.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only).
See [`LICENSE`](LICENSE).
