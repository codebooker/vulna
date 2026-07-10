<p align="center">
  <img src="brand/vulna-logo.png" alt="Vulna" width="440">
</p>

<p align="center">
  <strong>Self-hosted security assessment across every site.</strong>
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

## Project status

This repository is being built in small, testable milestones (Phase 0 through
Phase 15) as described in [`VULNA_CODEX_BUILD_PLAN.md`](VULNA_CODEX_BUILD_PLAN.md).

**Current phase: Phase 0 — Repository foundation.** This provides the monorepo
scaffolding, a development Docker Compose stack, a FastAPI backend with a health
endpoint, a React/TypeScript frontend with a health page, a Go probe module with
`version` and `self-test` commands, linting/formatting, a `Makefile`, and CI. No
assessment functionality is implemented yet.

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
