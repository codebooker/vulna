<p align="center">
  <img src="brand/vulna-logo.png" alt="Vulna" width="440">
</p>

<p align="center">
  <strong>Self-hosted vulnerability management for one network or many locations.</strong>
</p>

<p align="center">
  <a href="https://vulna.dev"><strong>Website</strong></a>
  ·
  <a href="#installation">Installation</a>
  ·
  <a href="docs/">Documentation</a>
  ·
  <a href="https://github.com/codebooker/vulna/releases">Releases</a>
</p>

<p align="center">
  <a href="https://github.com/codebooker/vulna/actions/workflows/backend.yml"><img src="https://img.shields.io/github/actions/workflow/status/codebooker/vulna/backend.yml?branch=main&style=flat-square" alt="Backend CI status"></a>
  <a href="https://github.com/codebooker/vulna/releases"><img src="https://img.shields.io/github/v/release/codebooker/vulna?style=flat-square" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg?style=flat-square" alt="AGPL-3.0 license"></a>
</p>

Vulna is an open-source platform for discovering assets, identifying
vulnerabilities, tracking remediation, and coordinating authorized security
assessments across multiple locations. It combines established security tools
with centralized scope control, scheduling, evidence, reporting, and audit logs.

Vulna is self-hosted. Your inventory, findings, credentials, and reports remain
under your control.

> [!WARNING]
> **Authorized use only.** Only scan systems and networks that you own or have
> explicit written permission to test. Read the
> [authorized-use policy](docs/authorized-use.md) and [security policy](SECURITY.md)
> before deploying Vulna.

## Project status

Vulna is currently **pre-release software under active development**. It is not
yet recommended for production use. Interfaces, deployment files, and upgrade
behavior may change before version 1.0.0.

See the [changelog](CHANGELOG.md), [release process](docs/release-process.md), and
[security review checklist](docs/security-review-checklist.md) for current
release information.

## What Vulna provides

- Asset and service discovery with change tracking
- Nmap discovery, Nuclei vulnerability checks, and TLS assessment
- CVE intelligence from NVD, CISA KEV, and EPSS
- Scope-controlled scan scheduling across one or many sites
- Finding triage, ownership, risk acceptance, and verification scans
- Executive and technical reports in PDF, CSV, and JSON formats
- Signed jobs, mutual-TLS endpoint identities, cancellation, and audit logging
- Optional Prometheus metrics, Grafana dashboards, alerts, and diagnostics
- Backup, restore, update, rollback, and offline-operation workflows

Vulna is an orchestration and vulnerability-management layer around proven
open-source scanners. It does not replace those scanning engines.

## Choose a deployment model

Every installation begins with the central Vulna appliance. The appliance hosts
the web interface, API, database, scheduler, reporting services, and a bundled
local Scout.

| Deployment                 | Where scans run                                          | Best for                                                    |
| -------------------------- | -------------------------------------------------------- | ----------------------------------------------------------- |
| **Central appliance only** | On the appliance's bundled local Scout                   | Networks directly reachable from the appliance              |
| **Appliance + VulnaScout** | On a Scout installed at the remote location              | Most branch offices, client sites, and segmented networks   |
| **Appliance + VulnaRelay** | On the appliance, through a tunnel provided by the Relay | Constrained sites where scanners should not run at the edge |

You do **not** need to install a separate endpoint to scan a network reachable
from the central appliance. Its local Scout enrolls automatically, but starts
with no approved network scope and cannot scan until an administrator authorizes
one.

For remote locations, VulnaScout is the preferred option because it runs the
scanners and independently enforces scope at the edge. VulnaRelay is an advanced,
opt-in tunnel mode with no scanners on the remote host; scope is enforced by the
central egress controller. See [VulnaRelay](docs/relay.md) for the security model
and tradeoffs.

## How a scan works

1. An administrator adds a site and explicitly approves its network ranges.
2. Vulna creates a signed, time-limited job for the selected Scout.
3. The Scout verifies the job and its local policy before running any scanner.
4. Results return over mutual TLS and are normalized into assets, services, and
   findings.
5. Vulna correlates changes, enriches findings with CVE intelligence, and tracks
   remediation through verification.

Scouts initiate outbound connections to the appliance; the appliance does not
require an inbound management port on a Scout. Relay deployments use an
authenticated WireGuard tunnel instead. The [architecture overview](docs/architecture.md)
explains these communication paths in more detail.

## Installation

### Requirements

- A dedicated Linux host or virtual machine
- Docker Engine with Docker Compose v2
- `amd64` or `arm64` architecture
- Available TCP ports 80, 443, and 8443
- Available UDP port 51820 when VulnaRelay is enabled

Run the preflight command before installation to identify missing dependencies,
port conflicts, storage limitations, and unsupported settings:

```bash
vulna preflight
```

### Install from a signed release

Download the installer from the release you intend to use, review it, and then
run it with that release version:

```bash
curl -fsSLO https://github.com/codebooker/vulna/releases/download/<version>/install.sh
less install.sh
VULNA_VERSION=<version> sh install.sh -- install
```

The bootstrap verifies the Ed25519 signature and SHA-256 checksum of every
downloaded artifact before executing it. The installer performs host preflight,
generates strong secrets, installs the single-host stack, and starts the bundled
local Scout.

Replace `<version>` with a published tag such as `v1.0.0`. Do not copy the example
unchanged. For manual verification, non-interactive installs, dry runs, and
uninstallation, see the complete [installation guide](docs/installation/README.md).

### Evaluate from a source checkout

Until a signed release is available, the single-host stack can be built from a
trusted checkout:

```bash
git clone https://github.com/codebooker/vulna.git
cd vulna
cp .env.example .env
# Review and set the required values in .env.
docker compose -f docker-compose.yml -f docker-compose.single-host.yml up -d --build
```

The deployment migrates the database, creates the initial administration
environment, and enrolls the local Scout. Approve a network scope in the web
interface before attempting a scan. See the
[single-host deployment guide](deploy/single-host/README.md) for configuration
and first-run details.

## Main components

| Component       | Responsibility                                                                 |
| --------------- | ------------------------------------------------------------------------------ |
| **VulnaDash**   | Web interface, API, scheduling, findings, reporting, and central orchestration |
| **VulnaScout**  | Scope-enforcing assessment agent that runs scanner plugins locally             |
| **VulnaRelay**  | Scanner-free remote tunnel for centrally executed scans                        |
| **VulnaWatch**  | NVD, CISA KEV, EPSS, and advisory intelligence synchronization                 |
| **VulnaVerify** | Remediation workflow, targeted rescanning, and resolution tracking             |
| **VulnaForge**  | Scanner plugin SDK, adapter manifests, and parser contracts                    |
| **VulnaPulse**  | Metrics, dashboards, alerting, and operational health                          |
| **VulnaLab**    | Isolated demonstration and integration-test environment                        |

## Repository layout

```text
vulna/
├── dash/        # FastAPI backend and React/TypeScript frontend
├── scout/       # VulnaScout and VulnaRelay Go agents
├── cli/         # Installer and administration CLI
├── watch/       # Vulnerability intelligence workers
├── verify/      # Remediation and correlation logic
├── forge/       # Plugin SDK and schemas
├── pulse/       # Observability configuration
├── lab/         # Isolated demo and integration environment
├── shared/      # Shared schemas and examples
├── deploy/      # Containers and deployment configuration
├── scripts/     # Installation and release utilities
└── docs/        # Guides, architecture, threat model, and ADRs
```

## Development

Development requires Docker with Docker Compose. Running services directly also
requires Python 3.12+, Node.js 22+, and Go 1.26+.

```bash
cp .env.example .env
make dev
```

The development frontend is available at `http://localhost:5173`; the backend
health endpoint is `http://localhost:8000/health`.

Common commands:

```bash
make backend-dev       # Run the FastAPI backend with reload
make frontend-dev      # Run the Vite development server
make probe-build       # Build VulnaScout
make test              # Run backend, frontend, Scout, and CLI tests
make lint              # Run formatters, linters, type checks, and Go vet
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup conventions and contribution
requirements.

## Security and privacy

Vulna handles sensitive network and vulnerability information. Review the
[threat model](docs/threat-model.md), [security policy](SECURITY.md), and
[rules of engagement](docs/rules-of-engagement.md) before enabling scans.

Report suspected vulnerabilities privately using the process in
[SECURITY.md](SECURITY.md). Do not open a public issue for an unpatched security
problem.

## License

Vulna is licensed under the
[GNU Affero General Public License v3.0](LICENSE) (`AGPL-3.0-only`).
