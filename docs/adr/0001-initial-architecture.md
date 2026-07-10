# ADR 0001: Initial Architecture and Technology Choices

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 0 (Repository foundation)

## Context

Vulna is a self-hosted, distributed platform for authorized vulnerability
assessment and penetration testing across multiple sites. It consists of a
central orchestrator (VulnaDash) and lightweight remote appliances (VulnaScout).
Before writing implementation code we record the foundational technology and
boundary decisions so later phases build on a stable, security-first base.

The guiding principle from the build plan is that Vulna is **not** a new
vulnerability engine — it is an orchestration, safety, correlation, evidence,
remediation, and reporting layer around proven open-source tools. Every decision
below is made to keep that layer safe, deployable, and maintainable.

## Decisions

### 1. Monorepo with clear service boundaries

We use a single repository with top-level directories per component (`dash/`,
`scout/`, `watch/`, `verify/`, `forge/`, `pulse/`, `lab/`, `shared/`). This keeps
shared schemas and cross-component changes atomic while preserving the option to
extract independently deployable services later. Service boundaries — not
directory layout — are the contract, and they are defined by the versioned JSON
Schemas in `shared/schemas/` and the REST API.

### 2. Backend: Python 3.12 + FastAPI + SQLAlchemy 2 + Alembic + PostgreSQL

FastAPI gives typed request/response models (Pydantic), automatic OpenAPI, and
first-class async. SQLAlchemy 2.x + Alembic provide a mature ORM and migration
story. PostgreSQL is the system of record for assets, findings, and audit data,
which benefit from relational integrity, JSONB, and strong indexing.

### 3. Queue: Redis + a task framework (Dramatiq or Celery)

Scans, result normalization, CVE synchronization, and report generation are
asynchronous. Redis backs the task queue and cache. The specific task framework
(Dramatiq preferred for simplicity, Celery acceptable) is deferred to Phase 1/2
when workers are introduced; Phase 0 only provisions Redis.

### 4. Frontend: React + TypeScript + Vite

A TypeScript SPA with Vite for fast builds, TanStack Query/Table for data
fetching and grids, React Hook Form + Zod for typed forms and validation, and an
accessible component approach (shadcn/ui-style). This matches the data-dense,
role-driven UI the product needs.

### 5. Probe: Go, single static binary

VulnaScout must run on constrained x86-64 and ARM64 hardware (mini PCs,
Raspberry Pi-class devices) and be trivial to deploy as a systemd service or
container. A single statically linked Go binary with SQLite local state, easy
cross-compilation, and strong child-process control fits these constraints far
better than a runtime-heavy alternative.

### 6. Reverse proxy: Caddy

Caddy provides simple automatic TLS for production and an easy HTTP-only lab
mode, reducing operator burden.

### 7. Reporting: Jinja2 + WeasyPrint

HTML templates rendered to PDF give reproducible, brandable reports without a
headless browser dependency. CSV/JSON exports use the standard library.

### 8. Security boundaries (non-negotiable)

- **Outbound-only, mutually authenticated probes.** Probes initiate all
  communication over HTTPS with mTLS. No inbound management port.
- **Pull model.** The orchestrator offers signed jobs; it never pushes commands.
- **No arbitrary remote shell.** Scanners run via typed, versioned plugin
  manifests with allowlisted arguments — never a free-form command string.
- **Signed jobs and local policy (Ed25519).** Probes independently enforce their
  signed local policy and reject unsigned, altered, expired, or out-of-scope jobs.
- **Untrusted scanner output.** All scanner output is strictly, size-bounded
  parsed and sanitized before storage or rendering.
- **Least privilege + encryption at rest.** Evidence and credentials are
  encrypted; the audit log is append-only; secrets come only from the
  environment or a secrets manager.

### 9. Multi-organization schema from day one

Even though the MVP may expose a single organization, every relevant table
carries organization ownership so tenant isolation can be enforced and tested
throughout.

## Consequences

- Contributors work across three language ecosystems (Python, TypeScript, Go);
  CI runs a matrix covering all three, including ARM64 probe cross-compilation.
- The pull-based, signed-job model adds latency versus a push channel but removes
  the need for inbound ports and dramatically shrinks the probe attack surface.
- Choosing established tools (FastAPI, React, Go, Postgres, Redis, Caddy) keeps
  the barrier to contribution low and the supply chain well understood.
- Deferring the concrete task framework and any assessment logic keeps Phase 0
  small and reviewable, per the "one phase at a time" rule.

## Alternatives considered

- **Backend in Go or Node:** rejected to keep the data/reporting/intelligence
  layer in Python's strong ecosystem (Pydantic, WeasyPrint, data tooling).
- **Push/websocket command channel to probes:** rejected; it requires inbound
  connectivity or a persistent control channel and increases attack surface.
- **Polyrepo:** rejected for now; atomic cross-component schema changes and a
  single CI surface are more valuable at this stage than independent release
  cadences.
