# Vulna Architecture

This document gives a high-level overview of Vulna's architecture. It
complements [`VULNA_CODEX_BUILD_PLAN.md`](../VULNA_CODEX_BUILD_PLAN.md), which is
the authoritative specification, and the Architecture Decision Records in
[`adr/`](adr/).

## Overview

Vulna is a distributed platform with a central orchestrator (**VulnaDash**) and
lightweight remote appliances (**VulnaScout**) deployed at each site. Probes
initiate all communication outbound over HTTPS with mutual TLS; the orchestrator
never opens a connection to a probe and never sends an arbitrary command.

```text
                         ┌──────────────┐
                         │  Web Browser │
                         └──────┬───────┘
                                │ HTTPS
                                ▼
┌──────────────────────────────────────────────────────────────┐
│                 VulnaDash Central Orchestrator                 │
│                                                                │
│  Caddy ─▶ Web/API (FastAPI) ─▶ Workers (queue / scheduler)     │
│                │                        │                      │
│     PostgreSQL (data/tasks)        Redis (cache)               │
│                │                        │                      │
│         Report Service          CVE Intelligence              │
│         (PDF/CSV/JSON)          (NVD / KEV / EPSS)             │
└───────────────────────────┬───────────────────────────────────┘
                            │ Outbound HTTPS + mTLS (probe-initiated)
        ┌───────────────────┼────────────────────┐
        ▼                   ▼                     ▼
   VulnaScout A        VulnaScout B          VulnaScout C
   Local Policy        Local Policy          Local Policy
   Scanner Plugins     Scanner Plugins       Scanner Plugins
        │                   │                     │
   Approved CIDRs      Approved CIDRs        Approved CIDRs
```

## Components

### VulnaDash (`dash/`)

- **backend/** — FastAPI application exposing the REST API, authentication and
  RBAC, the job scheduler, findings database access, CVE intelligence
  (VulnaWatch), reporting controls (VulnaReport), and workflow orchestration.
  Backed by PostgreSQL (SQLAlchemy 2.x + Alembic migrations) and Redis caching.
- **frontend/** — React + TypeScript single-page app (Vite) providing the
  dashboard, sites, probes, scans, assets, findings, CVE intelligence,
  remediation, reports, and administration pages.

The scheduler and worker are dedicated processes built from the API image. They
coordinate through PostgreSQL-leased tasks and advisory-lock leader election; no
periodic loop runs inside the web process. See
[Durable scheduler and worker](background-tasks.md).
The worker shares the API's persistent signing-key and report/evidence volumes so
scheduled jobs retain the same trust identity and artifacts survive restarts.

Asset context is organization-owned and independent from authorization. Normalized
tags and bounded JSON-AST group rules produce materialized, explainable membership;
one shared resolver applies finding → asset → group → site → department ownership.
Phase 39 permission and site predicates still govern every inventory and report
query. See [Asset context, groups, and ownership](asset-context.md) and
[ADR 0041](adr/0041-asset-context-groups-ownership.md).

Finding priority is produced by an organization-selected immutable risk-profile
version. Each calculation appends its normalized inputs, factor contributions, and
input hash; the four friendly buckets are derived from the resulting `0–100` score.
Remediation units auto-group exact keys only, while fuzzy proposals require explicit
review. Bounded finding decisions are evidence-backed and expire through the durable
worker sweep. See [Explainable risk and remediation](explainable-risk.md) and
[ADR 0042](adr/0042-explainable-risk-remediation.md).

Authenticated inventory resolves one purpose-bound credential per protocol through
asset → group → tag → network → site → preset precedence. A signed job carries only
an authenticated ciphertext envelope bound to its id, expiry, and one opted-in
Scout's enrollment X25519 key. The Scout decrypts after its normal policy/scope
checks and runs fixed read-only SSH or WinRM collectors without persisting secret
material. See [Authenticated inventory](authenticated-inventory.md) and
[ADR 0043](adr/0043-authenticated-inventory-credentials.md).

### VulnaScout (`scout/`)

A single statically linked Go binary deployed as a systemd service, container,
or appliance image. It enrolls with the orchestrator (CSR → client certificate),
polls for signed jobs, enforces its signed local policy independently, runs
scanner plugins in isolated child processes with resource limits, and uploads
results in resumable chunks. Local durable state lives in SQLite.

### Supporting components

- **watch/** (VulnaWatch) — CVE/KEV/EPSS synchronization and matching workers.
- **verify/** (VulnaVerify) — asset identity, finding correlation, remediation,
  and verification-rescan logic.
- **forge/** (VulnaForge) — scanner plugin SDK, manifest and parser contracts.
- **pulse/** (VulnaPulse) — Prometheus/Grafana observability (optional profile).
- **lab/** (VulnaLab) — isolated integration/demo environment.
- **shared/** — versioned JSON Schemas (job, result, plugin, policy) and examples.

## Communication model

Vulna uses a **pull model** rather than an always-open command channel:

1. The probe sends periodic heartbeats (`POST /api/v1/probes/{id}/heartbeat`).
2. The probe polls for work (`POST /api/v1/probes/{id}/jobs/next`) and receives
   either nothing or a signed job envelope.
3. The probe validates the signature, expiry, and local policy before executing.
4. Results are uploaded in chunks (`POST .../jobs/{job_id}/results`) with content
   hashes; the server acknowledges durable receipt.

## Defense in depth

Every job is validated in the web app, in the API, in the scheduler, at signing
time, on receipt by the probe, before each scanner stage, and before following
any redirect or discovered target. See [`threat-model.md`](threat-model.md).

## Technology choices

Summarized here; rationale lives in [`adr/0001-initial-architecture.md`](adr/0001-initial-architecture.md).

| Area | Choice |
|---|---|
| Backend | Python 3.12+, FastAPI, SQLAlchemy 2.x, Alembic, Pydantic |
| Queue | PostgreSQL leased tasks + advisory-lock scheduler election |
| Database | PostgreSQL |
| Frontend | React, TypeScript, Vite, TanStack Query/Table |
| Probe | Go (single static binary), SQLite local state |
| Reverse proxy | Caddy |
| Reporting | Jinja2 + WeasyPrint |
| Job authenticity | Ed25519 signatures |
| Probe transport | Periodic HTTPS polling with mTLS |
