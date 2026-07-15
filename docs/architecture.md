# Vulna Architecture

This document gives a high-level overview of the current Vulna architecture. The
security rationale and historical design decisions live in the
[Architecture Decision Records](adr/).

## Overview

Vulna is a distributed platform with a central appliance (**VulnaDash**), an
auto-enrolled local **VulnaScout**, and optional remote endpoints. A remote
VulnaScout runs scanners at its site. A **VulnaRelay** runs no scanners; it
provides a constrained WireGuard path so the appliance's local Scout can assess
an approved remote network.

Scouts initiate all control communication outbound over HTTPS with mutual TLS;
the orchestrator never opens a management connection to a Scout and never sends
an arbitrary command. Relays use an mTLS control channel plus a WireGuard tunnel.

```text
                         ┌──────────────┐
                         │  Web Browser │
                         └──────┬───────┘
                                │ HTTPS
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│                    Vulna central appliance                          │
│                                                                     │
│  Caddy ─▶ Web/API ─▶ PostgreSQL tasks/data ─▶ scheduler + workers   │
│              │              │                     │                 │
│       identity/RBAC    reports + evidence      CVE intelligence     │
│              │                                    │                 │
│              └──────── local Scout + scanners ────┘                 │
│                              │                                      │
│                  central Relay egress controller                    │
└──────────────────┬───────────┴────────────────────┬─────────────────┘
                   │ outbound HTTPS + mTLS          │ WireGuard
          ┌────────┴────────┐                       ▼
          ▼                 ▼                  VulnaRelay
   remote Scout A    remote Scout B                 │
   signed policy     signed policy             approved site LAN
   scanner plugins   scanner plugins
          │                 │
   approved LAN A     approved LAN B
```

## Components

### VulnaDash (`dash/`)

- **backend/** — FastAPI application exposing the REST API, authentication and
  RBAC, the job scheduler, findings database access, CVE intelligence
  (VulnaWatch), reporting controls (VulnaReport), and workflow orchestration.
  Backed by PostgreSQL (SQLAlchemy 2.x + Alembic migrations) and Redis caching.
- **frontend/** — React + TypeScript single-page app (Vite) providing the
  dashboard, sites, appliances, scans, assets, findings, CVE intelligence,
  inventory, remediation, reports, identity, integrations, and administration
  pages. Routes and API reads are permission- and site-aware.

The scheduler and worker are dedicated processes built from the API image. They
coordinate through PostgreSQL-leased tasks and advisory-lock leader election; no
periodic loop runs inside the web process. See
[Durable scheduler and worker](background-tasks.md).
The worker shares the API's persistent signing-key and report/evidence volumes so
scheduled jobs retain the same trust identity and artifacts survive restarts.

Asset context is organization-owned and independent from authorization. Normalized
tags and bounded JSON-AST group rules produce materialized, explainable membership;
one shared resolver applies finding → asset → group → site → department ownership.
Permission and site predicates govern every inventory and report query. See
[Asset context, groups, and ownership](asset-context.md) and
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

Remediation deadlines are immutable calculations selected by uniquely prioritized,
first-match SLA policies, with append-only exception, pause/resume, breach, and
completion history. External tickets sit behind an idempotent adapter contract:
the API commits the finding first, then the durable worker sends only selected
fields and persists the remote outcome independently. See [Remediation SLAs and
ticket synchronization](sla-ticketing.md) and [ADR 0044](adr/0044-sla-ticket-sync-boundary.md).

Passive inventory connectors expose a read-only provider contract and feed an
append-only observation ledger. Deterministic reconciliation materializes current
source links while keeping every merge reversible; lifecycle events and daily
aggregates power permission-scoped analytics and report templates. See
[Inventory intelligence](passive-inventory.md) and
[ADR 0045](adr/0045-passive-inventory-reconciliation.md).

### VulnaScout (`scout/`)

A single statically linked Go binary deployed as a systemd service, container,
or appliance image. It enrolls with the orchestrator (CSR → client certificate),
polls for signed jobs, enforces its signed local policy independently, runs
scanner plugins in isolated child processes with resource limits, and uploads
results in resumable chunks. Local durable state lives in SQLite.

The same source tree also builds `vulnarelay`, a separate scanner-free entrypoint.
It enrolls with a site-bound one-time token, holds an mTLS control certificate and
its WireGuard private key, reconciles approved/denied routes, and reports tunnel
health. It never receives scanner credentials or job-signing private keys. See
[VulnaRelay](relay.md).

### Supporting components

- **watch/** (VulnaWatch) — CVE/KEV/EPSS synchronization and matching workers.
- **verify/** (VulnaVerify) — asset identity, finding correlation, remediation,
  and verification-rescan logic.
- **forge/** (VulnaForge) — scanner plugin SDK, manifest and parser contracts.
- **pulse/** (VulnaPulse) — Prometheus/Grafana observability (optional profile).
- **lab/** (VulnaLab) — isolated integration/demo environment.
- **shared/** — versioned JSON Schemas (job, result, plugin, policy) and examples.

## Scout communication model

Vulna uses a **pull model** rather than an always-open command channel:

1. The probe sends periodic heartbeats (`POST /api/v1/probes/{id}/heartbeat`).
2. The probe polls for work (`POST /api/v1/probes/{id}/jobs/next`) and receives
   either nothing or a signed job envelope.
3. The probe validates the signature, expiry, and local policy before executing.
4. Results are uploaded in chunks (`POST .../jobs/{job_id}/results`) with content
   hashes; the server acknowledges durable receipt.

## Relay communication model

1. An administrator explicitly enables Relay mode and creates a site-bound,
   single-use enrollment command.
2. The endpoint enrolls over the mTLS control listener and receives its tunnel
   address, central public key, endpoint, and scoped routing configuration.
3. The central egress controller materializes only enrolled, current, non-killed
   peers and their approved/denied ranges into WireGuard and firewall state.
4. The Relay applies matching forwarding and NAT rules toward its site LAN.
5. Relay-backed jobs are dispatched only to the configured central Scout. Traffic
   is permitted only while both policy layers allow the target and the tunnel is
   up.

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
