# ADR 0015: Observability (VulnaPulse)

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 14 (VulnaPulse observability)

## Context

Operators need to see that the platform is healthy — probes online, feeds fresh,
scans progressing — without standing up bespoke tooling, and without the metrics
surface becoming a data-leak channel. Phase 14 adds a Prometheus/Grafana stack
and a VulnaDash metrics endpoint under a hard constraint: no sensitive assessment
content in metrics (build plan Phase 14).

## Decisions

### 1. Aggregate-only metrics, sensitive content never in labels

`/metrics` exposes counts and timestamps grouped by low-cardinality enum labels
(severity, status, feed source) and opaque UUIDs (probe id). It never places a
finding title, description, evidence, IP address, or CVE id in any label or value.
This is enforced by construction — the renderer only ever emits grouped counts and
per-probe/per-feed gauges — and guarded by a test that asserts a seeded finding's
title, its asset IP, and CVE ids are absent from the output. A metrics endpoint is
an exfiltration surface; treating it as one is the whole point.

### 2. Hand-rolled exposition, no client dependency

The Prometheus text format is trivial, so it is rendered directly rather than
pulling in a metrics client. This keeps full control over exactly which series and
labels are emitted (the sensitive-data guarantee) and adds no dependency. The
endpoint queries current aggregates on scrape; at the platform's scale that is
cheap and always correct, with no in-process counter state to drift.

### 3. Internal scrape only, not publicly proxied

The public Caddy proxy routes `/api/*`, docs, and `/health` to the API but not
`/metrics`, so the endpoint is reachable only on the internal Docker network where
Prometheus scrapes `api:8000/metrics` directly. Even though the metrics are
aggregate, keeping them off the public surface is defense in depth.

### 4. Opt-in, fully provisioned monitoring profile

The stack lives behind a Compose `monitoring` profile
(`docker compose --profile monitoring up -d`), so it never runs unless requested.
Grafana's datasource and the "Vulna Overview" dashboard are provisioned from disk
(no manual import), and Prometheus loads alert rules including a stale-CVE-feed
alert derived from `vulna_feed_last_success_timestamp_seconds` — the same feed
freshness the app already tracks.

## Consequences

- One command brings up dashboards and alerts wired to VulnaDash and the
  infrastructure exporters.
- The metrics contract is safe to expose to an ops team without leaking
  assessment content.
- Feed staleness, probe outages, and a down VulnaDash are alertable out of the box.

## Alternatives considered

- **`prometheus_client` with in-process counters:** rejected; it adds a dependency
  and in-process counter state that can drift from the database, and it makes the
  no-sensitive-labels guarantee harder to audit than a single renderer.
- **Exposing richer per-finding metrics for drill-down:** rejected outright; that
  is exactly the sensitive-data leak the requirement forbids. Drill-down belongs in
  the authenticated API and reports, not in metrics.
- **Running monitoring by default:** rejected; it is opt-in via a Compose profile
  so the base stack stays lean.
