# ADR 0006: Change Detection

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 5 (Change detection)

## Context

Assessments are only useful over time if operators can see what changed between
scans — new assets, ports opening or closing, service versions changing. Phase 5
records these as change events during result ingestion.

## Decisions

### 1. Detect changes at ingestion time, against the live inventory

Change detection runs inside the ingestion service, comparing the incoming scan
to the asset's **current** services *before* upserting them. New assets emit
`asset_discovered`; for existing assets, ports present now but not before emit
`new_port_opened`, ports previously open but now absent emit `port_closed`
(and are marked closed), and a changed product/version emits
`service_version_changed`. This keeps detection deterministic and colocated with
the state it compares, and needs no separate "diff two scans" job.

### 2. Append-only change events with before/after context

Each `ChangeEvent` is append-only and carries `event_type`, a human summary,
`before_json`/`after_json`, and links to the site, asset, and scan job. The
delta API filters by any of these, so "compare this asset over time" or "what
did this scan change" are simple queries.

### 3. Port-closed detection assumes comparable scan coverage

Nmap XML reports only interesting (open) ports, so "previously open, now absent"
is treated as closed. This is correct when successive scans cover the same
ports (the normal case for a repeated profile). A port that simply was not
scanned could be mis-reported as closed; recording the scanned port range per
scan to disambiguate is a future refinement.

## Consequences

- The delta view is populated automatically by every scan; no extra pipeline.
- Detection is O(services-per-asset) per host and runs in the same transaction
  as ingestion, so a scan and its change events commit atomically.
- Richer event types (IP changed, TLS certificate changed, new vulnerability,
  KEV/EPSS changes) plug into the same model as later phases add their data.

## Alternatives considered

- **Diffing two stored scan snapshots on demand:** rejected; storing and
  diffing full snapshots is heavier and the live-inventory comparison already
  yields the events operators want.
- **Emitting per-port events for brand-new assets:** rejected as noisy; a new
  asset yields a single `asset_discovered`, and port events start from the next
  scan.
