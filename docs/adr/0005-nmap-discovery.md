# ADR 0005: Nmap Discovery and the Asset Inventory

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 4 (Nmap discovery)

## Context

Phase 4 turns signed jobs into real work: the probe runs Nmap against approved
targets and the orchestrator normalizes the results into an asset and service
inventory that later phases (change detection, vulnerability matching,
reporting) build on.

## Decisions

### 1. Allowlisted, injection-safe scanner arguments

The probe never receives or executes a free-form command string (build plan
Sections 4.4, 12.3). The Nmap adapter builds arguments from a **typed profile**
plus targets, emitting only allowlisted flags. Targets are validated as plain
IPs/CIDRs and rejected if they could be mistaken for a flag (leading `-`) or
contain anything but an address — an argument-injection defense that is unit
tested. Nmap is invoked via `exec` with an argument slice (no shell).

### 2. Safe, unprivileged discovery profile

The default discovery profile uses a TCP connect scan (`-sT`) with light service
detection (`-sV`) and a bounded top-ports list, which needs **no raw sockets or
root**. This matches the hardened, unprivileged systemd service; raw-socket
scan types are intentionally excluded. The job's packet-rate limit is applied
via `--max-rate`.

### 3. Untrusted scanner output is parsed defensively

Scanner output is untrusted. The XML is parsed with `defusedxml`, which rejects
XML external-entity and entity-expansion ("billion laughs") attacks, and uploads
are size-bounded. This is verified with malicious-input tests, and confirmed
against real Nmap 7.99 output (which includes a DTD declaration).

### 4. Identity-based deduplication

Assets are matched by identifier — IP first, then MAC — not by database row, so a
repeated scan **updates** an existing asset and its services rather than creating
duplicates. Services are keyed by `(asset, transport, port)`. This is the seed of
the fuller asset-identity engine described in the build plan; richer weighted
evidence (hostnames, TLS/SSH fingerprints, SNMP, serials) is layered on later.

### 5. Defense in depth on scope

The probe enforces the signed local policy before scanning (a target must be in
scope), and the orchestrator also validates job targets against approved scopes
at creation time. Neither trusts the other; out-of-scope targets are rejected on
both sides.

### 6. Raw-output retention in the database (for now)

Each upload retains the raw scanner output verbatim as a `ScanArtifact` so scans
are reproducible and auditable. Phase 4 stores it in the database for
simplicity; encrypted, filesystem/object-storage evidence with redaction arrives
with the reporting subsystem.

## Consequences

- The end-to-end path (probe adapter → real nmap → parse → dedup → inventory) is
  validated with real nmap locally, so a lab VM was not required for Phase 4.
- Storing raw output in the database is fine for small discovery XML but will
  move to object storage before large scans or long retention.
- The connect-scan profile is safe and portable but less stealthy and slightly
  slower than a SYN scan; that is an acceptable trade for running unprivileged.

## Alternatives considered

- **SYN scan (`-sS`) / OS detection (`-O`):** rejected for the default profile;
  they need raw sockets/root, conflicting with the unprivileged agent. They can
  be offered later via a privileged, narrowly-scoped scanner helper.
- **Parsing Nmap's grepable/JSON output:** rejected; XML is the most complete and
  stable machine format, and defensive XML parsing is well understood.
- **Deduplicating by IP address in the row itself:** rejected in favor of
  separate identifiers, so an asset can carry multiple identities and survive IP
  changes.
