# ADR 0007: Nuclei/TLS Scanning and the Findings Model

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 6 (Nuclei vulnerability and TLS scanning)

## Context

Discovery (Phase 4) tells operators what is running; Phase 6 adds what is
*wrong* with it. The workflow gains a vulnerability stage (Nuclei) and a TLS
stage (testssl.sh), and the orchestrator turns their heterogeneous output into a
single, deduplicated findings database that later phases (CVE intelligence,
remediation, reporting) build on.

## Decisions

### 1. A scanner-agnostic `Finding` with a canonical dedup key

Each scanner speaks its own dialect, so parsers normalize output into one
`ParsedFinding` shape and ingestion persists a `Finding`. Deduplication uses a
`canonical_finding_key` = `sha256(org | asset | service | scanner |
weakness_key)`, where `weakness_key` is the scanner's stable identifier (Nuclei
template ID, testssl finding id). The same weakness re-reported on the same
service updates one row (bumping `last_seen_at`) rather than piling up
duplicates, which is what makes findings trend-able over time.

### 2. Findings recur and reopen through a lifecycle, not deletion

A finding carries a `status` (`open` / `resolved` / `reopened`). Ingestion never
deletes: an unseen finding is left for remediation workflow to resolve, and a
finding that recurs after being `resolved` is flipped to `reopened` (bumping
`reopened_count`) and emits a `finding_reopened` change event. First sight emits
`new_finding`. This reuses the Phase 5 change-event stream so the delta view
covers vulnerabilities, not just inventory.

### 3. The probe is a multi-stage plugin runner; adapters are allowlisted

A `Scanner` plugin interface (`Stage`, `Name`, `Run`) and a `Workflow` runner
replace the single hard-wired Nmap worker. The runner dispatches each job
workflow stage to the registered adapter and collects per-stage raw output.
Every adapter builds **allowlisted, typed arguments** — never a free-form
command string — and validates every target as a plain IP or CIDR through a
shared `ValidateTarget` (rejecting flag-like or shell-metachar targets) to close
argument injection. Nuclei runs under a safe template policy (excludes
`dos`/`intrusive`/`fuzzing`/`brute-force` tags, limits to low–critical
severities) consistent with non-destructive assessment mode; testssl.sh scans
the first single host on port 443 (it cannot take a range).

### 4. Missing scanners degrade gracefully; a failing stage never fails the job

The runner skips a stage whose plugin is not registered (the probe lacks that
scanner) and continues past a stage that errors, recording only the stages that
produced output. So an appliance with only Nmap still completes discovery, and a
Nuclei crash does not lose the discovery results. Empty Nuclei output (no
findings) is a valid result, distinguished from a run failure by the process
exit status.

### 5. Upload routing by scanner, not by content sniffing

The result-upload endpoint routes on an explicit `scanner` query parameter:
`nmap` → discovery ingest, `nuclei` / `testssl` → store artifact + finding
ingest. The client sets the matching content type (XML for Nmap, JSON
otherwise). Explicit routing keeps parser selection unambiguous and lets new
scanners register a route without content-type heuristics.

## Consequences

- Findings are deduplicated and lifecycle-tracked from the first scan, giving
  later phases (VulnaWatch CVE matching, VulnaVerify remediation) a stable
  substrate keyed by `canonical_finding_key`.
- Adding a scanner is: write an adapter (allowlisted args + `Scanner` interface),
  a parser to `ParsedFinding`, and a route entry — no core changes.
- The probe is resilient to partial tool availability and per-stage failure,
  which suits heterogeneous appliances.

## Alternatives considered

- **Storing raw scanner output only and parsing at read time:** rejected;
  normalizing at ingest is what enables dedup, cross-scanner queries, and change
  events. Raw artifacts are still stored for evidence.
- **Free-form scanner command templates in the job:** rejected as an injection
  and safety hazard; allowlisted typed arguments keep the probe’s behavior
  bounded and auditable.
- **Failing the whole job when any stage fails:** rejected; assessments are
  best-effort across independent stages, and losing discovery because a later
  stage crashed is worse than a partial result.
