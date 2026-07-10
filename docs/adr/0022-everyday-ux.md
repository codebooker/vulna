# ADR 0022: Everyday UX for Homelabs and Small Teams

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 22 (Everyday UX for Homelabs and Small Teams)

## Context

Vulna's data model is complete, but the product still spoke in CVEs, scanner
output, and enterprise risk language. This phase makes it useful to people who do
not do security full-time, without discarding the formal data experts rely on.

## Decisions

### 1. A plain-language priority model that never overstates uncertainty

`app/services/priority.py` maps a finding's severity, KEV, EPSS, validation, and
detection confidence to one of four everyday buckets — **fix now**, **plan a fix**,
**watch**, **informational** — while the formal severity/CVSS/confidence remain on
the record. The overriding rule (a security constraint) is that a **low-confidence
match is never presented as a confirmed, fix-now vulnerability**: uncertain
findings are capped at "watch", even when the underlying CVE is critical and
known-exploited. Only confident detections (or explicit validation) reach "fix
now".

### 2. A home dashboard centered on outcomes

`GET /dashboard/summary` aggregates what a non-specialist needs on login: what
needs attention (counts by priority plus the top items), what changed recently,
which systems were not assessed recently, whether Vulna itself is healthy, and a
single **next recommended action**. The highest-priority unresolved issue and its
suggested action are both discoverable from this one view.

### 3. A consistent finding layout with confidence and evidence

Every finding is presented in the same seven sections — what Vulna observed, why
it matters, how confident Vulna is, the affected system/service, practical
remediation, how to verify the fix, and references plus raw evidence — with a
plain-language summary and an expandable technical view. Detection confidence and
the evidence source are always shown, so a user never has to inspect raw output to
gauge trust. Evidence is **sanitized** for display (`app/services/evidence.py`:
control/escape characters stripped, size bounded) on top of the frontend's HTML
escaping.

### 4. One-click workflows with guardrails

**Mark fixed & verify** sets the finding to *ready for verification* and triggers
a rescan; it does **not** close the finding until the configured verification
succeeds (Phase 10). **False positive** and **Assign** are one click. Risk
acceptance continues to require an owner, reason, and expiration through the
existing guardrailed flow.

### 5. Bulk actions enforce per-object authorization and audit

`POST /findings/bulk` applies one action (assign, false-positive, start
remediation, triage) to many findings. Each finding is checked individually for
org ownership — anything outside the caller's organization is **skipped, never
touched** — and every change emits its own audit event.

### 6. Global search, scoped to the organization

`GET /search` returns matches across assets, findings, sites, scans, and reports,
always filtered to the caller's organization.

### 7. Accessible, responsive markup

The new views use semantic landmarks (`section`/`article` with `aria-label`),
real headings, labeled controls (including a visually-hidden label on the search
box), native `<button>`/`<details>` elements for keyboard operability, and
responsive grids. A documented keyboard-only review of the core flows is tracked
in `docs/accessibility.md`.

## Security constraints (how they are met)

- **No overstated matches** — uncertain findings are capped at "watch"; the label
  reflects confidence (§1).
- **Sanitized evidence** — scanner evidence is stripped of control/escape
  characters and size-bounded before display (§3).
- **Authorized, audited bulk actions** — per-object org checks and per-finding
  audit events (§5).

## Consequences

- A non-specialist can open the home page, see the single most important thing to
  do, and act on it.
- Findings read as advice, not scanner dumps, while the technical detail and
  stable exports remain available.
- The priority label is trustworthy because it is deliberately conservative about
  uncertain detections.

## Rollback / migration

Additive and read-mostly: the priority/confidence/evidence fields are computed at
serialization time (no schema change); the dashboard, search, and bulk endpoints
are new. Existing finding data and exports are unchanged.

## Alternatives considered

- **Deriving priority purely from CVSS/severity.** Rejected: it would label
  uncertain matches as fix-now, exactly the overstatement the security constraint
  forbids. Confidence is a first-class input.
- **Storing a priority column.** Deferred: computing it at read time keeps it in
  sync with evolving KEV/EPSS/validation without a migration or a recompute job.
