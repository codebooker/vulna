# ADR 0011: Remediation and Verification

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 10 (Remediation and verification)

## Context

Finding a vulnerability is only half the job; an assessment platform has to carry
each finding through ownership, remediation, and confirmation that the fix
actually worked — and let teams accept a risk deliberately and temporarily when
they cannot fix it now (build plan Section 9.15, 9.19). Phase 10 adds that
workflow on top of the findings database from Phase 6.

## Decisions

### 1. Verification resolves by scanner-scoped absence, reopen reuses recurrence

A targeted rescan creates an ordinary scan job for the finding's asset, tagged
with the finding IDs it verifies (`verifies_finding_ids_json`). When a scanner's
results are ingested, the verification step resolves each verified finding **that
same scanner** no longer observes — a finding is never resolved by the absence of
a scanner that could not have seen it (e.g. an Nmap scan does not resolve a Nuclei
finding). Reintroduction needs no new logic: the Phase 6 ingest already reopens a
resolved finding that recurs, so a fix that regresses reopens automatically on the
next scan. This keeps "fixed" and "came back" symmetric and driven by real
observations.

### 2. The assigned owner can act on their own finding

Finding updates are authorized for operators/administrators *or* the finding's
assigned owner. This lets a remediation owner move their finding to
`ready_for_verification` (the verification queue is simply findings in that
status) without granting them operator rights over every finding. Read access to
findings and notes stays broad; only mutation is gated.

### 3. Risk acceptances are bounded and expire by default

A `RiskAcceptance` always carries a required `expires_at`. Requesting one is an
operator action; activating it is an approver/administrator action (mirroring the
active-web-scan approval split from Phase 9). An expiry sweep flips lapsed active
acceptances to `expired`, clears the finding's pointer, reopens the finding, and
raises a `risk_acceptance_expired` change event — the "expiration triggers alert"
requirement is satisfied by reusing the Phase 5 change-event stream rather than a
separate alerting system. The sweep is an idempotent endpoint a scheduler can call
on a cadence.

### 4. A soft pointer avoids a circular foreign key

`risk_acceptances.finding_id` is the owning foreign key. The convenience
`findings.risk_acceptance_id` (the currently-active acceptance) is a plain UUID
column, not a formal FK, so the two tables do not form a foreign-key cycle that
would complicate migration ordering on SQLite and PostgreSQL. The application
maintains the pointer.

### 5. Notes are append-only

`FindingNote`s are never edited or deleted, preserving an auditable remediation
history alongside the audit log. Anyone in the organization can add one, since
remediation is collaborative across roles.

## Consequences

- Findings move through a real lifecycle (assigned → in progress → ready for
  verification → resolved / reopened / risk-accepted) with owners and due dates.
- Verification and reopen are automatic and observation-driven, so status
  reflects reality rather than manual bookkeeping.
- Risk acceptances cannot silently become permanent; they lapse and re-surface
  the finding.

## Alternatives considered

- **Resolving a finding whenever any later scan omits it:** rejected; without
  scoping to the observing scanner (and to explicit verification jobs) this would
  wrongly resolve findings a given scan never covered.
- **A dedicated notification/alerting subsystem for expiries:** deferred; emitting
  a change event reuses existing delta infrastructure and the digest/notification
  layer can consume it later.
- **A formal finding↔risk-acceptance foreign key both ways:** rejected for the
  circular-FK migration cost; the owning FK plus a soft pointer is sufficient.
