# ADR 0044: Immutable SLA calculations and asynchronous ticket boundary

## Status

Accepted

## Context

Remediation deadlines must remain explainable after policy changes, exceptions, and
risk acceptance. External ticket APIs are unreliable and cannot become part of the
transaction that stores a security finding. Connector credentials must remain
one-way and purpose-bound.

## Decision

- Evaluate uniquely prioritized organization policies in ascending order; first
  match wins and a fixed severity fallback covers unmatched findings.
- Store every established or changed due date as an append-only calculation linked
  to its predecessor. Keep `Finding.due_at` only as the current compatibility
  projection.
- Change a calculated deadline only through an approved exception or an explicit
  pause/resume rule. Accepted risk pauses time only when its matching policy opts in.
- Store structured, source-attributed guidance as bounded data that is never
  executable.
- Encrypt ticket secrets with a dedicated HKDF context and expose only one-way
  metadata.
- Persist findings first, then queue selected-field, idempotent connector work on the
  database-leased worker. Persist connector outcomes separately from core finding
  state.
- Require successful verification before normal ticket closure. The only alternative
  is an explicit step-up-authorized reason captured by the audit log.

## Consequences

Deadline history consumes additional rows but can be independently reconstructed and
audited. Policy edits do not silently rewrite old commitments. Ticket outages remain
visible without blocking assessment ingestion. Each provider adapter can be reviewed
and released independently behind the same contract. A portability export cannot
recreate connector secrets; encrypted backup/restore remains the operational move.
