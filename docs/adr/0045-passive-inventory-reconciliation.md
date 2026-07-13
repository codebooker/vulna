# ADR 0045: Preserve observations and make reconciliation reversible

## Status

Accepted for Phase 44.

## Context

Directory, network, virtualization, and cloud systems frequently disagree about
the identity and freshness of an asset. Treating a connector response as a direct
asset update would lose provenance and could silently collapse two systems.

## Decision

- Connector adapters expose read-only test and collect methods.
- Every collected source record is stored as an append-only observation.
- Exact identifiers use code-defined weights. Auto-merge requires a unique score
  of at least 95 and no immutable-identifier conflict; scores 70–94 require review.
- Current source-to-asset links are materialized separately from observations.
- Every merge retains a pre-merge snapshot and supports an audited split.
- Lifecycle state changes are events with a materialized current projection.
- Dashboard aggregation, history, and report generation are server-side and always
  apply the caller's grant scope.
- Reusable connector and export secrets use separate purpose-bound encryption
  contexts and are never placed in task payloads or portability exports.

## Consequences

The database retains more history, but identity decisions are explainable and
reversible. Provider adapters can ship independently without changing the trust,
authorization, or reconciliation boundary.
