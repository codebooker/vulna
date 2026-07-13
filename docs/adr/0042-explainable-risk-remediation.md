# ADR 0042: Immutable explainable risk and review-gated grouping

- Status: accepted
- Date: 2026-07-13

## Context

The earlier four-bucket classifier was readable but could not preserve which inputs
or policy version produced a priority. Broad remediation similarity can also group
unrelated work, while unbounded false-positive/suppression flags lose review context.

## Decision

Risk profiles are immutable versions over a code-defined factor catalogue. Every
calculation appends the normalized inputs, weighted contributions, profile version,
positive maximum, and canonical input hash. A cached pointer/score on the finding is
only an efficient projection of the latest snapshot.

Automatic remediation grouping accepts exact CVE, package, product, and normalized
remediation keys only. Fuzzy similarity creates a separate pending suggestion that
requires explicit step-up-protected review. Finding decisions are append-only,
evidence-backed, expiring records that retain and restore the previous workflow
status.

## Consequences

Operators can reproduce and explain every score, compare policy versions, reverse a
reviewed grouping, and audit every exception. Storage grows with recalculations and
decision history; retention/export/backup paths therefore treat these records as
first-class organization data. A downgrade cannot represent them and requires a
verified pre-upgrade backup.
