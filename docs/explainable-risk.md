# Explainable risk and remediation grouping

Vulna uses versioned, organization-owned risk profiles and immutable score
snapshots. The formal finding
severity, CVSS, threat intelligence, validation state, workflow status, and existing
`/api/v1` shapes remain available. The friendly priority bucket is presentation,
derived from the latest `0–100` score.

## Score contract

The factor catalogue is code-defined: severity, CVSS, known exploitation, EPSS,
detection confidence, validation, internet exposure, and asset criticality. A
profile version supplies one numeric weight for every factor. Missing or unknown
factors and an all-zero profile are rejected.

Each source is normalized to `[-1,1]`; unavailable contextual values are neutral
(`0`). For each factor Vulna records the original source value, normalized value,
weight, and contribution. It then:

1. sums `normalized value × weight`;
2. divides by the profile's positive maximum (`sum(abs(weight))`);
3. multiplies by 100 and clamps the result to `0–100`; and
4. stores the canonical input SHA-256, profile id/version, numerator, denominator,
   sources, and contributions in an append-only snapshot.

Identical inputs reuse the current snapshot during ordinary ingest; an explicit
recalculation appends a new snapshot. Publishing or activating a default profile
version recalculates organization findings. The friendly labels are `fix_now`
(`75–100`), `plan` (`50–74.99`), `watch` (`25–49.99`), and `informational`
(`<25`).

## Remediation units

Automatic grouping is deliberately narrow. Vulna creates memberships only for an
exact normalized CVE, package, detected product, or remediation-text hash. A finding
may belong to multiple exact units, preserving the match basis on every membership.

Fuzzy token similarity is a suggestion mechanism, not an automatic grouping rule.
Suggestions record their score and shared tokens in `pending` state. Only an
authorized, recently authenticated reviewer can accept a suggestion and create a
membership; rejection is retained. Manual units and memberships remain available.

## Finding decisions

False-positive, duplicate, and suppression decisions require a reason, at least one
structured evidence reference, and a future expiry. Duplicate decisions also require
a different canonical finding in the same organization. Only one active decision may
project onto a finding at a time. The decision records the prior workflow status;
revocation or worker-driven expiry restores that status without deleting decision
history. Legacy status fields remain compatible, but the decision APIs are the
authoritative evidence-backed workflow.

During upgrade, an existing false-positive, duplicate, or suppressed status becomes
an active migration decision with its retained reason (when present), a migration
record reference, and a 90-day review window. Because the old schema did not retain
the preceding workflow state or duplicate target, expiry returns it to `new`; an
operator should review and replace the migration record with current evidence.

All mutation endpoints require the existing site-scoped management permission and a
recent interactive step-up. Reads use the same site-scoped permission predicates as
findings/remediation. API tokens cannot perform step-up operations. Every profile,
score, unit, suggestion review, and decision mutation is audited.

## API and operations

The additive interfaces are `/api/v1/risk-profiles`, `/finding-scores`,
`/remediation-units`, and `/findings/{id}/decisions`. The dedicated system sweep
expires decisions; expiry is idempotent and organization-scoped. Encrypted database
backups retain all records. Portability schema v5 includes non-secret profiles,
snapshots, remediation records, and decision evidence/history.
