# ADR 0041: Safe asset context, grouping, and ownership resolution

## Status

Accepted for Phase 40.

## Context

Inventory had an unstructured legacy tag array and no common ownership resolver.
Reporting, SCIM planning, and later risk/SLA phases need consistent asset context,
but accepting executable group expressions or ambiguous owner rules would create a
security and operational boundary that is difficult to audit.

## Decision

Store typed neutral context fields on assets and normalize tags into organization-
owned definitions plus assignments. Retain `tags_json` as a derived compatibility
projection. Represent dynamic group rules as bounded JSON ASTs over code-defined
fields and operators. Materialize memberships and their explanations after relevant
inventory changes; never execute user-provided code, SQL, regular expressions, or
templates.

Resolve ownership using one shared service in this order: finding, asset, highest-
priority matching enabled group, site, department, unassigned. Reject potentially
overlapping equal-priority ownership groups at configuration time and fail closed if
a tie is nevertheless present. Append effective-owner snapshots when inputs change.

Keep context independent from authorization. The Phase 39 permission catalogue and
site-scoped query predicates remain the only access decision. Include non-secret
context and history in portability exports while full database backup preserves all
rows.

## Consequences

- Group evaluation is predictable, explainable, and portable across databases.
- Materialization makes inventory/report filtering stable and avoids executing rules
  during every list request.
- Context or ownership changes may update memberships/history during ingestion, so
  those operations remain transactional.
- Conservative tie rejection can require administrators to choose distinct
  priorities even when two rules do not currently overlap.
- Downgrade retains the legacy tag projection but cannot represent structured
  context, groups, or ownership history; a verified pre-upgrade backup is required.
