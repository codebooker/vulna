# ADR 0038: Organization-isolated SCIM 2.0 provisioning

- Status: accepted
- Phase: 38

## Context

Enterprise directories need standards-based user and group lifecycle without
gaining a general Vulna API credential or the ability to enumerate local recovery
accounts. Phase 34 already distinguishes local, JIT, and SCIM ownership; Phase 39
will replace the single compatibility role and site assignments with scoped grants.

## Decision

Expose RFC 7643/7644 resources under `/scim/v2`, separate from versioned Vulna APIs.
Authenticate each request with a high-entropy organization token shown once and
stored only as a SHA-256 digest. Tokens expire, rotate/revoke immediately, and use
an atomic database-backed per-minute counter.

SCIM reads and mutates only SCIM-owned users in the token organization. User ids are
the existing stable UUIDs; `externalId` is an organization-unique correlation value.
Deprovisioning changes authoritative account status and revokes credentials but
never deletes attribution history.

Store provisioned groups and direct user memberships. Administrators—not directory
payloads—map groups to the existing compatibility roles and sites after a preview.
Effective access uses the highest mapped role and union of mapped sites, with a
Viewer/no-site least-privilege fallback. Changed access increments authentication
version and revokes sessions. The schema reserves opaque asset-group mapping targets
but does not expose them until Phase 40. ADR 0041 activates those targets after
organization validation without treating them as authorization grants.

Parse filters and PATCH paths with bounded, non-executable grammars. Return standard
SCIM pagination, media types, discovery resources, ETags, and error objects. Keep
sanitized provisioning and audit records without request bodies or token material.

## Consequences

- Common directory connectors can provision without provider-specific APIs.
- Local/JIT and break-glass accounts stay outside the provisioning trust boundary.
- The compatibility role remains a temporary projection until Phase 39 migrates
  mappings into additive grants.
- Full connector continuity requires encrypted backup/restore. Portability schema
  v2 exports only non-secret ownership/mapping/history metadata and still validates
  schema-v1 bundles.
- Nested groups, Bulk, password change, and sorting remain explicitly unsupported.
