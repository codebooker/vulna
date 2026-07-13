# SCIM 2.0 provisioning

Vulna exposes organization-isolated SCIM 2.0 Users and Groups resources for
directory-driven account lifecycle. SCIM manages provisioning; users still sign in
through a configured OIDC or SAML provider. A SCIM password is never stored or
accepted for local login.

The implementation follows the [SCIM core schema (RFC 7643)](https://www.rfc-editor.org/rfc/rfc7643)
and [SCIM protocol (RFC 7644)](https://www.rfc-editor.org/rfc/rfc7644).

## Configure a connector

1. Sign in as an administrator with recent authentication and open
   **Administration → Provisioning**.
2. Copy the tenant URL. It ends in `/scim/v2`.
3. Create a purpose-named bearer token. Copy it immediately; Vulna stores only its
   SHA-256 hash and cannot display the value again.
4. Enter the tenant URL and token in the directory provider. Users, Groups,
   ServiceProviderConfig, ResourceTypes, and Schemas endpoints all use the same
   bearer authentication.
5. Provision a small test user and group. The user starts as Viewer with assigned-
   site mode and no sites—no group silently grants access.
6. In Vulna, preview the provisioned group's role/site mapping. Confirm it only
   after reviewing the affected-user count. A changed mapping revokes affected
   sessions immediately.

Token creation, rotation, revocation, and mapping updates require administrator
authorization; secret-affecting operations also require recent step-up. Rotation
revokes the old token before returning the replacement.

## Supported protocol surface

- `GET/POST /scim/v2/Users`, plus resource `GET`, `PUT`, `PATCH`, and `DELETE`
- `GET/POST /scim/v2/Groups`, plus resource `GET`, `PUT`, `PATCH`, and `DELETE`
- `POST /Users/.search` and `/Groups/.search`
- `GET /ServiceProviderConfig`, `/ResourceTypes`, and `/Schemas`
- one-based `startIndex`/`count` pagination, bounded pages, attribute projection,
  case-insensitive filters, value-path group-member filters, ETags, SCIM media
  types, and SCIM error objects

Bulk, password change, nested groups, and sorting are advertised as unsupported.
Filters and PATCH paths use a bounded allowlist; no directory input becomes an
executable expression.

## Ownership and deprovisioning

SCIM tokens can see and mutate only users created by SCIM for their organization.
Local and JIT users—including break-glass administrators—are not listed and return
the same not-found response as an unknown id. A conflicting username returns a
generic uniqueness error without exposing the other account.

`active: false` or `DELETE /Users/{id}` deactivates the account, clears pending
credentials, revokes sessions, and appends lifecycle/audit history. The row is not
hard-deleted, so findings, approvals, and other historical attribution remain
intact. Reactivation is explicit. The last active administrator invariant applies
to provisioning changes too.

## Group mappings

SCIM supplies group membership but does not directly choose Vulna permissions.
An administrator maps a provisioned group to an existing compatibility role and
either all sites or an explicit site set. Every site is revalidated against the
organization.

When a user belongs to multiple mapped groups, the highest existing compatibility
role wins and site ids form a union; any explicitly all-site group wins for site
scope. With no mapped group, a SCIM user falls back to Viewer with no assigned
sites. Phase 39 materializes these results as additive scoped grants. Generic
asset-group targets can now reference Phase 40 groups after organization and site
scope validation. They remain mapping metadata and never substitute for an asset
permission or grant.

## Operations and recovery

The Provisioning page shows sanitized success/failure history. It never includes
bearer values, password fields, or request bodies. Rate limits are maintained in
the database per token, so restarts do not reset an active request window.

Encrypted backup/restore preserves token hashes, revocation, mappings, membership,
ownership, and logs. The non-secret portability export includes SCIM users, groups,
mapping metadata, and sanitized history, but excludes tokens and counters. After a
restore, test both a current token and a rotated/revoked token before resuming sync.
