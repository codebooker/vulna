# ADR 0034: History-preserving user lifecycle and site assignments

- **Status:** Accepted
- **Date:** 2026-07-13
- **Phase:** 34

## Context

Permanent passwords selected by administrators create a secret-delivery problem,
hard deletion breaks historical attribution, and an organization-only role does
not constrain users to the sites they operate. Phase 34 must improve these areas
without breaking the Phase 0–33 API or pre-empting Phase 39 granular RBAC.

## Decision

Store authoritative account status and authentication source alongside the
derived compatibility `is_active` and existing primary `role`. Create separate
invitation and password-reset records whose random tokens are shown once, hashed
with HMAC keys derived from distinct HKDF contexts, expire, and are consumed or
revoked once. Users choose their own passwords.

Never hard-delete users. Status, role, password, and site-access changes increment
an authentication version and revoke currently available credential material.
Keep append-only lifecycle events and the existing audit log. Refuse unsafe
self-management and loss of the last active administrator.

Represent Phase 34 access as `all` or explicit organization-owned site
assignments. Apply one shared site-scope predicate to server queries and detail
lookups; cross-organization and out-of-scope records return 404. Administrators
remain organization-wide. Phase 39 will translate assignments to grants.

## Consequences

- Invitation/reset plaintext is unrecoverable after the creation response.
- Deactivation preserves attribution and immediately denies authenticated calls.
- Existing users keep all-site access after the safe backfill.
- Portability exports only non-secret user/assignment metadata; encrypted backups
  preserve the complete database state.

## Rollback

Downgrade removes Phase 34 lifecycle tables and derived fields only when every user
still has a password hash. It refuses to downgrade while a passwordless invited
account exists because the previous schema cannot represent it safely.
