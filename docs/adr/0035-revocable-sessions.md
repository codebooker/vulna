# ADR 0035: Revocable server sessions and rotating refresh families

- **Status:** Accepted
- **Date:** 2026-07-13
- **Phase:** 35

## Context

Phase 34 JWTs remain valid until their expiry unless the user's authentication
version changes. That cannot support per-device revocation, idle or absolute
limits, concurrent-session policy, or refresh-token theft detection. Persisting a
long-lived bearer token in browser storage also increases exposure to script access.

## Decision

Issue 15-minute session-bound access tokens and hold them in browser memory. Keep a
random refresh token in an HttpOnly, SameSite=Lax cookie that is Secure outside
localhost development. Store only a hash derived with the dedicated
`SESSION_REFRESH` HKDF purpose.

Represent each sign-in as a database session with user/organization ownership,
authentication version, device and source metadata, last activity, idle expiry,
absolute expiry, trust duration, and explicit revocation. Rotate the refresh token
under a row lock on every refresh. Link each used token to its replacement; reuse
revokes the entire session and records an audit event.

Enforce session validity on every session-bound access token. Status, password,
role, site access, and later MFA/organization-access changes revoke all sessions.
Retain derived Phase 34 API fields and reject runtime stateless tokens after the
migration increments all user authentication versions.

## Consequences

- Every upgrade user signs in once; captured legacy tokens cannot survive.
- Revocation is immediate without maintaining an access-token denylist.
- Refresh secrets never appear in API responses after creation and are excluded
  from portability exports.
- Encrypted database backups preserve session state and therefore require the same
  critical handling as other authentication data.

## Rollback

Downgrade drops session and refresh tables. It intentionally does not decrement
user authentication versions, because rollback must not make pre-upgrade bearer
tokens valid again. Users sign in again on the downgraded version.
