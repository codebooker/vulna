# ADR 0036: MFA, WebAuthn, and recent step-up

## Status

Accepted — Phase 36.

## Context

Revocable sessions stop stolen refresh credentials, but password-only sessions do
not provide phishing-resistant authentication or a reliable recent-authentication
signal for destructive operations. Factor data must remain organization-scoped,
backup-safe, and absent from portability exports.

## Decision

- Encrypt TOTP seeds with Fernet under an HKDF-derived, purpose-specific context.
  Store each recovery code as its own Argon2 hash and show plaintext only once.
- Use the maintained `webauthn` server library and browser WebAuthn APIs. Require
  exact challenge, RP ID, origin, signature, and user verification. Challenges are
  random, five-minute, session/user/organization-bound, locked on consumption, and
  single-use.
- Treat TOTP and WebAuthn as strong factors. Recovery codes recover one sign-in but
  do not count as an enrolled strong factor. Record methods and MFA timestamps on
  server sessions.
- Keep the default policy optional. Required users without factors receive a
  configurable grace period and, after expiry, can access only factor enrollment.
- Apply one recent-step-up dependency to existing high-risk mutations. The
  organization session policy owns the window.
- Persist login/MFA throttling by hashed account and IP identifiers with bounded
  exponential backoff and generic errors.

## Consequences

WebAuthn deployments need a stable HTTPS origin and relying-party ID. Factor
changes revoke other sessions. The Phase 36 downgrade is schema-safe but lossy:
it cannot reconstruct the cleared legacy recovery-code JSON array or retain new
factor state, so operators must verify a backup before downgrading.
