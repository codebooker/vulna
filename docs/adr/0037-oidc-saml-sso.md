# ADR 0037: Organization-scoped OIDC and SAML SSO

**Status:** Accepted — Phase 37.

## Context

Enterprise operators need standards-based federation without weakening the Phase
34–36 account, session, MFA, organization-isolation, and recovery controls. The
danger is larger than a failed integration: an administrator can accidentally
lock out every local operator, a callback can become an account-linking or
cross-organization bypass, and remote metadata/token endpoints introduce SSRF and
replay surfaces.

## Decision

- Store OIDC/SAML providers, stable external-subject links, exact group mappings,
  immutable test records, policy, browser-flow state, and SAML replay identifiers
  in organization-scoped tables.
- Encrypt OIDC client secrets/flow values and SAML certificate/key material using
  distinct HKDF purposes. Return only presence metadata.
- Use Authlib for OIDC Authorization Code + PKCE and OneLogin `python3-saml` with
  xmlsec for SAML. Keep durable state in the database instead of client sessions.
- Validate and IP-pin server-side OIDC destinations. Private IdPs are explicit;
  loopback, link-local, reserved, and metadata targets are never allowed.
- Require exact issuer/audience/nonce validation and signed OIDC ID tokens. Require
  signed SAML assertions, strict response/request binding, and replay records;
  assertion encryption is configurable.
- Treat discovery/metadata validation, a same-administrator browser test, provider
  enablement, and strong-MFA break-glass readiness as separate gates. Enforcement
  is impossible until every gate passes.
- Let profiles affect only whether Identity & SSO appears in ordinary navigation.
  Server authorization and direct authorized access are unchanged.

## Consequences

The design is additive under `/api/v1`. Existing installations receive a disabled
policy and no break-glass flags, so upgrade behavior is unchanged. Full federation
state is backup-only and intentionally excluded from portable exports. JIT users
remain compatible with the current single role/site fields; Phase 39 migrates those
assignments into scoped grants. Phase 38 adds provisioning/deprovisioning ownership.

An external IdP remains an optional availability dependency. Local strong-MFA
break-glass is deliberately preserved and highly visible in audit/notifications;
there is no hidden vendor bypass.
