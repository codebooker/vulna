# OIDC and SAML single sign-on

Phase 37 adds optional, organization-scoped identity federation. A fresh install
and every upgrade keep SSO **disabled**, so local authentication continues until
an administrator deliberately completes the validation, test, enablement, and
policy gates.

## Before configuring a provider

1. Give Vulna a stable public HTTPS origin:

   ```env
   VULNA_SSO_PUBLIC_BASE_URL=https://vulna.example.com
   ```

2. Sign in as a local administrator and enroll TOTP or WebAuthn.
3. In **Identity & SSO**, protect at least one active local administrator as a
   break-glass account. Prefer two independently held accounts.

The break-glass flag alone is insufficient: the account must remain active,
local, an administrator, password-backed, and enrolled in a strong factor. Vulna
will not enable enforcement—or permit a later role/status/invitation/factor change—
if that would remove the final qualifying account. A break-glass sign-in while
enforcement is active is audited and emits a critical security notification.

## OIDC

Register this callback with the provider:

```text
https://vulna.example.com/api/v1/sso/oidc/<provider-id>/callback
```

Create a provider with its exact issuer, client ID, and write-only client secret.
Generic, Microsoft Entra, Google, Okta, and Keycloak presets choose ordinary
`openid profile email` scopes; presets are convenience defaults rather than weaker
validation modes.

Vulna fetches discovery, token, and JWKS documents only from validated HTTPS
destinations. DNS is resolved once, loopback/link-local/metadata destinations are
blocked, and the connection is pinned to the validated address. Private RFC1918
IdPs require the explicit **trusted private-network IdP** option. That exception
does not permit loopback, link-local, reserved, or cloud-metadata addresses.

Authorization uses code flow with PKCE S256, random state, and nonce. State is
hashed; PKCE verifier and nonce are purpose-encrypted; each state expires after ten
minutes and is consumed before token exchange. Authlib verifies the ID-token
signature and exact issuer, audience, nonce, expiry, issued-at, authorized party,
and access-token hash where present. Unsigned tokens are always rejected.

## SAML 2.0

Create a SAML provider, then import IdP metadata. Vulna never asks the OneLogin
toolkit to fetch an arbitrary metadata URL: the administrator uploads XML, DTD and
entity declarations are rejected, and the toolkit parses the expected IdP
descriptor and signing certificate.

Download the SP metadata from:

```text
https://vulna.example.com/api/v1/sso/saml/<provider-id>/metadata
```

The ACS is:

```text
https://vulna.example.com/api/v1/sso/saml/<provider-id>/acs
```

The API image includes xmlsec. Strict mode signs AuthnRequests and SP metadata,
requires signed assertions, checks `InResponseTo`, validates audience/destination/
time conditions through the OneLogin toolkit, and records hashes of response and
assertion IDs so replays fail. Assertions may additionally be required encrypted.
The current and next IdP signing certificates can coexist during rollover; changing
metadata or rollover material disables the provider and clears its successful test.

## Test before enablement

Validation proves discovery or metadata structure. It does not prove the browser
login, claims, callback URL, group mapping, or administrator identity. Use **Test
sign-in** while the provider is disabled. The signed external identity must resolve
back to the same active Vulna administrator who started the test; another account
cannot satisfy the gate.

After a successful test, enable the provider. `optional` policy shows local and SSO
choices. `enforced` accepts only the selected SSO provider, except for qualifying
break-glass accounts. Disabling a provider used by enforcement is refused until the
policy is changed.

## Linking, JIT, and group mappings

External accounts are keyed by `(provider, subject)` and never by a mutable display
name. A first link or JIT provision requires a provider-verified email. JIT users
are passwordless, active, and owned by the external source. Exact external group
mappings can select the compatibility role and existing site assignments. If
groups map to conflicting roles, sign-in fails instead of choosing one. Phase 39
will migrate these compatibility roles/sites into scoped grants.

SCIM ownership is not implemented in Phase 37. Do not treat JIT as a substitute
for deprovisioning; disable the Vulna user or provider until Phase 38 provisioning
is configured.

## Backup, export, and offline operation

Identity-provider secrets, certificates, private keys, links, policy, test history,
and replay state are excluded from portability exports. They are included in the
database dump and therefore require an encrypted, verified backup. Restore the
entire trust state together; do not copy individual ciphertext fields between
installations.

No provider is required for self-hosted or offline operation. When an IdP is
configured, only the selected identity endpoints receive protocol traffic; Vulna
does not add telemetry or a vendor control plane.
