# Data map

What Vulna stores, where, how sensitive it is, and whether it can leave the
deployment. The machine-readable version is
[`shared/schemas/data-map.json`](../shared/schemas/data-map.json).

## What can leave (and what never does)

| Data flow | Destination | Contains org data? | Control |
|---|---|---|---|
| Intelligence feeds (NVD/KEV/EPSS) | fixed feed hosts | no (download only) | `intelligence_feeds_enabled` |
| SMTP / webhooks | operator-configured | selected notification fields only | per channel |
| Telemetry | operator-configured (none by default) | aggregate counts only | `telemetry_enabled` (off) |
| Update checks | none | — | the app never contacts a release server |
| OIDC / SAML sign-in | operator-configured identity provider | identity protocol messages only | per provider; off by default |

Telemetry, when enabled, **never** contains IP addresses, hostnames, usernames,
findings, CVEs tied to assets, evidence, credentials, report contents, or a stable
cross-installation identifier.

## What is stored locally

| Category | Store | Sensitivity | In export? |
|---|---|---|---|
| Organization / sites / scopes | database | low | yes |
| Scouts | database | low | metadata only |
| Assets / services | database | medium | yes |
| Structured asset context, normalized tags/groups, membership explanations, and ownership history | database | medium | yes |
| Findings | database | medium | yes |
| Raw scanner output | database | medium | no |
| Evidence | reports volume | high | no |
| Reports (files) | reports volume | medium | metadata only |
| Audit log | database | medium | no |
| User lifecycle / site access metadata | database | high | yes, metadata only |
| Password, invitation, reset, recovery material | database (hashed) | critical | no |
| Session device/IP metadata | database | high | no |
| Refresh-token hashes | database (hashed) | critical | no |
| TOTP seeds | database (purpose-bound encrypted) | critical | no |
| Recovery codes | database (one Argon2 hash per code) | critical | no |
| WebAuthn credentials/challenges | database (public keys and short-lived challenge state) | high | no |
| Authentication throttle state | database (hashed account/IP keys) | high | no |
| Identity-provider configuration and external subject links | database | high | no |
| OIDC client secrets, SAML certificates, and SP private keys | database (purpose-bound encrypted) | critical | no |
| OIDC/SAML state, nonce, request, and replay records | database (hashed/encrypted where secret) | high | no |
| SCIM user/group/mapping metadata and sanitized history | database | high | yes, metadata only |
| SCIM bearer tokens and request counters | database (hashed token) | critical | no |
| Roles, permission mappings, scoped grants, and service-account metadata | database | high | yes, metadata only |
| Personal/service API-token values and hashes | value shown once / hash in database | critical | no |
| API-token lifecycle metadata (expiry, revocation, restrictions, last use) | database | high | yes, metadata only |
| Background task payloads, leases, results, errors, and worker heartbeats | database | medium | no |
| Internal CA + signing keys | keys volume | critical | no |
| Notification / SMTP secrets | database (encrypted) | high | no |

The [export](portability.md) contains only the non-secret categories marked "yes"
or "metadata only". User lifecycle events are backup-only; exported user records
contain status/source/role/site access metadata but never authentication or
session material.
Secrets, keys, evidence, and raw output never appear in an export.
