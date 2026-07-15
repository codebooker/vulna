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
| Ticket synchronization | operator-configured ticket provider | selected finding fields only; never evidence/raw output | per connector; tested and off by default |
| Passive inventory collection | operator-configured inventory source | read-only bounded asset observations | per connector; tested and off by default |

Telemetry, when enabled, **never** contains IP addresses, hostnames, usernames,
findings, CVEs tied to assets, evidence, credentials, report contents, or a stable
cross-installation identifier.

## What is stored locally

| Category | Store | Sensitivity | In export? |
|---|---|---|---|
| Organization / sites / scopes | database | low | yes |
| Scouts | database | low | metadata only |
| Relays, tunnel addresses, scope, status, and certificate fingerprints | database | high | no |
| Assets / services | database | medium | yes |
| Structured asset context, normalized tags/groups, membership explanations, and ownership history | database | medium | yes |
| Findings | database | medium | yes |
| Risk profiles, immutable score inputs/contributions, remediation units/suggestions, and bounded finding decisions | database | medium | yes |
| SLA policies, immutable deadline calculations, exceptions, history, and structured guidance | database | medium | yes |
| Raw scanner output | database | medium | no |
| Scan progress, ETA, and sanitized structured failure diagnostics | database | high | no |
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
| Credential vault metadata, assignments, sanitized tests, and usage | database | high | metadata only |
| Credential secret versions | database (purpose-bound encrypted) | critical | no |
| Scout credential-encryption private key | Scout state (`0600`) | critical | no |
| Software inventory, history, and EOL overrides | database | medium | yes |
| Signed Scout credential envelopes | database (Scout-bound ciphertext) | critical | no |
| Ticket connector metadata and synchronization history | database | high | metadata only |
| Ticket connector secrets | database (purpose-bound encrypted) | critical | no |
| Passive connector metadata, observations, source links, lifecycle, reconciliation snapshots, and aggregate history | database | high | yes or metadata only |
| Passive inventory connector secrets | database (purpose-bound encrypted) | critical | no |
| CSV inventory source uploads | database (purpose-bound encrypted) | high | metadata only; never source bytes or ciphertext |
| Report templates, schedules, and comparison history | database | medium | yes |
| Report export passwords | database (purpose-bound encrypted) | critical | no |
| Scope-specific analytics cache | database | medium | no |
| Internal CA + signing keys | keys volume | critical | no |
| Central Relay WireGuard private key and peer configuration | relay configuration volume | critical | no |
| Relay mTLS identity and WireGuard private key | remote Relay state (`0700`) | critical | no |
| Notification / SMTP secrets | database (encrypted) | high | no |

The [export](portability.md) contains only the non-secret categories marked "yes"
or "metadata only". User lifecycle events are backup-only; exported user records
contain status/source/role/site access metadata but never authentication or
session material.
Secrets, keys, evidence, raw scanner output, and CSV source contents never appear
in an export.

Passive inventory preserves every bounded source observation before applying an
identity decision. Exact identifier weights make unique conflict-free scores of 95
or above auto-merge; 70–94 requires review, and each merge is reversible. Scoped
analytics and report templates reuse the same permission predicates. See
[Inventory intelligence](passive-inventory.md) and
[ADR 0045](adr/0045-passive-inventory-reconciliation.md).
