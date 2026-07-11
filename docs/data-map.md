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

Telemetry, when enabled, **never** contains IP addresses, hostnames, usernames,
findings, CVEs tied to assets, evidence, credentials, report contents, or a stable
cross-installation identifier.

## What is stored locally

| Category | Store | Sensitivity | In export? |
|---|---|---|---|
| Organization / sites / scopes | database | low | yes |
| Scouts | database | low | metadata only |
| Assets / services | database | medium | yes |
| Findings | database | medium | yes |
| Raw scanner output | database | medium | no |
| Evidence | reports volume | high | no |
| Reports (files) | reports volume | medium | metadata only |
| Audit log | database | medium | no |
| Users / credentials | database | high | no |
| Internal CA + signing keys | keys volume | critical | no |
| Notification / SMTP secrets | database (encrypted) | high | no |

The [export](portability.md) contains only the non-secret categories marked "yes"
or "metadata only". Secrets, keys, evidence, and raw output never appear in an
export.
