# Passive inventory, reconciliation, analytics, and report builder

Phase 44 adds a read-only connector boundary around external inventory sources.
The core is provider-neutral: each adapter can test a connection and collect
bounded observations, but the contract has no create, update, or delete operation
against a source system. Provider adapters are shipped as smaller stacked changes.

## Source and secret boundary

An inventory connector belongs to one organization and site. Public configuration
rejects secret-shaped fields; reusable credentials are encrypted with the dedicated
`inventory_connector_secret` HKDF context. API reads and portability exports return
only `has_secret`. New connectors are disabled, and enabling requires a successful
administrator test. Collection runs only in the dedicated worker with leases,
idempotency, retries, cancellation, and dead-letter inspection.

Every source record becomes an append-only observation. An observation contains a
bounded attribute object, normalized identifiers, source timestamp, and payload
hash. Source observations are never overwritten, so operators can explain how the
current inventory was derived.

### Authoritative DNS importer

The DNS source performs AXFR only for an explicit list of authoritative zones. It
does not expose arbitrary DNS questions, dynamic updates, or a configurable
operation. Transfers use TCP port 53 through dnspython's asynchronous
`inbound_xfr` API; the older generator API is not used. See the official
[dnspython asynchronous query documentation](https://dnspython.readthedocs.io/en/stable/async-query.html).

Configure `server` as a hostname or IP address and `zones` as 1–20 exact non-root
zone names. The destination is resolved once through the shared SSRF validator and
the transfer connects to that pinned address. Private destinations require
`allow_private=true`; loopback, link-local, multicast, unspecified, reserved, and
cloud-metadata destinations remain blocked. Port 53 is fixed so connector data
cannot create a general outbound socket surface.

TSIG is required by default. Store the base64 TSIG value as the connector's
one-way secret and set the public `tsig_name`; `tsig_algorithm` accepts only
`hmac-sha256` or `hmac-sha512`. A source without TSIG requires the separate,
visible `allow_unsigned=true` exception. TSIG authenticates and integrity-protects
the transfer but ordinary DNS over TCP is not encrypted, so operators should use a
trusted network path for sensitive zone data.

Transfers default to a ten-second message timeout, a thirty-second lifetime per
zone, and a 10,000-record total across all configured zones. The configurable
limits can only be lowered or raised within fixed ceilings. The transaction aborts
as soon as the total is exceeded, before an oversized zone is materialized. Only
A, AAAA, PTR, and CNAME data becomes an observation; SOA, NS, MX, TXT, and DNSSEC
records count toward the safety limit but are not stored as assets. Wildcard owners
also remain policy data rather than becoming synthetic assets. Zone data has no
source timestamp, so all records from one collection share the worker's
timezone-aware observation time.

### Kea DHCP importer

The DHCP source supports Kea's HTTPS REST control channel and sends only the
documented read-only `lease4-get-page` command. The command name and DHCPv4
service target are code-defined; connector configuration cannot supply a Kea
command. Newer direct-daemon endpoints are the default, while
`legacy_control_agent=true` adds the fixed `dhcp4` service route used by older
Control Agent deployments.

Configure the exact HTTPS control URL, a public `username`, and the password as
the connector's one-way secret. Basic authentication is refused without both
parts. `allow_unauthenticated=true` is an explicit API-only exception for an
already protected endpoint, and `allow_private=true` is required before the
DNS-pinned transport can contact a private address. Kea recommends protecting
remote administration with TLS and access controls; see the
[Kea security guidance](https://kea.readthedocs.io/en/latest/arm/security.html).

Pages default to 500 and are capped at 1,000 leases and a 1 MiB response. The
worker validates that each cursor advances, normalizes IPv4, MAC, and hostname
identifiers, and uses Kea's client-last-transaction time as the source timestamp.
Only active state-zero leases are collected by default; `include_inactive=true`
is an explicit API configuration option. The adapter stores bounded lease and
subnet metadata, never the provider response body or authentication header.

### CSV importer

CSV sources use `PUT /api/v1/inventory/connectors/{id}/csv` with a raw UTF-8 file.
The upload is limited to 5 MiB, 10,000 data rows, 100 unique columns, and 16 KiB
per cell. Comma, semicolon, tab, and pipe delimiters are supported. The file is
encrypted in the database with the dedicated `inventory_csv_source` HKDF context;
it is decrypted only in memory for an administrator test or worker collection.
Upload and clear operations disable the connector and invalidate its previous
test. `DELETE` on the same endpoint clears the encrypted source but retains all
append-only observations and reconciliation history.

Headers matching identifier names such as `hostname`, `fqdn`, `ip_address`,
`mac_address`, `agent_id`, or `cloud_instance_id` are mapped automatically. For
explicit mapping, connector configuration accepts `source_id_field`,
`identifier_fields` entries in `type=column` form, `attribute_fields` entries in
`target=column` form, and an optional timezone-aware `observed_at_field`. These
selectors are validated field names, reject secret-shaped columns and targets,
and are never evaluated as expressions.

API responses and portability exports expose only `has_source_data`, filename,
SHA-256, byte count, and upload time. They never expose source bytes or ciphertext.
Task payloads contain only the connector run identifier.

### Generic JSON API importer

The generic importer performs HTTPS `GET` requests only. Configuration selects a
bounded relative path, item/source/cursor fields, explicit `identifier_fields`
(`type=field`), and an attribute allowlist. Dotted field names are data selectors
with a maximum depth; they are never evaluated as code. Responses and pages are
bounded to 1 MiB and 10,000 items, redirects are disabled, DNS is pinned after SSRF
validation, and private destinations require the explicit `allow_private` option.

## Reconciliation

Reconciliation uses exact, code-defined identifier weights. Agent IDs, cloud
instance IDs, host keys, certificate fingerprints, and SNMP engine IDs score 100;
MAC addresses score 95; FQDN, SMB name, hostname, and IP matches score lower.
Immutable-identifier conflicts always block a merge.

- A unique candidate at 95 or above with no conflicts merges automatically.
- Candidates from 70 through 94 require explicit approval.
- Lower scores create a distinct discovered asset.
- Ambiguous high-confidence candidates require review instead of auto-merging.

Each merge stores the prior source link and observation mapping in a snapshot.
Splitting removes the active link and creates a separate asset from the preserved
observation. Approvals, rejections, and splits require step-up authentication and
produce audit events.

## Inventory lifecycle and analytics

Each asset has one materialized state: `expected`, `discovered`, `assessed`,
`stale`, or `missing`. The scheduled system sweep applies each asset's freshness
window and appends a lifecycle event whenever state changes. It never deletes an
asset or observation.

`GET /api/v1/analytics/dashboard` uses SQL aggregates and permission-scoped site
filters; it does not load finding rows into application memory. Results are cached
for 60 seconds in an organization-and-scope-specific database entry and responses
are private with `Vary: Authorization`. Daily aggregates and recent lifecycle events
power `/api/v1/analytics/history` and comparison reports.

## Report templates

Templates retain report types, site/tag/group filters, sections, redaction, and
branding. Supported redactions cover network identifiers, asset names, ownership,
and remediation text. An optional export password is purpose-encrypted and used to
produce AES-256 protected PDFs; it is never returned or copied into a task payload.

Scheduled generation uses the worker and the latest completed in-scope scan. A
successful scheduled run can emit a selected-field `report_ready` notification,
which links back to Vulna without attaching report contents. Comparison runs retain
two date ranges and a server-side aggregate comparison.

## Permissions

The API enforces `connectors.*`, `reconciliation.*`, `analytics.read`, and
`report_templates.*` permissions with the same organization/site grants used by
all inventory, report, and evidence paths. Frontend visibility is only a
presentation aid.

## Backup and portability

Encrypted database backups retain connector ciphertext, encrypted CSV source data,
report passwords, task history, observations, and reconciliation snapshots.
Portability schema v8 exports
non-secret connector metadata, observations, source links, lifecycle/history,
aggregate history, reconciliation explanations, and report template/run metadata.
For CSV sources this includes only presence, filename, SHA-256, size, and upload
time. DNS connectors export the server, explicit zones, public TSIG metadata, and
`has_secret`, but never the TSIG value or ciphertext. It excludes connector and
source ciphertext, export passwords, analytics
cache entries, task payloads, and leases. Restoring a usable CSV source or secret
requires a verified encrypted backup. Downgrade removes Phase 44 history and cannot
reconstruct source links, so verify a backup first.
