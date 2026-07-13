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

Encrypted database backups retain connector ciphertext, report passwords, task
history, observations, and reconciliation snapshots. Portability schema v8 exports
non-secret connector metadata, observations, source links, lifecycle/history,
aggregate history, reconciliation explanations, and report template/run metadata.
It excludes connector ciphertext, export passwords, analytics cache entries, task
payloads, and leases. Restoring usable secrets requires a verified encrypted
backup. Downgrade removes Phase 44 history and cannot reconstruct source links, so
verify a backup first.
