# Passive inventory, reconciliation, analytics, and report builder

Vulna provides a read-only connector boundary around external inventory sources.
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

### Proxmox VE importer

The Proxmox source accepts only an exact HTTPS origin on the native `8006` port
or a hardened port-443 reverse proxy. Configure a separated API token as
`USER@REALM!TOKENID`, store its token UUID as the one-way secret, and grant only
the documented `PVEAuditor` permissions. The adapter performs fixed `GET` reads of
the Proxmox [cluster resource index](https://pve.proxmox.com/pve-docs/api-viewer/index.html#/cluster/resources)
for nodes and guests; templates are excluded unless an administrator explicitly
includes them. It exposes no configurable action, filter, provider path, or
mutation. Proxmox documents token separation and a limited monitoring-token
example in its [API token guidance](https://pve.proxmox.com/pve-docs/pve-admin-guide.html#pveum_tokens).

System trust is used by default, with one optional public issuing CA for an
internal PKI. DNS is pinned, redirects are disabled, private management networks
require explicit opt-in, every response is capped at 1 MiB, and combined records
are bounded. Token IDs are public connector metadata; token secrets and complete
Authorization headers never enter results, observations, cursors, tasks, logs,
errors, audits, or portability exports.

### XCP-ng / Xen Orchestra importer

The XCP-ng source uses the current Xen Orchestra
[REST API](https://docs.xen-orchestra.com/restapi/) at an exact HTTPS port-443
origin. Store an existing XO authentication token as the one-way secret and grant
the account only `host:read` and `vm:read` (or the equivalent read-only ACL). Vulna
sends the token only in XO's documented authentication cookie and performs fixed
`GET` reads of bounded host and VM field projections. It never creates, refreshes,
or deletes tokens and exposes no arbitrary fields, filters, actions, paths, or
provider URLs. See Xen Orchestra's [ACL v2 guidance](https://docs.xen-orchestra.com/xo6/acl-v2)
for the least-privilege permission model.

System or operator-supplied public-CA trust always verifies TLS. DNS pinning,
redirect denial, explicit private-network opt-in, a 1 MiB response cap, sentinel
record limits, and strict UUID/identifier validation apply before observations are
accepted. Authentication tokens and cookie headers remain absent from all durable
and portable state.

### Amazon Web Services importer

One AWS source represents one explicit account/partition and a bounded list of
regions. The one-way secret is a strict access-key credential envelope; temporary
credentials with a session token are supported and preferred. Vulna never uses
ambient environment, shared-file, container, or instance-metadata credentials.
The adapter signs requests with maintained AWS Signature Version 4 primitives but
retains Vulna's own endpoint allowlist, DNS pinning, redirect denial, timeouts, and
1 MiB response bounds. It calls only fixed regional
[`GetCallerIdentity`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
and [`DescribeInstances`](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html)
actions; no endpoint, service, action, filter, or region discovery is configurable.

The caller identity and every reservation owner must match the expected account
when configured. Pagination is repeat-checked and kept only in worker memory;
partial, malformed, duplicate, cross-account, or over-limit results fail the run.
Recently terminated instances are excluded by default. AWS recommends temporary
credentials and least privilege in its
[IAM security guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html);
the connector role needs only `ec2:DescribeInstances` for its configured regions.
Access keys, secret keys, session tokens, signatures, and principal ARNs never
enter results, errors, observations, tasks, logs, audits, or exports.

### Microsoft Azure importer

The Azure source uses an explicit cloud, tenant, application client, and one or
more subscription UUIDs. The client secret is stored only in the encrypted
one-way connector field. Vulna exchanges it at the code-defined Microsoft identity
endpoint and performs a fixed, projected Azure Resource Graph query through the
documented [`resources` API](https://learn.microsoft.com/en-us/rest/api/azureresourcegraph/resourcegraph/resources/resources?view=rest-azureresourcegraph-resourcegraph-2024-04-01).
Queries run per subscription so an inaccessible subscription cannot be silently
omitted, and the projection intentionally excludes arbitrary resource properties,
custom data, secret URLs, and tags.

Global, US Government, and China clouds use code-defined authority/resource hosts;
custom endpoints and queries are unavailable. Pagination tokens, bearer tokens,
and projected records are bounded and validated, while truncation, duplicates,
partial authorization, or malformed identity fails closed. Grant Resource Graph
read access plus read access to only the configured VM resources. Client secrets,
OAuth tokens, and raw provider responses never enter persistent or portable state.

### Google Cloud importer

The Google Cloud source reads the fixed Compute Engine
[`aggregatedList`](https://cloud.google.com/compute/docs/reference/rest/v1/instances/aggregatedList)
resource for explicit projects. Upload a service-account JSON file as the one-way
secret; Vulna strictly validates its Google token endpoint, service-account
identity, key metadata, and RSA private key before signing a short-lived JWT for
the `compute.readonly` scope. The credential JSON, private key, JWT assertion, and
access token remain only in the encrypted secret or worker memory. Ambient
Application Default Credentials and attacker-controlled token URLs are never used.

The request uses a code-defined field projection that excludes instance metadata,
user data, disks and encryption keys, service accounts, labels, and arbitrary
provider properties. Page tokens are bounded/repeat-checked and URLs are rebuilt
locally. Any unreachable zone, partial result, duplicate, malformed record, or
limit breach fails the run. Prefer a custom role containing only
`compute.instances.list` where policy permits; Google documents broader built-in
roles in its [Compute IAM guidance](https://cloud.google.com/compute/docs/access/iam)
and recommends short-lived credentials in its
[service-account guidance](https://cloud.google.com/iam/docs/best-practices-service-accounts).

### VMware vCenter importer

The vCenter source uses Broadcom's current
[vSphere Automation API](https://developer.broadcom.com/xapis/vsphere-automation-api/latest/).
Configure an exact HTTPS origin on port 443, a dedicated read-only account, and its
password as the connector's one-way secret. Private management addresses require
`allow_private=true`. System trust is used by default; `trust_pem` may contain one
public issuing CA certificate for an internal PKI. Disabling certificate or
hostname verification is not available.

Authentication is limited to the documented
[`POST /api/session`](https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/session/post/)
exchange. The resulting token exists only in worker memory and is sent as
`vmware-api-session-id` to the fixed
[`GET /api/vcenter/host`](https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/vcenter/host/get/)
and [`GET /api/vcenter/vm`](https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/vcenter/vm/get/)
resources. A fixed `DELETE /api/session` invalidates the token after success and is
also attempted on every provider or validation failure. Session creation/deletion
is authentication lifecycle only; the adapter exposes no inventory mutation
operation.

The current vCenter list contracts return at most 2,500 visible hosts and 4,000
visible VMs. Vulna enforces those provider ceilings, a combined 6,500-record limit,
the shared 1 MiB response limit, and a bounded timeout. The connector configuration
cannot add filters, actions, paths, ports, or query parameters. Host and VM managed
object references are namespaced to the connector as immutable provider IDs. A
valid host SMBIOS UUID receives an additional `vmware-host` identity so the same
physical hypervisor can reconcile across qualified sources; names contribute only
validated IP/FQDN/hostname/SMB identifiers.

### UniFi Network importer

The UniFi source discovers sites through Ubiquiti's official
[Site Manager API](https://developer.ui.com/site-manager/v1.0.0/gettingstarted)
and reads site inventory through the official remote Network API.
Create an API key from the
[UniFi Site Manager API-key settings](https://unifi.ui.com/settings/api-keys)
for the UI account that owns or super-administers the required hosts. Use **Load
UniFi sites** and select exactly one Network site for each connector. That site is
mapped to the Vulna site selected in the same form; create or remap one connector
per required mapping. An unscoped or legacy all-host configuration fails closed.

Vulna calls only fixed `api.ui.com` resources: `GET /v1/sites` for bounded discovery,
then the selected console's remote Network `GET /sites/{siteId}/devices` and
`GET /sites/{siteId}/clients` resources. The latter returns currently connected
physical and VPN clients. Both offset pagers cap page size at 200, each combined run
at 10,000 records and 1,000 pages per resource, and each JSON response at 1 MiB.
Console, site, device, and client IDs plus bounded identity/state fields are
validated before becoming observations. Arbitrary controller URLs, paths,
credentials in URLs, redirects, and private-network access are not configurable.

The API key is a one-way connector secret sent only in `X-API-Key`; requests are
read-only, DNS-pinned, and restricted to the fixed public API host. Provider object
IDs remain provenance only: reconciliation uses MAC, IP, and valid host names so a
UniFi record cannot fabricate another provider's immutable cloud identity. Adopted
infrastructure is classified as a network device; client type and access metadata
remain provenance while the endpoint starts as unknown until stronger evidence
classifies it.

### Microsoft Entra importer

The Microsoft Entra source reads registered device objects through Microsoft Graph
with app-only client credentials. Create a single-tenant app registration, grant it
the least-privileged `Device.Read.All` **application** permission, obtain tenant and
application client UUIDs, and store its client secret as the connector's one-way
secret. Microsoft documents that permission for
[`GET /devices`](https://learn.microsoft.com/en-us/graph/api/device-list?view=graph-rest-1.0)
and the client-credentials token exchange with a resource-specific
[`/.default` scope](https://learn.microsoft.com/en-us/graph/auth-v2-service).
Vulna cannot prove that the app registration has no additional permissions, so the
tenant administrator remains responsible for granting only `Device.Read.All`.

Configure `tenant_id`, `client_id`, and one of `global`, `us_government`,
`us_government_dod`, or `china` as `cloud`. Tenant aliases such as `common` are
rejected: both IDs must be UUIDs. Each cloud maps to code-defined authority and
Graph hosts from Microsoft's
[national cloud table](https://learn.microsoft.com/en-us/graph/deployments).
There is no base URL, authority, Graph version, operation, filter, expansion, or
field selector in connector configuration. Private destinations are never allowed,
each HTTPS destination is resolved and pinned, redirects are disabled, and the
client secret and temporary bearer token remain absent from results, cursors,
observations, task state, errors, logs, and portability exports.

The adapter selects a fixed allowlist of device identity, OS, manufacturer/model,
ownership, enrollment, management, compliance, trust, registration, and last-seen
properties. Page size defaults to 500 and is capped at 999; a run is capped at
10,000 records, 1 MiB per response, and a bounded timeout. Graph next links are
followed only inside one worker call and must retain the exact HTTPS cloud host,
`/v1.0/devices` path, selected fields, and allowed `$top`/`$skiptoken` query surface.
Pagination tokens are never persisted in a task or API.

Each observation uses the Graph object UUID as source provenance and a
tenant-qualified device UUID as an immutable cloud identifier. Valid device names
also become FQDN/hostname and SMB identifiers. Disabled device accounts are
excluded by default; `include_disabled=true` retains them with their account state.
Graph registration, sync, and approximate sign-in timestamps are context, while
the worker collection time is the freshness timestamp for a still-present device.

### Active Directory importer

The Active Directory source reads computer objects through verified LDAPS on fixed
TCP port 636. Connector configuration cannot supply an LDAP operation, filter, port,
or attribute name: the adapter uses the fixed
`(&(objectCategory=computer)(objectClass=computer))` subtree search and a code-defined
allowlist. The ldap3 connection is marked read-only and referrals are disabled, so
bind credentials are never forwarded to another directory server. ldap3 documents
both its [read-only connection option](https://ldap3.readthedocs.io/en/latest/connection.html)
and [paged search support](https://ldap3.readthedocs.io/en/latest/searches.html).

Configure `server`, `bind_user`, and `base_dn`; store the bind password as the
connector's one-way secret. The destination is resolved once through the shared
SSRF guard and the LDAPS socket connects to that pinned address. Private controllers
require `allow_private=true`. TLS always requires a trusted certificate and verifies
the configured controller name through SNI and hostname matching. System trust is
the default; `trust_pem` may contain one public issuing CA certificate for a private
domain PKI. Cleartext LDAP, StartTLS downgrade, arbitrary ports, disabled validation,
and referral credential forwarding are not available.

Searches use RFC 2696 paging internally because Active Directory limits ordinary
search responses. Pages default to 500 and are capped at 1,000; the entire collection
is capped at 10,000 entries with a bounded server and receive timeout. Paging cookies
exist only inside one worker call and never enter task state or APIs. Microsoft
documents [`objectGUID`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adls/f5f15ec2-427e-4ebe-bb64-2493cf1d032f)
as the object's stable unique identifier and
[`dNSHostName`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adls/71ffde4b-5b5b-4623-9f40-cf4c835ceaa2)
as the computer's registered DNS name.

Each observation uses `objectGUID` as stable source provenance and retains the SID,
distinguished name, account state, operating-system fields, location, manager, and
directory change time as bounded attributes. FQDN, hostname, and SMB name are the
reconciliation identifiers. Disabled computer accounts are excluded by default;
`include_disabled=true` imports them with `directory_enabled=false`. Directory
change time remains context—the collection time is the freshness timestamp so an
unchanged but still-present computer does not become stale merely because its LDAP
record was not recently edited.

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
`has_secret`, but never the TSIG value or ciphertext. Active Directory connectors
likewise export public server/base/trust configuration and `has_secret`, never the
bind password or ciphertext. UniFi connectors export only their console/site
mapping, bounds, and `has_secret`; the API key and ciphertext are excluded. It excludes
connector and source ciphertext. vCenter connectors export only their public HTTPS
origin, username, resource selectors, limits, public CA trust, private-network
opt-in, and `has_secret`; passwords, Basic credentials, API session tokens, and
ciphertext are excluded. Proxmox and XCP-ng sources export only their public origins, resource
selectors, bounds, TLS trust, private-network choice, public token ID where
applicable, and `has_secret`; token secrets and authentication headers are excluded.
AWS exports partition, explicit regions, optional expected account, bounds, and
`has_secret`, never any access-key component or signature. Azure exports cloud,
tenant/client/subscription identifiers, bounds, and `has_secret`; Google Cloud
exports project identifiers, bounds, and `has_secret`. Their client secrets,
service-account JSON, private keys, assertions, and access tokens are excluded. It
also excludes export passwords, analytics cache entries, task payloads, and leases.
Restoring a usable CSV source or secret requires a verified encrypted backup.
Downgrade can remove inventory history and cannot reconstruct source links, so verify a
backup first.
