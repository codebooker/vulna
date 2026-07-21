# Migration notes

## PostgreSQL row-level tenant isolation

- The application now enters a restricted `vulna_runtime` role for every ORM
  transaction and binds protected data access to one organization after user,
  token, SCIM, or Scout authentication.
- High-value tenant tables use PostgreSQL RLS. Missing tenant context fails
  closed; cross-tenant writes are rejected by the database.
- The migration creates two `NOLOGIN` roles and therefore requires `CREATEROLE`
  or equivalent managed-database administration. The supported Compose database
  owner already has this capability. See [tenant isolation](tenant-isolation.md).

## Audit integrity and complete Rules-of-Engagement grants

- New audit events are HMAC-authenticated and linked in a serialized,
  organization-local hash chain. PostgreSQL rejects audit updates/deletes.
- Configure `VULNA_AUDIT_INTEGRITY_KEY` if a dedicated audit key is preferred;
  otherwise `VULNA_MASTER_KEY` is used. Preserve rotated keys in
  `VULNA_AUDIT_INTEGRITY_PREVIOUS_KEYS` while historical events are retained.
- Existing audit rows are linked and labeled `legacy-sha256-v1`; their original
  contents cannot be retroactively authenticated.
- Existing Rules-of-Engagement rows are migrated as expired legacy grants and
  cannot authorize new sessions. Create a replacement grant containing the
  authorization owner/source/reference, authorization document SHA-256, exact
  CIDRs or assets, exact modules, and effective dates.
- Every controlled-pentest request now requires an active complete RoE. The
  session snapshots its policy digest, exact target/module, selected network and
  Scout, resulting job, and current fenced job attempt.

User-visible behavior and configuration changes, per release. Vulna is in
pre-release active development; until the first tagged release, this page tracks
changes on `main`. Full detail is in the [CHANGELOG](../CHANGELOG.md).

## How to read this

Each release that changes user-visible behavior or configuration lists:

- **What changed** for an operator.
- **Action required**, if any (a new setting, a migration to run, a command that
  moved).

Database migrations run automatically on start (`alembic upgrade head`); no manual
step is needed for schema changes unless noted.

## Unreleased (on `main`)

- **Faster, versioned scan execution and fenced delivery.** Scan presets now
  control the signed workflow and rate limits, the Standard profile includes
  automatic passive ZAP, and discovery avoids restarting downstream scanners for
  every subnet. New immutable job-attempt leases fence stale Scouts and bind all
  result uploads to an authorized stage and versioned content envelope. Current
  Scout and backend images must be upgraded together; interrupted pre-upgrade
  scans should be restarted. Existing queued jobs are re-signed into the v1 wire
  contract when first offered, and recurring schedules are pinned to an explicit
  preset version.

- **Relay enrollment and certificate lifecycle.** Relay enrollment commands now
  expire using the configured token TTL, enrolled Relays persist certificate
  metadata and renew automatically before expiry, and a bounded prior-certificate
  window permits lost-response recovery. Approved Relay ranges are checked
  globally because the current WireGuard route table is shared across
  organizations. No operator action is required, but overlapping routes in a
  multi-organization appliance must be made globally unique before changing
  Relay scope.

- **Route-level frontend loading.** Operator pages are loaded on demand rather
  than shipping one monolithic JavaScript bundle. No operator action is required.

- **Scan progress and failure diagnostics.** The additive upgrade adds bounded
  stage progress, an estimated-completion timestamp, and sanitized structured
  failures to scan jobs. Existing completed scans backfill to 100%; every other
  historical scan stays at zero because no trustworthy checkpoint exists. No
  operator action is required and a Scout that has not upgraded continues using
  the compatible status payload without progress. Downgrade preserves the scan job
  and summary error but permanently removes detailed progress and diagnostic
  history; export anything needed for an incident and verify an encrypted backup
  first.

- **Remaining Phase 44 passive inventory providers.** No schema migration is
  required for Proxmox VE, XCP-ng/Xen Orchestra, AWS, Microsoft Azure, or Google
  Cloud. Public origins/scopes/bounds use the existing connector configuration and
  every provider credential uses the existing purpose-encrypted one-way secret.
  Existing sources are unchanged and none is enabled automatically. Portability
  excludes token secrets, cloud access keys, client secrets, service-account JSON,
  private keys, signatures, and ephemeral access tokens, so full credential
  continuity requires a verified encrypted backup.

- **VMware vCenter passive inventory importer (Phase 44).** No schema migration is
  required. The public HTTPS origin, username, resource selectors, limits, public
  CA trust, and private-network opt-in use existing connector configuration; the
  password uses the existing purpose-encrypted one-way secret. Existing sources
  are unchanged and none is enabled automatically. Portability excludes the
  password and ephemeral session, so full continuity requires an encrypted backup.

- **UniFi Network passive inventory importer (Phase 44).** No schema migration is
  required. The public Integration API root, site UUID, resource selectors, and
  safety limits use existing connector configuration; the API key uses the existing
  purpose-encrypted one-way secret. Existing sources are unchanged and none is
  enabled automatically. Portability omits the API key, and full continuity
  requires an encrypted backup.

- **GO-2026-5932 dependency hardening.** No schema or operator action is required.
  Vulna does not use the affected OpenPGP package; CI now fails if it enters a
  supported Go build graph. Scout HKDF moved to the compatible standard-library
  implementation, and the indirect `x/net` module was upgraded to v0.55.0.

- **Microsoft Entra passive inventory importer (Phase 44).** No schema migration
  is required. Tenant/app UUIDs, the code-defined cloud selector, and bounded read
  limits use existing public connector configuration; the app client secret uses
  the existing purpose-encrypted one-way secret. Existing sources are unchanged,
  and none is enabled automatically. Portability excludes the secret and temporary
  Graph tokens; full connector continuity requires an encrypted backup.

- **Active Directory passive inventory importer (Phase 44).** No schema migration
  is required. Controller, bind identity, base DN, public CA trust, and bounded
  paging settings use existing public connector configuration; the bind password
  uses the existing purpose-encrypted one-way secret. Existing sources are
  unchanged and none is enabled automatically. Portability omits the password and
  full continuity requires an encrypted backup.

- **Authoritative DNS passive inventory importer (Phase 44).** No schema migration
  is required. DNS server, explicit zone names, safety limits, and public TSIG
  metadata use the existing connector configuration; TSIG key material uses the
  existing purpose-encrypted one-way secret. Existing sources are unchanged and no
  connector is enabled automatically. Portability contains only public
  configuration and `has_secret`; full continuity requires an encrypted backup.

- **CSV passive inventory importer (Phase 44).** The additive upgrade stores CSV
  upload ciphertext and non-secret filename/hash/size/upload metadata on inventory
  connectors. Existing connectors receive null source fields and remain disabled
  unless already qualified for another adapter. CSV source bytes use a distinct
  encryption purpose, stay out of portability, and are included in encrypted
  database backups. Downgrade preserves connectors and collected observations but
  permanently removes uploaded CSV source data and its metadata; verify a backup
  first.

- **Passive inventory and report builder (Phase 44 core).** The additive upgrade
  creates connector/run/observation/source-link records, reconciliation candidates
  and reversible snapshots, inventory lifecycle projections/events, daily
  aggregates and scoped cache entries, plus report templates/schedules/runs.
  Existing assets receive a neutral `assessed` or `discovered` state based only on
  their existing assessment timestamp; no connector, expected policy, schedule, or
  outbound delivery is enabled automatically. Portability moves to schema v8 and
  accepts v1–v7 while excluding connector ciphertext, export passwords, cache rows,
  and task payloads. Downgrade drops Phase 44 provenance and cannot reconstruct
  source links or split history; take and verify an encrypted backup first.

- **Remediation SLAs and ticket synchronization (Phase 43 core).** The additive
  upgrade creates ordered SLA policies, immutable finding calculations, exception
  and event history, structured guidance, purpose-encrypted connector
  configuration, and synchronization history. Existing findings are backfilled
  from their current `due_at`; findings without one receive the documented severity
  fallback anchored to `first_seen_at` (or creation time). No ticket connector is
  enabled automatically, and a connector must pass an administrator test first.
  Portability moves to schema v7 and continues accepting v1–v6, but exports only
  sanitized connector metadata—never ciphertext. Downgrade preserves the latest
  compatibility `due_at` but removes SLA history, guidance, connector configuration,
  and sync history; take and verify an encrypted backup first.
- **Authenticated scanning and software inventory (Phase 42).** The additive
  upgrade adds an opt-out-by-default Scout flag/public X25519 key, nullable asset
  and credential-protocol job projections, purpose-encrypted credential versions,
  deterministic assignments, tests/usage, normalized software inventory/history,
  EOL intelligence, and expiring overrides. Existing Scouts stay opted out and
  have no encryption key; re-enroll each Scout before enabling credential delivery.
  Existing jobs receive neutral null/empty values. Portability moves to schema v6
  and still validates v1–v5, but never exports vault ciphertext or encrypted job
  envelopes. Downgrade removes credential/software history and cannot reproduce a
  Scout key or vault version; take and verify an encrypted backup first.
- **Explainable risk and remediation units (Phase 41).** The additive upgrade creates
  one default versioned risk profile per organization and backfills every finding
  with an immutable score snapshot. Inputs are normalized to `[-1,1]`; each source,
  weight, contribution, profile version, and input hash is retained. Existing
  severity/status fields and friendly priority labels remain compatible projections.
  Exact CVE/package/product/remediation keys may group automatically; fuzzy proposals
  remain pending until reviewed. New false-positive, duplicate, and suppression
  decisions require evidence and a future expiry. Existing legacy exception statuses
  become auditable migration decisions with a 90-day review window and a migration
  evidence reference; operators should attach current evidence before renewing them.
  Portability moves to schema v5 and
  continues accepting v1–v4. Downgrade removes score/remediation/decision history
  because Phase 40 cannot represent it; take and verify an encrypted backup first.
- **Asset context, groups, and ownership (Phase 40).** The additive upgrade adds
  neutral structured context to assets, normalized tags/assignments, static and
  dynamic groups with materialized membership, site/department/asset ownership,
  and append-only effective-owner history. Existing `tags_json` values backfill
  losslessly and remain as a compatibility projection; existing assets receive no
  inferred classification or owner. Portability moves to schema v4 while validation
  continues to accept v1–v3. Dynamic rules are validated JSON, never executable
  expressions. Downgrade recreates the legacy tag projection before removing Phase
  40 tables, but cannot represent structured context, groups, or ownership history;
  take and verify an encrypted pre-upgrade backup first.
- **Dedicated scheduler and worker (post-Phase-39 gate).** The additive upgrade
  creates durable task and worker-heartbeat tables. Single-host Compose installs now
  start `scheduler` and `worker` services automatically; the API no longer runs its
  legacy in-process loop. Existing synchronous feed/report endpoints remain valid.
  Queue state is included in encrypted database backups but excluded from portability
  exports. Downgrade deletes task history and requires the API's legacy scheduler loop,
  which this release no longer contains, so restore the prior application image and a
  verified pre-upgrade backup together.
- **Granular RBAC and service accounts (Phase 39).** The additive upgrade creates
  built-in/custom roles, role permissions, scoped grants, service principals, and
  hashed API-token records. Each existing user receives organization or site grants
  derived from the current role and Phase 34 assignments; `role`, `is_active`, and
  site-access fields remain compatible projections. No existing capability is
  disabled. Authorization changes now revoke user sessions and invalidate issued
  tokens. The portability bundle moves to schema v3 and validation still accepts v1
  and v2. Downgrade preserves derived legacy role/site fields but deletes custom
  roles, service accounts, and API tokens because the prior schema cannot represent
  them; revoke automation credentials and take a verified encrypted backup first.
- **SCIM 2.0 provisioning (Phase 38).** The additive upgrade creates hashed,
  expiring bearer-token records, provisioned groups and memberships, role/site
  mappings, sanitized request logs, and database-backed rate-limit windows. Existing
  users remain local/JIT and are never claimed by SCIM; their effective access does
  not change. New SCIM users default to Viewer with no assigned sites until an
  administrator previews and applies group mappings. The portability bundle moves
  to schema v2 and includes non-secret SCIM users/groups/mappings/history while
  validation continues to accept v1. Phase 39 supersedes this with schema v3 while
  retaining v1/v2 validation. Downgrade removes provisioning configuration
  and external ids but preserves user and lifecycle rows; SCIM-created passwordless
  users still require SSO after downgrade, so take and verify an encrypted backup.
- **OIDC and SAML SSO (Phase 37).** The additive upgrade creates organization
  provider, policy, external-link, group-mapping, test-history, short-lived state,
  and SAML replay tables plus a disabled-by-default break-glass flag. Every existing
  organization receives an SSO policy in `disabled` mode, so local sign-in behavior
  does not change. Set `VULNA_SSO_PUBLIC_BASE_URL` to the public HTTPS origin before
  configuring callbacks. Enforcement remains unavailable until an administrator
  validates and tests a provider, enables it, and protects a local strong-MFA
  administrator. Downgrade deletes federation configuration and links but preserves
  local users/history; take and verify an encrypted backup first because encrypted
  provider material cannot fit the Phase 36 schema.
- **MFA and WebAuthn (Phase 36).** The upgrade adds encrypted TOTP factors,
  independently hashed recovery codes, WebAuthn public credentials and five-minute
  challenges, organization MFA policy, session authentication strength, and durable
  hashed account/IP throttling. Existing onboarding recovery-code hashes migrate
  into per-code records without plaintext exposure and the legacy JSON array is
  cleared. MFA defaults to optional. When an administrator requires it, unenrolled
  users receive a seven-day grace period by default. Configure
  `VULNA_WEBAUTHN_ORIGIN` and `VULNA_WEBAUTHN_RP_ID` when the public origin cannot
  be inferred. Downgrade removes Phase 36 factor state and cannot recreate the
  cleared legacy recovery-code array; take and verify an encrypted backup first.
- **Revocable sessions (Phase 35).** The upgrade creates server-side session and
  hashed refresh-token tables and increments every existing user's authentication
  version. All pre-upgrade stateless access tokens are intentionally rejected, so
  every user signs in once after upgrade. New access tokens last 15 minutes and
  stay in browser memory; the HttpOnly refresh cookie restores the session.
  Downgrade removes the new tables but does not decrement authentication versions,
  because doing so could resurrect a captured legacy token. Take and verify an
  encrypted backup before downgrade.
- **User lifecycle (Phase 34).** Existing users are backfilled to active/local
  with all-site access, so upgrades preserve their effective access. Administrators
  now invite users instead of choosing passwords; existing password hashes remain
  valid. The migration adds lifecycle, invitation/reset, and site-assignment
  tables. Downgrade is supported only when no passwordless invited account exists,
  because the prior schema requires every user to have a password hash. Existing
  access tokens remain valid unless the affected account's role, status, password,
  or site access changes. No operator action is required.
- **Experience profiles (Phase 33).** Existing organizations are backfilled to
  `small_business`. This changes navigation organization only; routes, policies,
  permissions, schedules, security controls, and stored configuration continue
  unchanged. Installer answer schema v1 remains readable; new answer files use v2.
  Backup/restore includes the two new organization fields. Downgrading discards
  only the presentation preference.
- **Notifications (Phase 29).** New email/webhook notification channels. No action
  required; opt in by creating a channel under Notifications. Credentials are
  stored encrypted and never returned.
- **Maintenance center (Phase 28).** New maintenance overview, storage budgets,
  and a fail-closed retention cleanup. Retention cleanup is opt-in and
  administrator-only; no data is removed unless you run it.
- **Low-resource / offline (Phase 27).** New Lite/Standard/Full operating
  profiles derived from Scout resources, plus a durable result queue. No action
  required; new `result_queue_max_bytes` Scout setting defaults sensibly.
- **Diagnostics & maintenance (Phase 26–28).** New System Health and Maintenance
  pages. Read-only; no action required.

New configuration keys are additive and default to safe values; existing
deployments continue to work without changes. See the per-phase entries in the
[CHANGELOG](../CHANGELOG.md) for specifics.
