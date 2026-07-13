# Migration notes

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

- **SCIM 2.0 provisioning (Phase 38).** The additive upgrade creates hashed,
  expiring bearer-token records, provisioned groups and memberships, role/site
  mappings, sanitized request logs, and database-backed rate-limit windows. Existing
  users remain local/JIT and are never claimed by SCIM; their effective access does
  not change. New SCIM users default to Viewer with no assigned sites until an
  administrator previews and applies group mappings. The portability bundle moves
  to schema v2 and includes non-secret SCIM users/groups/mappings/history while
  validation continues to accept v1. Downgrade removes provisioning configuration
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
