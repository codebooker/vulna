# Roles, scoped grants, service accounts, and API tokens

Vulna uses a code-defined permission catalogue and database-backed roles.
Authorization is always enforced by the API; navigation visibility uses the same
permission keys only as a convenience.

## Permission catalogue and roles

`GET /api/v1/permissions` returns stable permission keys, their supported scopes,
and whether an operation is high risk. A database role selects keys from this
catalogue. It cannot create arbitrary permission strings.

The six pre-Phase-39 roles remain as immutable built-in roles. Existing `role` and
`site_access_mode` response fields are derived compatibility projections, so old
`/api/v1` clients continue to work. Custom roles do not replace the stored history
or delete the compatibility fields.

## Scoped grants

A grant binds one role to one user or service account at either:

- organization scope, covering every site in that organization; or
- site scope, covering exactly one site owned by that organization.

The permission and scope must come from the same grant. For example, `sites.read`
at Site A cannot combine with `assets.read` at Site B to expose either permission at
the other site. List, detail, report, and evidence queries use the same correlated
grant filters. Cross-organization principal, role, and scope ids are rejected.

Grant and role changes increment the principal's authorization version. User
sessions are revoked immediately; previously issued API tokens become stale. Vulna
refuses removal of the last active administrator's administrator grant.

## Service accounts

Service accounts are non-interactive principals for automation. They have no email,
password, MFA factor, browser session, or SSO/SCIM identity. Create the account,
grant only the permissions and sites it needs, then issue an expiring API token.
Suspending a service account revokes every active token immediately.

Service-account activity is recorded as `service_account` in the audit log. Legacy
database attribution columns that reference users remain null; the audit event
retains the service principal id.

## API tokens

Personal and service tokens:

- start with `vapi_`, use high-entropy random values, and are displayed once;
- are stored only as SHA-256 hashes with a non-secret display prefix;
- require an expiry of 1–365 days;
- may restrict source addresses with IPv4 or IPv6 CIDRs;
- support rotation and immediate revocation; and
- inherit the current grants of exactly one principal and organization.

APIs return `has_secret` and lifecycle metadata after creation, never a reusable
value or token hash. API tokens cannot satisfy interactive step-up authentication,
so they cannot perform operations that require a recent password, MFA, or WebAuthn
assertion.

Use the **Authorization** page for roles, grants, service accounts, and tokens. The
page is an Advanced route in the Small Business experience; hiding it never changes
authorization or background behavior.

## Backup and portability

Encrypted backups preserve roles, grants, service principals, token hashes,
revocation, IP restrictions, and authorization versions. Authorization metadata was
introduced in portability schema v3 and remains present in the current schema v4,
but token hashes and values are never exported. Restoring automation credentials
requires a verified encrypted backup, not a portability import.
