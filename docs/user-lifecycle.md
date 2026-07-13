# User administration and lifecycle

Phase 34 replaces administrator-chosen passwords and hard deletion with a
history-preserving account lifecycle. The Users page is available to organization
administrators.

## Invite a user

Choose **Users → Invite user**, enter the email, role, and site access, then create
the invitation. Vulna displays the expiring link once when SMTP is not configured.
The database stores only a purpose-bound HMAC hash of the token. The recipient
uses the link once and chooses their own password; reuse and expired links fail.

Reissuing an invitation revokes older invitations and all currently available
credentials for that account. Administrators cannot assign a permanent password.
For an active local account, **Reset password** produces a separate, single-use
link with a distinct cryptographic purpose. Password changes invalidate existing
Phase 34 access tokens.

## Status and history

Accounts are `invited`, `active`, `suspended`, `locked`, or `deactivated` and are
owned by `local`, `jit`, or `scim` authentication sources. Phase 34 creates local
accounts; the other source values prepare the additive SSO/SCIM phases. Every
status, role, site, invitation, and password-reset action is audited and reflected
in lifecycle history. Deactivation preserves findings, reports, audit attribution,
and the user record.

Vulna refuses self-deactivation, self-demotion, and any transition that would
remove the last active administrator. A deactivated/suspended/locked account is
rejected at the authentication dependency immediately.

## Site access

`all` access sees every site in the organization. `assigned` access is filtered by
the shared server-side site guard; unauthorized list rows disappear and detail
requests return a non-disclosing 404. Administrators retain organization-wide
access. Frontend navigation is never the authorization boundary.

Site access applies to sites, assets, scopes, networks, Scouts, changes, findings,
reports, jobs, schedules, workflows, dashboards/search, notifications, retention,
privacy analytics, relays, and controlled pentest data. Phase 39 migrates these
assignments into generalized scoped grants and retains these fields as derived
`/api/v1` compatibility projections.

## Upgrade, export, and recovery

Existing users become active/local with all-site access. The compatibility
`is_active` and primary `role` fields remain in `/api/v1`. Non-secret user and
assignment metadata is included in portability exports; password/token hashes and
lifecycle event details are excluded. Encrypted database backups preserve the full
lifecycle state. See [migration notes](migration-notes.md),
[portability](portability.md), and [backups](backups.md).
