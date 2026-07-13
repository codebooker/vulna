# Export and moving to a new host

You own your data and can take it with you. This page covers exporting your data
and moving Vulna to another machine.

## Export

`GET /api/v1/portability/export` (administrator) produces a **versioned,
checksummed** JSON bundle of your organization's non-secret data: organization,
sites, network scopes, Scouts (metadata only), users (non-secret lifecycle and
access metadata), user-site assignments, assets, services, findings, report
metadata, and remediation history. It contains **no** password hashes, invitation
or reset hashes, recovery codes, keys, tokens, certificates, lifecycle event
details, or report file bytes.
Session records, device/IP history, and refresh-token hashes are also excluded.
They are authentication state, not portable organization content.
TOTP seeds, recovery-code hashes, WebAuthn credentials/challenges, MFA policy,
authentication-strength timestamps, and throttle records are likewise excluded;
they remain only in encrypted full-database backups.
Identity-provider configuration, encrypted OIDC/SAML material, external subject
links, group mappings, SSO policy/test history, break-glass flags, protocol state,
and replay records are also excluded. Moving federation configuration requires an
encrypted backup/restore so provider trust and anti-replay history cannot be
separated from the credentials and MFA factors that make enforcement safe.
Export schema v2 includes SCIM-owned user external ids, provisioned groups,
membership, role/site mapping metadata, and sanitized provisioning history. It
excludes bearer-token hashes, token identifiers, source IPs, rate-limit windows,
and reserved Phase 40 asset-group targets. Schema-v1 bundles remain valid input to
the validation endpoint; full connector continuity still requires encrypted
backup/restore.

The bundle can be validated **independently**:

- It conforms to the published schema
  [`shared/schemas/export-bundle.schema.json`](../shared/schemas/export-bundle.schema.json).
- Its `checksum` is the SHA-256 of the canonical JSON of every field except
  `checksum` itself.

`POST /api/v1/portability/validate` validates a bundle without applying it: it
checks the schema version and checksum, confirms internal ownership consistency,
and reports conflicts. A bundle belonging to a **different organization is
refused** — portability never becomes a cross-organization authorization bypass.

## Move Vulna to another host

Moving hosts is a backup/restore, which preserves the internal CA and Scout
identity so enrolled Scouts keep their mutual-TLS trust. `GET
/api/v1/portability/migration-plan` returns the checklist:

1. **Back up** — `vulna backup create --encrypt` (includes the CA and Scout state).
2. **Verify** — `vulna backup verify <bundle>` before moving.
3. **Restore** — `vulna backup restore <bundle>` on the new host. The CA and Scout
   identity are restored, so Scouts reconnect with their existing trust.
4. **Update the URL / certificate** — point the new host's public URL and TLS
   certificate; see [networking](networking.md).
5. **Check Scouts** — run `vulna doctor` and `vulnascout doctor`; re-enroll any
   Scout that cannot reconnect.

See [backups](backups.md) for the backup/restore details.
