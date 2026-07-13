# External Security Review Checklist

A structured checklist for an independent review of Vulna before a public
release. Each item points at where the control lives so a reviewer can verify it
directly. See also [`threat-model.md`](threat-model.md) and
[`../SECURITY.md`](../SECURITY.md).

## Authentication & authorization
- [ ] Passwords hashed with Argon2; no plaintext or reversible storage (`app/auth`).
- [ ] Invitation and reset tokens are random, single-use, expiring, stored only as
  HMAC hashes, and separated with distinct HKDF purposes (`app/services/account_tokens.py`).
- [ ] JWTs signed (HS256) with a required secret; no default secret ships.
- [ ] RBAC enforced on every mutating endpoint; role checks are explicit and tested (`app/auth/dependencies.py`, `tests/test_rbac.py`).
- [ ] Organization scoping on every resource read/write (cross-org access returns 404).
- [ ] Account status and authentication version are checked on every authenticated
  request; status/password/role/site changes immediately invalidate Phase 34 access.
- [ ] Access tokens are 15-minute, session-bound, and held in browser memory;
  refresh tokens are purpose-bound hashes in rotating families and an observed
  reuse revokes the whole session (`app/services/sessions.py`, `tests/test_sessions.py`).
- [ ] Refresh cookies are HttpOnly and SameSite=Lax, Secure in production, and
  session idle/absolute expiry plus administrator revocation are server-enforced.
- [ ] TOTP seeds use purpose-bound encryption; recovery codes are independent
  Argon2 hashes shown once; API/export/notifications never return stored secrets
  (`app/services/secret_crypto.py`, `tests/test_mfa.py`).
- [ ] WebAuthn verifies challenge, RP ID, origin, user verification, signature, and
  sign count through the maintained server library; challenges are owned,
  five-minute, and single-use. Chromium virtual-authenticator coverage exercises
  the browser ceremony (`dash/frontend/e2e/webauthn.spec.ts`).
- [ ] MFA-required sessions cannot access ordinary APIs before completing a factor;
  recovery codes are one-time, TOTP timecodes reject replay, and factor changes
  revoke other sessions.
- [ ] Authentication failures use generic errors and database-backed, hashed
  account/IP exponential backoff. High-risk scope, pentest, retention, evidence,
  repair, key/certificate, and restore-adjacent operations require recent step-up.
- [ ] Assigned-site query filters and detail checks cover every site-bound API;
  frontend visibility is not treated as authorization (`app/auth/site_scope.py`).
- [ ] Self-deactivation/self-demotion and loss of the last active administrator are
  refused; deactivation preserves historical attribution.
- [ ] OIDC uses code + PKCE S256 with durable single-use state/nonce; discovery,
  token, and JWKS URLs are HTTPS-validated and IP-pinned, and signed ID tokens verify
  exact issuer/audience/nonce/expiry/authorized-party/access-token binding
  (`app/services/sso.py`, `tests/test_sso.py`).
- [ ] SAML strict mode requires signed assertions, checks InResponseTo, rejects
  replayed response/assertion IDs, rejects DTD/entities, supports optional encrypted
  assertions and signing-certificate rollover, and uses xmlsec in the API container.
- [ ] SSO enforcement requires a validated, same-administrator-tested, enabled
  provider and at least one active local administrator with strong MFA. Local, role,
  status, invitation, and factor-removal paths cannot strand enforcement; break-glass
  use is audited and generates a critical security notification.
- [ ] SCIM tokens are high-entropy, shown once, hashed at rest, expiring, rotatable,
  immediately revocable, organization-bound, and database-rate-limited
  (`app/services/scim.py`, `tests/test_scim.py`).
- [ ] `/scim/v2` exposes only SCIM-owned users for the token organization; local/JIT
  and cross-organization users are hidden. PATCH paths and filters are parsed from a
  bounded grammar, deprovisioning preserves history, and every access change revokes
  affected sessions.
- [ ] Group mappings are previewed and explicitly confirmed, validate every site's
  organization, derive least-privilege Viewer/no-site fallback, and cannot demote or
  deactivate the final active administrator.
- [ ] Permission keys are code-defined; database roles cannot introduce unknown
  strings. Every role, principal, and scope id is rechecked against the caller's
  organization (`app/auth/permission_catalog.py`, `app/services/authorization.py`).
- [ ] Site-bound queries correlate the requested permission and scope to the same
  grant; permissions from two different site grants cannot combine
  (`app/auth/site_scope.py`, `tests/test_authorization.py`).
- [ ] Role/grant/status changes revoke user sessions or invalidate service tokens,
  and the final active administrator grant cannot be removed.
- [ ] Personal/service API tokens are random, shown once, hashed, expiring,
  optionally IP-bound, rotatable, immediately revocable, and rejected for step-up.
  Service accounts have no password, session, SSO, or SCIM login path.
- [ ] SLA policy priority is unique and first-match evaluation is deterministic;
  calculated deadlines, exceptions, pause/resume, breach, and completion events are
  append-only. Direct edits cannot overwrite calculated `due_at`, and accepted risk
  pauses only when the matched policy explicitly opts in (`app/services/sla.py`,
  `tests/test_sla_ticketing.py`).

## Probe trust boundary (mTLS)
- [ ] Caddy terminates mTLS with `client_auth mode require_and_verify` and a trust pool of the internal CA; `mode request` is not used (`deploy/Caddyfile`, ADR 0003 live validation).
- [ ] The client-cert fingerprint header is injected by the proxy with a lone `header_up` set (delete+set drops it); the API trusts it only from the proxy and never exposes the API port publicly.
- [ ] The fingerprint format matches what the API stores (validated live: lowercase-hex SHA-256 of the cert DER).

## Signed jobs, policy, and scope
- [ ] Job envelopes and local policies are Ed25519-signed; probes reject unsigned/altered/expired (`scout/internal/policy`, cross-language vectors).
- [ ] Each probe independently enforces its signed scope (approved CIDRs) and refuses out-of-scope targets/redirects — defense in depth beyond the server check.

## Scanner safety
- [ ] No free-form command strings; every adapter uses allowlisted, typed arguments (`scout/internal/scanners/*`).
- [ ] Targets are validated as IP/CIDR (argument-injection defense) before any scanner runs.
- [ ] Nuclei uses the safe template policy (no dos/intrusive/fuzzing/brute-force); ZAP passive has no active scan, limited-active uses a rule allowlist; ZAP scope is bound to in-scope hosts so redirects cannot leave scope.
- [ ] SSH/WinRM inventory accepts exactly one in-scope asset IP, uses fixed read-only
  commands, bounded time/output, pinned SSH host keys or verified WinRM HTTPS, and
  rejects job-supplied command material (`tests/test_authenticated_inventory.py`,
  `scout/internal/scanners/*_inventory`).

## Controlled pentest
- [ ] Module policy is allowlist-only; DoS and exploit categories are categorically blocked; the default pack is auxiliary/validation only, with no exploit lists in the repo (`app/services/pentest_policy.py`, `scout/internal/pentest`).
- [ ] Every session is approval-gated and time-bounded; the allowlist is enforced on both server and probe; cleanup is recorded.

## Secrets & data handling
- [ ] No secrets in the repository or git history; keys live in the data dir, never in packages (grep for tokens/keys).
- [ ] OIDC secrets, OIDC flow material, SAML IdP/SP certificates, and SAML SP keys
  use distinct HKDF contexts; APIs and portability exports expose no reusable
  provider material.
- [ ] SCIM bearer values and hashes never appear in API reads, logs, audit metadata,
  notifications, or portability exports; token values exist only in one creation or
  rotation response.
- [ ] Personal/service API-token values and hashes never appear in API reads, logs,
  audit metadata, notifications, or portability exports; only a one-time creation or
  rotation response contains the value.
- [ ] Background task types are allowlisted in code; payloads contain no secrets or
  executable expressions, leases expire/renew, attempts are bounded, and dead
  letters/cancellation/retry require `tasks.*` permissions and audit events.
- [ ] Vault APIs are one-way; SSH and WinRM use distinct HKDF purposes. Resolution
  precedence is deterministic and same-level conflicts block. A signed credential
  envelope is X25519/HKDF/ChaCha20-Poly1305 bound to one job/Scout/expiry and is
  decrypted only after Scout signature/policy/scope/opt-in checks. Plaintext never
  enters Scout state, argv, environment, output, evidence, logs, or portability.
- [ ] Ticket secrets use a distinct HKDF purpose and are exposed only as
  `has_secret`; connector configuration requires step-up and a successful test
  before enablement. Worker payloads contain selected finding fields but no evidence
  or raw output, remote failures cannot roll back findings, sync is idempotent, and
  closure requires verification or an explicit audited reason
  (`app/services/ticketing.py`, `tests/test_sla_ticketing.py`).
- [ ] Passive inventory adapters expose no source mutation method; public config
  rejects secret fields, connector secrets use a distinct HKDF purpose, task
  payloads contain only run IDs, observations reject secret-shaped attributes, and
  reconciliation auto-merges only unique conflict-free scores at or above 95.
  Every merge has a reversible snapshot and split audit (`tests/test_passive_inventory.py`).
- [ ] CSV inventory source bytes use their own HKDF purpose and are decrypted only
  for test/worker collection. APIs and portability expose metadata only; upload
  changes invalidate qualification, clear retains observations, and parser limits
  prevent unbounded rows, columns, cells, and files (`tests/test_inventory_csv.py`).
- [ ] Kea DHCP uses only the fixed read-only `lease4-get-page` command, bounds and
  advances cursors, pins the validated HTTPS destination, requires explicit
  private/unauthenticated exceptions, and never retains its Basic authentication
  header or provider body (`tests/test_inventory_dhcp.py`).
- [ ] Authoritative DNS exposes AXFR over fixed TCP port 53 only for explicit
  non-root zones, pins one SSRF-validated destination, requires strong TSIG by
  default, bounds zone/time/record work while receiving, and stores only A, AAAA,
  PTR, and CNAME observations. Unsigned and private access are separate explicit
  exceptions; the TSIG value never enters results, cursors, exports, or errors
  (`tests/test_inventory_dns.py`).
- [ ] Active Directory uses verified LDAPS on pinned fixed port 636, system or
  supplied public-CA trust, hostname/SNI verification, disabled referrals, a
  read-only connection, a fixed computer filter/attribute allowlist, and bounded
  internal paging. Bind passwords and paging cookies never enter reads, results,
  task state, portability, observations, audit metadata, or errors
  (`tests/test_inventory_active_directory.py`).
- [ ] Microsoft Entra accepts only UUID tenant/app IDs and four code-defined cloud
  endpoints, uses client credentials with fixed Graph `/.default` scope, requests
  only `GET /v1.0/devices` with `Device.Read.All` and a fixed field/query allowlist,
  validates every internal next link, pins DNS, refuses private destinations and
  redirects, and never retains the client secret, bearer token, or pagination token
  (`tests/test_inventory_entra.py`).
- [ ] UniFi Network accepts only exact local or Site Manager Integration API roots
  and one site UUID; issues fixed `GET` requests for adopted devices and connected
  clients; validates bounded offset paging and record fields; pins DNS; requires
  private-network opt-in; and never retains its `X-API-Key` value in results,
  cursors, observations, tasks, logs, or exports (`tests/test_inventory_unifi.py`).
- [ ] VMware vCenter accepts only an HTTPS port-443 origin, verifies system or
  supplied public-CA trust, pins DNS, requires explicit private-network access,
  creates one ephemeral session, reads only the fixed host/VM list resources, and
  invalidates the session after success or failure. Passwords, Basic headers, and
  session IDs never enter results, observations, cursors, tasks, logs, errors, or
  exports (`tests/test_inventory_vcenter.py`).
- [ ] Report export passwords use a separate HKDF purpose, appear only as
  `has_export_password`, never enter task payloads/portability/audit metadata, and
  AES-256 protection is applied only in renderer memory (`tests/test_passive_inventory.py`).
- [ ] Scheduler replicas use PostgreSQL advisory-lock leader election and unique
  idempotency keys; queue backpressure is configured before connector workloads.
- [ ] Untrusted scanner output parsed defensively (defusedxml for XML; malformed lines skipped).
- [ ] `/metrics` exposes aggregate-only data — no finding titles, evidence, IPs, or CVE ids in labels (`tests/test_metrics.py`).

## Supply chain & release
- [ ] `pip-audit`, `npm audit --audit-level=high`, and `govulncheck` are clean (the `security` CI job).
- [ ] `deploy/security/check_go_openpgp.py` rejects the GO-2026-5932-affected
  `golang.org/x/crypto/openpgp` package and subpackages from every CLI and Scout
  build graph for supported operating systems.
- [ ] SBOMs generated for backend, frontend, and probe (`deploy/sbom/generate-sbom.sh`).
- [ ] Release artifacts are checksummed and Ed25519-signed; `verify.sh` rejects tampered artifacts and wrong-key signatures.
- [ ] Backup/restore round-trips identity/policy and refuses a tampered archive (`deploy/backup/smoke_test.sh`).

## Appliance & operations
- [ ] The probe runs unprivileged under a hardened systemd unit (`deploy/probe/vulnascout.service`).
- [ ] Upgrades preserve identity/policy (separate data dir) and rollback restores the prior release (`deploy/probe/smoke_test.sh`).
- [ ] Monitoring is opt-in and internal-only; Grafana ships with a changeable admin password.
