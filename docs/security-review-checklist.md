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

## Controlled pentest
- [ ] Module policy is allowlist-only; DoS and exploit categories are categorically blocked; the default pack is auxiliary/validation only, with no exploit lists in the repo (`app/services/pentest_policy.py`, `scout/internal/pentest`).
- [ ] Every session is approval-gated and time-bounded; the allowlist is enforced on both server and probe; cleanup is recorded.

## Secrets & data handling
- [ ] No secrets in the repository or git history; keys live in the data dir, never in packages (grep for tokens/keys).
- [ ] OIDC secrets, OIDC flow material, SAML IdP/SP certificates, and SAML SP keys
  use distinct HKDF contexts; APIs and portability exports expose no reusable
  provider material.
- [ ] Untrusted scanner output parsed defensively (defusedxml for XML; malformed lines skipped).
- [ ] `/metrics` exposes aggregate-only data — no finding titles, evidence, IPs, or CVE ids in labels (`tests/test_metrics.py`).

## Supply chain & release
- [ ] `pip-audit`, `npm audit --audit-level=high`, and `govulncheck` are clean (the `security` CI job).
- [ ] SBOMs generated for backend, frontend, and probe (`deploy/sbom/generate-sbom.sh`).
- [ ] Release artifacts are checksummed and Ed25519-signed; `verify.sh` rejects tampered artifacts and wrong-key signatures.
- [ ] Backup/restore round-trips identity/policy and refuses a tampered archive (`deploy/backup/smoke_test.sh`).

## Appliance & operations
- [ ] The probe runs unprivileged under a hardened systemd unit (`deploy/probe/vulnascout.service`).
- [ ] Upgrades preserve identity/policy (separate data dir) and rollback restores the prior release (`deploy/probe/smoke_test.sh`).
- [ ] Monitoring is opt-in and internal-only; Grafana ships with a changeable admin password.
