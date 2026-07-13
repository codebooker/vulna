# Vulna Threat Model

> **Status:** Skeleton established in Phase 0. This document is expanded in
> Phase 15 (Hardening and public release). It uses a STRIDE-oriented approach.

## Assets to protect

- Integrity and authenticity of job envelopes and local policies.
- Confidentiality of evidence, credentials, and scan results.
- The certificate authority and job-signing keys.
- Cross-tenant / cross-organization data isolation.
- The safety of assessed environments (no unauthorized or destructive actions).
- Availability and integrity of the audit trail.

## Trust boundaries

1. Browser ↔ VulnaDash (HTTPS).
2. VulnaScout ↔ VulnaDash (outbound HTTPS + mutual TLS).
3. Reverse proxy ↔ API. The proxy terminates probe mTLS and forwards the
   verified client-certificate fingerprint in `X-Vulna-Client-Cert-Fingerprint`.
   **The API must never be published directly**: it trusts that header, and the
   proxy strips any client-supplied value. Exposing the API port directly would
   permit fingerprint-header spoofing (see ADR 0003).
4. VulnaDash ↔ PostgreSQL / Redis (internal network).
5. VulnaScout ↔ scanner child processes (sandboxed, resource-limited).
6. VulnaScout ↔ assessed targets (policy-enforced scope).
7. Browser / VulnaDash ↔ operator-configured OIDC or SAML identity provider.

## Threats and controls (STRIDE summary)

| Threat | Example | Primary controls |
|---|---|---|
| **Spoofing** | Forged probe or forged server | Mutual TLS, enrollment tokens, bounded client certs, revocation checks |
| **Tampering** | Altered job envelope or result | Ed25519-signed jobs/policies, content hashes on result chunks, strict parsers |
| **Repudiation** | Denying who approved a pentest | Append-only audit log with actor, source IP, request ID |
| **Information disclosure** | Evidence or credential theft | Encryption at rest, RBAC, signed expiring download URLs, no secrets in logs/reports |
| **Denial of service** | Oversized uploads, decompression bombs | Size/rate limits, resource controls, timeouts |
| **Elevation of privilege** | Command injection via plugin config | Typed inputs, allowlisted flags, no arbitrary shell, least-privilege sandboxing |

## Specific threats to address (from build plan §29)

- Compromised orchestrator sends malicious jobs → probe local-policy enforcement
  and job signing bound the blast radius.
- Compromised probe uploads forged results → per-probe certificate, server-side
  validation, and correlation reduce trust in a single probe.
- Enrollment-token theft → short-lived (15 min), single-use, hashed tokens.
- Probe private-key theft → keys never leave the probe; revocation on heartbeat.
- Cross-tenant data leakage → organization ownership enforced in the schema and
  authorization layer; IDOR tests required.
- Malicious scanner output attacks parser → treat output as untrusted; strict,
  size-bounded parsing; sanitize before rendering.
- DNS rebinding / redirect scope escape → re-resolve DNS and re-check scope at
  execution time; restrict redirects.
- Malicious update package → signed release manifests, checksums, rollback.
- CVE feed poisoning → validate feed sources and record provenance.
- Identity-provider SSRF or DNS rebinding → HTTPS-only discovery/token/JWKS
  endpoints, address-class validation, and connection IP pinning; private IdPs
  require an explicit exception that never permits loopback/link-local/metadata.
- OIDC callback forgery or token substitution → random hashed state, encrypted
  nonce/PKCE verifier, single-use expiry, signed ID-token verification, and exact
  issuer/audience/nonce/request binding.
- SAML wrapping/replay or unsolicited assertion → OneLogin+xmlsec strict mode,
  signed assertions, `InResponseTo`, audience/destination/time validation, safe XML
  metadata parsing, and durable hashed message/assertion replay records.
- SSO lockout → enforcement requires a validated, same-administrator-tested,
  enabled provider and preserves an active local strong-MFA break-glass
  administrator; every break-glass use is audited and alerted.

## Required controls (baseline)

mTLS · signed jobs · signed local policy · signed plugin releases · checksums ·
strict parsers · content sanitization · least privilege · encrypted evidence ·
RBAC · append-only audit trail · SBOMs · dependency scanning · reproducible
releases where feasible.

## Privacy and data ownership (Phase 31)

Vulna is self-hosted and does not require an account, license server, hosted
control plane, or telemetry endpoint, and the running application never contacts a
release server. The only outbound traffic is intelligence-feed downloads and the
SMTP/webhook notifications an operator configures; every destination is listed on
the privacy page. Telemetry is off by default, opt-in only, and strictly
anonymous (aggregate counts, no PII or cross-installation identifier). Data
portability is bounded by these controls:

- **Export excludes secrets** — the data export carries only non-secret categories
  (see the [data map](data-map.md)); keys, credentials, evidence, and raw output
  never appear.
- **Untrusted import** — a bundle is validated (schema, checksum, ownership) and
  never applied automatically; a bundle from another organization is refused, so
  portability cannot become a cross-organization authorization bypass. Trust roots,
  privileged users, and signing keys are never overwritten by an import; a host
  move is a backup/restore that deliberately preserves CA and Scout identity.

## Out of scope (current)

- Vulnerabilities in third-party scanner tools themselves.
- Physical attacks on the orchestrator host beyond disk-encryption guidance.
- Nation-state supply-chain compromise of the base OS/toolchain.
