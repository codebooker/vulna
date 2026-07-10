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

## Required controls (baseline)

mTLS · signed jobs · signed local policy · signed plugin releases · checksums ·
strict parsers · content sanitization · least privilege · encrypted evidence ·
RBAC · append-only audit trail · SBOMs · dependency scanning · reproducible
releases where feasible.

## Out of scope (current)

- Vulnerabilities in third-party scanner tools themselves.
- Physical attacks on the orchestrator host beyond disk-encryption guidance.
- Nation-state supply-chain compromise of the base OS/toolchain.
