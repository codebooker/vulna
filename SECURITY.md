# Security Policy

Vulna is security-sensitive software: it orchestrates network scanning and
authorized penetration-testing tooling across multiple sites. We take the
security of the platform — and the safety of the environments it assesses —
seriously.

## Authorized use only

Vulna must only be used to assess systems and networks that the operator **owns**
or has **explicit, written permission** to test. Unauthorized scanning or
exploitation may be illegal. See [`docs/authorized-use.md`](docs/authorized-use.md)
and [`docs/rules-of-engagement.md`](docs/rules-of-engagement.md).

## Core safety guarantees

These invariants are enforced in depth and must never be weakened for
convenience:

- **No arbitrary remote shell.** The orchestrator never accepts or transmits an
  arbitrary command string for a probe to execute. Scanners run through typed,
  versioned plugin manifests with allowlisted arguments.
- **Local target enforcement.** Each VulnaScout stores a signed local policy and
  independently rejects any target outside its approved CIDRs, any out-of-scope
  DNS resolution or redirect, and any prohibited profile.
- **Outbound-only probes.** Probes initiate all communication over HTTPS with
  mutual TLS; no inbound management port is required.
- **Signed jobs and policies.** Job envelopes and local policies are signed
  (Ed25519); probes reject unsigned, altered, or expired jobs.
- **Least privilege & untrusted input.** Scanner output is treated as untrusted
  and strictly parsed; evidence is encrypted at rest; audit logs are append-only.
- **Intrusive actions are gated.** Controlled-pentest and exploit-validation
  stages are disabled by default and require explicit, role-restricted approval.

Non-goals (never automated): denial of service, data destruction, persistence,
ransomware simulation, unrestricted brute force, credential dumping, and
internet-wide scanning. See the build plan §3.3.

## Reporting a vulnerability

If you discover a security vulnerability in Vulna itself, please report it
privately. **Do not open a public issue for security reports.**

- Use GitHub's **private vulnerability reporting** ("Report a vulnerability" on
  the repository's Security tab), or
- Email the maintainers at the address listed on the project page.

Please include a description, affected version/commit, reproduction steps, and
impact assessment. We aim to acknowledge reports within a few business days and
will coordinate a fix and disclosure timeline with you.

## Supported versions

Vulna is pre-1.0 and under active development. Until the first stable release,
only the `main` branch receives security fixes.

## Scope

In scope: the VulnaDash orchestrator, VulnaScout agent, plugin framework, and
their default configurations. Out of scope: vulnerabilities in third-party
scanner tools (Nmap, Nuclei, ZAP, testssl.sh, Metasploit) — report those to
their respective projects — and issues that require already-compromised
credentials or physical access beyond the documented threat model.

## Release verification

Release artifacts are checksummed and signed with an Ed25519 release key. Verify
a download before trusting it:

```sh
VULNA_RELEASE_PUBKEY=release_ed25519.pub deploy/release/verify.sh dist/
```

This checks the signature over `SHA256SUMS` (authenticity) and then every
artifact's checksum (integrity); it fails if either does not match. Dependency
audits (`pip-audit`, `npm audit`, `govulncheck`), the backup/restore round-trip,
and release signing run in the `security` CI workflow. Because
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) has no fixed
`x/crypto/openpgp` release, CI also proves that the affected OpenPGP package and its
subpackages are absent from every supported CLI and Scout build graph.
