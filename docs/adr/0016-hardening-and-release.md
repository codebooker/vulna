# ADR 0016: Hardening and Public Release

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 15 (Hardening and public release)

## Context

Before a public release, Vulna needs supply-chain hygiene, verifiable release
integrity, a tested disaster-recovery path, and reviewer-facing documentation —
without a heavy new toolchain (build plan Phase 15). It also must keep its
security posture honest: no unresolved high-severity dependency findings, signed
and checksummed artifacts, and a restore test that actually runs.

## Decisions

### 1. Fix dependency advisories by upgrading, not suppressing

The dependency scan turned up advisories in `cryptography`, `starlette` (via
FastAPI), and `pytest`. Rather than add an ignore list, the pins were bumped to
advisory-clean versions (cryptography 49, starlette pinned explicitly to 1.3.1
since FastAPI's floor is open, pytest 9, FastAPI 0.139) and the full suite re-run
— all 193 tests pass. `pip-audit`, `npm audit --audit-level=high`, and
`govulncheck` are all clean. A clean upgrade is strictly better than a
justified-but-standing suppression, and it is what the acceptance criterion
("no high-severity unresolved findings") should mean.

### 2. Scanning runs in CI, on every change

A `security` workflow runs the three language scanners plus the backup and
release smoke tests. Advisories then surface on the PR that introduces (or fails
to update) a vulnerable dependency, not months later. Because the scanners can
start flagging a previously-clean dependency at any time, running them
continuously — not once at release — is the point.

### 3. Backups verify integrity before restoring; releases before trusting

Both the backup and the release flows put a checksum (and, for releases, an
Ed25519 signature) between the artifact and its consumer. `restore.sh` refuses an
archive whose SHA-256 does not match; `verify.sh` refuses artifacts whose
signature is invalid or whose checksums do not match. The identity/policy-bearing
data directory is included in every backup, so a restore brings a probe fleet's
trust material back intact. Both paths have smoke tests that assert the happy path
*and* that tampering is rejected — the rejection is the security property, so it
is tested explicitly.

### 4. Ed25519 signing via OpenSSL, no new release toolchain

Releases are signed with an Ed25519 key using OpenSSL, which is already present
everywhere the project builds and matches the Ed25519 the platform already uses
for jobs and policy. The scripts select an OpenSSL that supports Ed25519 (system
OpenSSL 3.x in CI; a real OpenSSL locally, since macOS ships LibreSSL), avoiding a
dependency on cosign/minisign/GPG for the base flow.

### 5. Sample lab is isolated and clearly marked

VulnaLab ships as a separate Compose file of deliberately-vulnerable targets with
prominent "isolated use only" warnings, so it can demonstrate the full workflow
without ever being confused for something to run near production.

## Consequences

- The project ships with clean dependency scans, signed+checksummed releases, a
  tested restore path, SBOMs, and a reviewer checklist.
- Security regressions in dependencies or the backup/release mechanics are caught
  by CI.
- Full "restore succeeds" against a live PostgreSQL still needs a running database
  (the smoke test covers the archive/checksum/data-dir mechanics; the scripts
  carry the `pg_dump`/`pg_restore` integration for real deployments).

## Alternatives considered

- **Suppressing dependency advisories with a triage file:** rejected while a clean
  upgrade exists; suppression is the fallback for advisories with no fix, not the
  default.
- **cosign/sigstore for release signing:** deferred; it is a good future addition
  for transparency-log-backed signatures, but it adds a toolchain, whereas OpenSSL
  Ed25519 is already available and sufficient for signed+checksummed artifacts.
- **Bundling the vulnerable lab into the main Compose file:** rejected as unsafe;
  the lab is deliberately separate and warning-labeled.
