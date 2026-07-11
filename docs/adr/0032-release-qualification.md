# ADR 0032: Release Qualification and Self-Hosting Ecosystem Packaging

- **Status:** Accepted
- **Date:** 2026-07-11
- **Phase:** 32 (Release Qualification and Self-Hosting Ecosystem Packaging)

## Context

For a 1.0, the easy path must consistently work across a small, honest support
matrix, a release must not ship if a security-critical regression fails, and
community packaging must be sustainable without diluting the official, signed
artifacts. This phase adds the support matrix, a release-blocking gate, a
packaging policy, release-process/artifact/key documentation, an install
diagnostics issue template, and reference benchmarks.

## Decisions

### 1. A small, testable support matrix

`deploy/release/support-matrix.json` (machine-readable) and `docs/support-matrix.md`
enumerate the supported Linux distributions, container-runtime/Compose versions,
`amd64`/`arm64`, single-host resource tiers, browsers, Dashboard/Scout
compatibility, and scanner versions. It is intentionally limited to what the
project can test continuously.

### 2. A release-blocking regression gate

The `release_gate` pytest marker tags the security-critical modules — setup and
enrollment, target/scope enforcement, job signatures and signed local policy, job
cancellation, backup/restore, relay egress + kill switch, and data authorization
(RBAC and cross-organization isolation). `deploy/release/release_gate.sh` runs
`pytest -m release_gate`; **a release cannot be promoted when it fails.** A
meta-test (`tests/test_release_gate.py`) enforces that every required module keeps
the mark and that the support matrix stays well-formed, so the gate cannot quietly
lose coverage.

### 3. Signed artifacts, channels, and key handling

Every release includes signed binaries, a `SHA256SUMS` manifest with an Ed25519
detached signature, SBOMs, migration notes, compatibility notes, and recovery
instructions (the release process reuses the Phase 15/24 signing and Phase 25
backup machinery). Two channels — **stable** (current + one prior minor) and a
slower **maintenance** channel — are documented, along with signing-key rotation
and compromise-recovery procedures.

### 4. A packaging policy that protects the official images

Packages are tiered: officially maintained, community-maintained templates, and
experimental examples. A community template cannot be presented as official unless
it meets the same upgrade and recovery tests, and **no packaging** may require
privileged containers, host filesystem access beyond the data/keys volumes, host
networking, or Docker socket access beyond the documented Scout/scanner boundary.
Third-party templates must not silently replace signed official images.

### 5. Privacy-safe support intake

An "Install / deployment help" issue form guides users to attach a **redacted
support bundle** (Phase 26) and `vulna doctor --json`, with an explicit privacy
checkbox, so support requests carry useful diagnostics without publishing secrets
or raw evidence.

### 6. Contributor guidance preserves the simple path

`CONTRIBUTING.md` gains a "Preserving the simple path" section binding every new
feature: one default path, safe defaults stay safe, the same security boundary,
no mystery failures, and the release gate must stay green.

## Security constraints (how they are met)

- **Release blocked on regression** — install, scope enforcement, signing,
  cancellation, backup/restore, and authorization are release-gated (tested).
- **No privileged packaging** — the packaging policy forbids privileged
  containers, host networking, host FS, and Docker socket access beyond the Scout
  boundary.
- **Signed images not silently replaced** — the policy requires official images by
  signed reference; key rotation/compromise recovery is documented.
- **Support without secrets** — the diagnostics template mandates the redacted
  support bundle and a privacy attestation.

## Consequences

- A 1.0 candidate has an objective, security-focused promotion gate and a clear,
  small support matrix.
- The community can contribute packaging without endangering the official,
  signed path.

## Rollback / migration

Additive: a pytest marker + gate script, a support-matrix data file, docs, an issue
template, and a CONTRIBUTING section. No code or schema changes. Marking existing
tests does not change their behavior.

## Alternatives considered

- **A broad support matrix (many distros/arches).** Rejected: the matrix must be
  limited to what is tested continuously, per the acceptance criteria.
- **A separate re-implemented gate suite.** Rejected as duplicative; marking the
  existing security-critical tests reuses coverage and a meta-test prevents drift.
