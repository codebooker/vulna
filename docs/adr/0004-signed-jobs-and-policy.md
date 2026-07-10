# ADR 0004: Ed25519-Signed Jobs and Local Policy

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 3 (Signed jobs and local policy)

## Context

A probe must be able to reject work that is unauthorized even if the
orchestrator is compromised or a job is tampered with in transit. Phase 3
introduces signed job envelopes and a signed local policy that the probe
verifies and enforces **independently**.

## Decisions

### 1. Ed25519 signatures over a canonical JSON form

The orchestrator holds an Ed25519 key pair; probes receive only the public key
(at enrollment). Both job envelopes and local-policy documents are signed over a
**canonical JSON** encoding so the Python signer and the Go verifier produce
byte-identical input:

- object keys sorted recursively,
- compact separators, no insignificant whitespace,
- HTML escaping disabled (literal `<`, `>`, `&`),
- integer fidelity (numbers decoded with `json.Number` on the Go side; no floats
  in signed payloads),
- no trailing newline.

The `signature` field is never part of the signed bytes. This is verified by
cross-language test vectors (Python signs; Go verifies) and a document-hash
equality test, so the canonicalizations cannot silently drift apart.

### 2. The probe enforces its signed local policy independently

The local policy carries approved CIDRs, denied CIDRs, allowed modes/plugins,
and resource limits, all derived from the site's approved network scopes. The
probe verifies the signature, then enforces scope itself: a job target must be
within an approved CIDR, not in a denied range, and (unless allowed) not public.
The orchestrator also validates targets at job-creation time — defense in depth,
not a substitute for local enforcement.

### 3. Deterministic policy, hash-based staleness detection

The policy document is deterministic given the probe's scopes, so its hash is
stable. The probe reports its policy hash in each heartbeat; the orchestrator
advertises the current hash and sets `update_available` on a mismatch, so the
probe re-syncs only when the policy actually changed.

### 4. Signed envelope stored verbatim

A job is signed once at creation and the exact signed envelope is stored and
delivered verbatim, so the bytes the probe verifies are identical to what was
signed — no reconstruction drift from timestamp formatting or key ordering.

### 5. Job lifecycle, expiry, and cancellation

Jobs carry `not_before`/`expires_at`; the probe rejects expired or not-yet-valid
jobs, and the orchestrator does not deliver expired ones. Cancellation is
cooperative: a queued job is cancelled immediately server-side; an active job is
flagged and advertised in the heartbeat `cancellations` list, and the probe
stops the (currently simulated) worker via context cancellation and reports the
result. This is the kill switch until real scanners arrive in Phase 4.

## Consequences

- The security-critical crypto is provably compatible across languages and is
  the first thing tested, reducing the risk of a subtle canonicalization bug.
- Losing the signing private key requires re-issuing it to probes; it is kept
  secret and backed up alongside the CA key.
- The Phase 3 worker is a simulation; it exercises the cancellation path but
  performs no assessment. Real scanner execution is Phase 4.

## Alternatives considered

- **RSA/ECDSA job signatures:** rejected in favor of Ed25519 for small, fast,
  deterministic signatures (matching the build plan's recommendation).
- **Reconstructing the envelope for delivery:** rejected; storing the signed
  bytes verbatim eliminates canonicalization drift between sign and deliver.
- **JCS (RFC 8785) or a library canonicalization:** rejected for now; a small,
  explicit canonical form is easy to reproduce in Go with the standard library
  and is covered by cross-language tests.
