# ADR 0043: Scout-bound credential envelopes and fixed inventory collectors

- Status: accepted
- Date: 2026-07-13

## Context

Software inventory needs authenticated host access, but reusable credentials must
not become general remote-execution material or persist at the edge. Assignments
also need deterministic behavior so a broad site default cannot silently override
an asset-specific credential.

## Decision

Vault secrets are append-only, purpose-encrypted versions and are never readable
through the API. Resolution uses asset → group → tag → network → site → preset and
fails closed on same-level conflicts. Each Scout generates an X25519 key at
enrollment and remains opted out by default.

For one signed, single-host job, VulnaDash decrypts the resolved version in memory
and immediately re-encrypts it to that Scout with ephemeral X25519, HKDF-SHA256,
and ChaCha20-Poly1305. Job/Scout binding is authenticated and the entire ciphertext
envelope is covered by the Ed25519 job signature. The Scout decrypts only after its
existing signature, expiry, scope, policy, limits, plugin, and opt-in checks pass.
SSH and WinRM collectors contain fixed read-only command allowlists; no job field
can supply a command.

## Consequences

Database compromise still exposes vault ciphertext and therefore requires the
application secret to be protected and backups encrypted. A Scout compromise can
expose a credential for a currently running job, but not the vault or credentials
assigned to other Scouts/jobs. Rotation cannot retract an envelope already
delivered, so short job expiries, cancellation, usage audit, and Scout containment
remain important. Portability can move non-secret metadata, but operational
credential continuity requires encrypted backup/restore.
