# Release process and qualification

A release must consistently deliver the easy path across the
[support matrix](support-matrix.md). This page describes the release-blocking
gate, the channels, the artifacts, and key handling. See
[ADR 0032](adr/0032-release-qualification.md).

## Release-blocking regression gate

A release **cannot be promoted** if the security-critical regression suite fails.
Run it with:

```sh
deploy/release/release_gate.sh
```

It runs the backend tests marked `release_gate`, covering **setup/enrollment,
target/scope enforcement, job signatures and signed local policy, job
cancellation, backup/restore, relay egress + kill switch, and data authorization**
(RBAC and cross-organization isolation). The full CI (backend, frontend, probe,
installer, packaging, schemas, hardening, dependency-scan, cross-builds) must also
be green, and the clean single-host install must reach a first safe assessment.

Qualification checklist for a release:

1. `deploy/release/release_gate.sh` is green.
2. Clean single-host install → first safe scan passes on each supported platform
   class.
3. Upgrade and rollback pass from every supported prior minor release.
4. Backup and restore pass (identity/CA preserved).
5. Artifacts are complete (below).

## Channels and support period

- **stable** — minor releases; the current minor and one prior are supported.
- **maintenance** — security and critical fixes only; slower-moving, enabled once
  the project has capacity.

Updates are never forced. The application never contacts a release server; updates
are run by the operator with the signed `vulna` CLI (see [updates](updates.md)).

## Release artifacts

Every release includes:

- Signed binaries (`vulna`, `vulnascout`, and `vulnarelay`) for
  `linux/amd64` and `linux/arm64`.
- A **deployment bundle** (`vulna-deploy_<version>.tar.gz`) with the Compose files,
  the single-host overlay, `.env.example`, and the backup/restore scripts. The
  bootstrap downloads this for `install` so the operator gets a working deployment,
  not just a bare binary. Build it with `deploy/release/build-deploy-bundle.sh`.
- A `SHA256SUMS` manifest and an **Ed25519 detached signature** over it.
- **SBOMs** for the images.
- **Migration notes** (see [migration-notes](migration-notes.md)) and
  **compatibility notes** (the [support matrix](support-matrix.md)).
- **Recovery instructions** (backup/restore, CA recovery; see
  [backups](backups.md)).

Consumers verify the signature (authenticity) and then the checksums (integrity)
before running anything — the bootstrap installer does this automatically.

### Assembling and publishing a release

Build the binaries and deployment bundle with the canonical artifact names used
by all three installers:

```sh
# 1. Build vulna, VulnaScout, VulnaRelay, and the deployment bundle.
deploy/release/build-release-artifacts.sh <vX.Y.Z> dist/

# 2. Generate the hosted bootstraps with the release public key embedded, so
#    `curl … | sh` works without the operator supplying a key.
deploy/release/embed-release-pubkey.sh release_ed25519.pub > dist/install.sh
deploy/release/embed-release-pubkey.sh release_ed25519.pub scripts/install-scout.sh \
  > dist/install-scout.sh
deploy/release/embed-release-pubkey.sh release_ed25519.pub scripts/install-relay.sh \
  > dist/install-relay.sh

# 3. Add the image SBOMs to dist/, then write and sign one complete manifest
#    with the offline Ed25519 private key.
VULNA_RELEASE_KEY=release_ed25519.pem deploy/release/sign.sh dist/
```

The hosted installers carry only the **public** key. Run `sign.sh` last so the
final manifest covers every binary, bundle, SBOM, and installer file.

## Signing keys: rotation and compromise recovery

- The **release signing key** (Ed25519) is generated once and kept offline/secret;
  only the public key is embedded in the verifying bootstrap.
- **Rotation:** publish the new public key in a signed release under the old key,
  then sign subsequent releases with the new key. Document the changeover.
- **Compromise:** revoke the compromised key publicly, publish an out-of-band
  advisory, rotate to a new key, and re-sign the current supported releases. The
  internal deployment CA is separate and is rotated per
  [maintenance](maintenance.md).

Third-party or community templates must never silently replace the signed official
images; see [packaging policy](packaging-policy.md).
