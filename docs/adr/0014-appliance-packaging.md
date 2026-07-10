# ADR 0014: Appliance Packaging

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 13 (Appliance packaging)

## Context

VulnaScout must be trivial to deploy on the varied hardware a self-hoster has —
a VM, a container, or a Raspberry Pi-class box — and must survive upgrades and
rollbacks without re-enrolling. The build plan requires Debian/ARM64 packages, a
Docker probe, cloud-init, a VM-image path, an appliance console, and update +
rollback that never lose identity or policy (build plan Phase 13; and the
turnkey-appliance goal recorded for [[vulna-relay-deferred]]).

## Decisions

### 1. Separate the binary from the data, always

Release binaries live under `/opt/vulna/releases/<version>/`; the active one is a
single symlink `/opt/vulna/bin/vulnascout`. Identity, signed policy, and config
live in `/var/lib/vulna`, which packaging and updates never touch. This split is
what makes "upgrade does not lose identity or policy" and "rollback restores the
prior version" true by construction: an upgrade adds a release and moves the
symlink; a rollback moves it back; the data dir is untouched throughout.

### 2. Update/rollback is a tiny, testable shell engine

`update.sh` (install/activate/rollback/current) is deliberately small and
dependency-free, so it runs identically in a `.deb` post-install, the appliance
console, and CI. A `smoke_test.sh` drives it with stub binaries and asserts that
identity/policy files persist across an upgrade and that a rollback restores the
prior version — the two acceptance criteria that do not need a live VulnaDash.
The `packaging` CI job runs it (and shellchecks the scripts) on every change.

### 3. One static binary, tools bundled where it matters

The probe is a static, CGO-free binary, so the Docker image and packages are
built per architecture from the same source and the same Dockerfile
(`buildx --platform linux/amd64,linux/arm64`). Nmap is bundled/depended-on because
discovery is the baseline; the heavier scanners (Nuclei/testssl.sh/ZAP) are
optional and their stages skip gracefully when absent (Phase 6), keeping the base
appliance small.

### 4. Enrollment is a one-line command; cloud-init automates it

The package sets up the user, data dir, and service and activates the shipped
release; the operator then runs `vulna-appliance enroll --server … --token …`.
`cloud-init.yaml` does the same unattended and shreds the one-time token after
use. This is the "fresh VM enrolls with documented commands" path, identical on
amd64 and arm64.

### 5. Hardened, unprivileged service

The systemd unit runs the probe as a dedicated unprivileged user with
`NoNewPrivileges`, `ProtectSystem=strict`, a writable-path allowlist of just the
data dir, and related sandboxing. The probe needs no elevated privileges (Nmap
uses connect-scan, no raw sockets — Phase 4), so the appliance runs locked down
by default, including on Pi-class hardware.

## Consequences

- Upgrades and rollbacks are safe and near-instant (symlink flip), with identity
  and policy preserved.
- The same artifacts serve VM, container, and Pi deployments.
- Full end-to-end validation of "fresh VM enrolls" / "Pi smoke test" still needs a
  live VulnaDash and real hardware; the mechanics (build, install, update,
  rollback, scope-preserving data dir) are automated and CI-tested, and the
  arm64 binary is cross-built in CI.

## Alternatives considered

- **In-place binary replacement without versioned releases:** rejected; it makes
  rollback fragile and risks a half-written binary. Side-by-side releases plus a
  symlink are atomic and reversible.
- **A single fat image with every scanner:** rejected as too large for Pi-class
  devices; optional scanners are layered on when needed.
- **Storing identity under `/opt` with the binaries:** rejected; co-locating
  mutable identity with replaceable binaries is exactly what loses identity on
  upgrade. The data dir is deliberately separate.
