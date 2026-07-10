# ADR 0018: Safe Installer and Environment Preflight

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 18 (Safe Installer and Environment Preflight)

## Context

The single-host deployment (Phase 17) works, but installing it still meant
knowing the Compose invocation, hand-writing an `.env`, and discovering
environment problems (missing Docker, occupied ports, too little disk) only after
things failed halfway. Phase 18 provides **one supported installation workflow**
that detects common problems *before* any file is written or any service starts,
generates strong secrets, and is safe to re-run, dry-run, and cleanly uninstall.

## Decisions

### 1. A single `vulna` CLI, distributed as a signed release artifact

Installation and administration go through one small, statically linked Go binary
(`cli/`, stdlib-only, built for linux/amd64 and linux/arm64), mirroring VulnaScout
so it fits the existing signed-release pipeline. It is distinct from the
in-container `app.cli` maintenance CLI: `vulna` runs on the **host** and never
needs the application's Python runtime or database.

### 2. A verifying bootstrap that never trusts unverified remote content

`scripts/install.sh` downloads a **pinned** release of the CLI plus the
`SHA256SUMS` manifest and its detached Ed25519 signature, then, before executing
anything: (1) verifies the signature over the manifest against a pinned release
public key, and (2) verifies the artifact's SHA-256 against the now-trusted
manifest. Any mismatch aborts. Downloaded content is never piped into a shell —
the artifact is verified on disk and only then executed. This is the "download a
pinned CLI release, verify its checksum and signature, then invoke the CLI"
requirement, and it satisfies the security constraint against executing
unverified remote shell content. A fully manual installation path documents the
same steps for users who will not run a shell pipeline.

### 3. Preflight runs before any change and explains every problem

Before writing anything, the installer checks: supported OS/architecture,
container runtime and Compose v2, CPU/memory/free disk, port conflicts (80/443),
time synchronization, DNS/outbound reachability to the intelligence and update
sources, filesystem permissions, and an incompatible existing install. Every
non-passing result names the **problem, impact, and next step** (cross-phase rule:
no mystery failures). Hard failures (missing Docker, unsupported architecture,
occupied ports, insufficient disk, unwritable target) block the install; warnings
require `--force` to proceed. Loss of outbound connectivity is a **warning, not a
failure** — Vulna is designed to run offline.

### 4. Strong secrets, restrictive configuration, nothing leaked

The installer generates the database password, session/JWT key, and initial admin
password with `crypto/rand` and writes them only to a `0600` `.env` file in a
`0700` configuration directory. Secrets are **never printed to normal output or
logs** — the admin password is written to the restricted file and the operator is
told where, not shown its value.

### 5. Idempotent install; dry-run; non-interactive answer file

Re-running `vulna install` never rotates existing secrets and never overwrites an
operator's manual `.env` edits; it only fills in missing keys and rewrites the
non-secret install record — a safe "repair." `--dry-run` prints the exact files,
directories, services, ports, and capabilities that would be created and writes
nothing. `--non-interactive` reads a **versioned** answer file (unknown fields and
unsupported schema versions are rejected). Interactive prompts are limited to
installation directory, data directory, access mode, hostname/URL, and update
checks.

### 6. Clean uninstall preserves data; purge must name the data path

`vulna uninstall` stops the stack with `docker compose down` (named data volumes
are **preserved**) and removes only the generated `.env` and install record.
Deleting data requires `--purge <data-dir>`, which must exactly match the recorded
data directory as an explicit confirmation before removing volumes (`down -v`) and
the data directory.

### 7. Deployment model and its current limitation

The CLI operates on a Vulna **deployment directory** (a source checkout or an
extracted release bundle) and reuses the Phase 17 Compose project; the bootstrap
provides that directory. Persistent application data lives in Docker-managed named
volumes (Phase 17), not host bind mounts, so relocating bulk data to an arbitrary
path is an advanced, documented step rather than an installer default. Because
prebuilt images are not yet published to a registry, the deployment builds images
from source on first start (registry publishing is deferred to release
qualification). This is documented as a known limitation.

## Secret / capability inventory (delta over Phase 17)

- **New secrets:** none beyond those Phase 17 already required; the installer is
  what *generates* the database password, `VULNA_SECRET_KEY`, and the admin
  password, writing them 0600. It does not introduce a new trust boundary.
- **Capabilities:** the installer is an ordinary unprivileged host process. It
  does not modify firewall rules, mandatory access control, or existing file
  permissions, and it never runs the stack privileged or mounts the Docker socket.

## Consequences

- A supported clean host installs with one documented, verified command and no
  manual file edits.
- Environment problems surface before any change, each with a remedy.
- Re-runs are safe; dry-run is faithful; uninstall preserves data by default.

## Rollback / migration

The installer is additive and opt-in: existing deployments created by hand in
Phase 17 continue to work unchanged. Running `vulna install` against such a
directory adopts it (generating any missing secrets without rotating present
ones) and never destroys data. There is no schema change in this phase.

## Alternatives considered

- **A shell-only installer.** Rejected: preflight logic, answer-file validation,
  and idempotent secret handling are clearer and testable as a typed program; the
  shell layer is kept to a thin, auditable verify-then-exec bootstrap.
- **`curl … | sh`.** Rejected outright by the security constraints; the bootstrap
  verifies a signed artifact on disk before running it.
- **Bind-mounting all data volumes under a chosen data directory.** Deferred:
  relocating the database/evidence/report volumes reintroduces the non-root
  ownership problem solved in Phase 17 and is better handled as an explicit
  advanced option than as an installer default.
