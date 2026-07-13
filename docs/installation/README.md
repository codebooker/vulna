# Installing Vulna

The supported way to install Vulna on one host is the `vulna` installer CLI. It
runs environment **preflight** checks, generates strong secrets into a restrictive
configuration, and materializes the single-host deployment. It is safe to re-run,
supports a dry run, and uninstalls without deleting your data.

> The installer sets up the same single-host stack described in
> [`../../deploy/single-host/README.md`](../../deploy/single-host/README.md):
> VulnaDash plus an auto-enrolled, **scope-gated** local Scout. See
> [ADR 0018](../adr/0018-installer-and-preflight.md) for the design.

## Option A — Verified bootstrap (recommended)

The bootstrap script downloads a **pinned** release of the CLI, verifies its
SHA-256 checksum and Ed25519 signature, and only then runs it. Review the script
first; it never pipes unverified content into a shell.

```bash
# 1. Download and read the script.
curl -fsSLO https://github.com/codebooker/vulna/releases/latest/download/install.sh
less install.sh

# 2. Run it. Everything after `--` is passed to `vulna install`.
VULNA_VERSION=v1.0.0 sh install.sh -- install
```

The installer prompts only for: installation directory, data directory,
deployment profile (`1` Small Business / `2` Enterprise), access mode
(`localhost` / `lan` / `public`), hostname or URL, and whether to enable update
checks. The profile changes initial dashboard organization only; it never disables
a capability or security control. It then runs preflight and installs.

## Option B — Manual installation (no shell pipeline)

If you prefer not to run a bootstrap script:

1. Download the release assets for your platform from the
   [releases page](https://github.com/codebooker/vulna/releases): the
   `vulna_<version>_linux_<arch>` binary, `SHA256SUMS`, and `SHA256SUMS.sig`.
2. Verify authenticity, then integrity:
   ```bash
   # Authenticity: signature over the checksum manifest.
   openssl pkeyutl -verify -pubin -inkey vulna_release_ed25519.pub -rawin \
       -in SHA256SUMS -sigfile SHA256SUMS.sig
   # Integrity: the binary matches the trusted manifest.
   grep " vulna_<version>_linux_<arch>$" SHA256SUMS | sha256sum -c -
   ```
3. Install and run it from a Vulna deployment directory (a source checkout or the
   extracted release bundle, which contains the Compose files):
   ```bash
   install -m 0755 vulna_<version>_linux_<arch> /usr/local/bin/vulna
   cd /path/to/vulna
   vulna install
   ```

## Preflight only

To check a host without changing anything:

```bash
vulna preflight
```

Every warning or failure names the problem, its impact, and the next step.
Failures (missing Docker, unsupported architecture, occupied ports 80/443,
insufficient disk, an unwritable target) block installation. Warnings — including
no outbound connectivity, since Vulna runs offline — can be passed with `--force`.

## Non-interactive / automation

Provide a versioned answer file:

```json
{
  "schema_version": 2,
  "install_dir": "/opt/vulna",
  "data_dir": "/opt/vulna/data",
  "config_dir": "/opt/vulna/config",
  "access_mode": "localhost",
  "admin_email": "admin@example.com",
  "update_checks": true,
  "deployment_profile": "small_business"
}
```

```bash
vulna install --non-interactive --answers answers.json --start
```

Schema-v1 answer files remain accepted and migrate in memory to
`small_business`. New saves always use schema v2. A flag can override either an
answer file or the interactive default:

```bash
vulna install --deployment-profile enterprise --dry-run
```

`vulna install --save-answers answers.json` writes the effective (non-secret)
answer file from an interactive run for later reuse.

## Dry run

See exactly what an install would do — including the selected profile, files,
directories, services, ports, and capabilities — without making any change:

```bash
vulna install --dry-run
```

## Re-running is safe

Re-running `vulna install` never rotates existing secrets and never overwrites
manual `.env` edits; it repairs generated files and fills in anything missing.

## Uninstall

```bash
vulna uninstall            # stops the stack; PRESERVES data volumes
vulna uninstall --purge /opt/vulna/data   # also deletes data; must name the data dir
```

The initial administrator password is generated into the `0600` `.env` file and
is never printed. Retrieve it from that file on the host, or reset it with the
in-container admin tools.
