# vulna — installer and administration CLI

A small, statically linked Go binary that installs and administers the Vulna
single-host deployment on a host. It runs environment **preflight** checks,
generates strong secrets into a restrictive configuration, materializes the
deployment idempotently, and can dry-run, start, and cleanly uninstall the stack.

It is distinct from the in-container `app.cli` maintenance CLI: `vulna` runs on
the host and needs neither the application runtime nor the database.

## Commands

```
vulna install      Preflight, generate config/secrets, materialize the deployment
vulna preflight    Run environment checks only (no changes)
vulna uninstall    Stop the stack and remove generated files (data preserved)
vulna version      Print version and build information
```

## Build

```bash
make cli-build         # -> cli/bin/vulna
make cli-test          # go vet + go test
```

## Install flow

See [docs/installation/](../docs/installation/README.md) for the verified
bootstrap and manual installation paths, and
[ADR 0018](../docs/adr/0018-installer-and-preflight.md) for the design and
security rationale. The layout stdlib-only; no third-party modules.
