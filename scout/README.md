# VulnaScout

The Vulna remote assessment appliance — a single, statically linked Go binary
deployed at each site as a systemd service, container, or appliance image.

> **Authorized use only.** VulnaScout must only assess networks it is explicitly
> permitted to test. From Phase 3 onward it enforces a signed local policy and
> independently rejects out-of-scope, unsigned, or expired jobs.

**Current scope (through Phase 2):** enrollment and heartbeat. The agent
generates its key pair locally, submits a CSR with a one-time token, stores the
issued client certificate, and heartbeats to the orchestrator over mutual TLS.
The agent is standard-library-only (no external dependencies) so it
cross-compiles to a single static binary for amd64 and arm64. Policy
enforcement, job execution, and scanner plugins arrive in later phases.

## Commands

```text
vulnascout version                 Print version/build info
vulnascout self-test               Non-destructive local diagnostics
vulnascout enroll --server <url> --token <t>   Enroll using a one-time token
vulnascout status                  Show local enrollment status
vulnascout run                     Heartbeat to the orchestrator until stopped
```

Configuration is read from `/etc/vulna/agent.json` (see
`packaging/systemd/agent.json.example`) with `VULNASCOUT_*` environment
overrides; flags override both. State (key `0600`, certificate, CA, `state.json`)
lives under `--state-dir` (default `/var/lib/vulna`).

## Build & run

```bash
# From scout/
go build -o bin/vulnascout ./cmd/vulnascout
./bin/vulnascout version
./bin/vulnascout self-test        # non-destructive local diagnostics

# Enroll then run (against a dev orchestrator)
./bin/vulnascout enroll --server https://localhost --token vscout_... --state-dir ./state --insecure
./bin/vulnascout run --state-dir ./state --insecure

# Tests / vet / format
go test ./...
go vet ./...
gofmt -l .

# Cross-compile (static binaries)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/vulnascout-linux-amd64 ./cmd/vulnascout
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/vulnascout-linux-arm64 ./cmd/vulnascout
```

## Layout

```text
scout/
├── cmd/vulnascout/     # binary entry point
├── internal/           # api, config, enrollment, executor, policy, queue,
│                       #   scanners, storage, telemetry, updater, cli, selftest
├── plugins/            # scanner plugin manifests (nmap, nuclei, zap, testssl, metasploit)
├── packaging/          # deb, docker, systemd, cloud-init, appliance
└── tests/              # integration tests (later phases)
```
