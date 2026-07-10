# VulnaScout

The Vulna remote assessment appliance — a single, statically linked Go binary
deployed at each site as a systemd service, container, or appliance image.

> **Authorized use only.** VulnaScout must only assess networks it is explicitly
> permitted to test. From Phase 3 onward it enforces a signed local policy and
> independently rejects out-of-scope, unsigned, or expired jobs.

**Phase 0 scope:** the Go module, a `cmd/vulnascout` entry point with `version`
and `self-test` commands, the internal package skeleton, unit tests, and a
multi-arch Dockerfile. Enrollment, policy enforcement, job execution, and
scanner plugins arrive in later phases.

## Build & run

```bash
# From scout/
go build -o bin/vulnascout ./cmd/vulnascout
./bin/vulnascout version
./bin/vulnascout self-test        # non-destructive local diagnostics

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
