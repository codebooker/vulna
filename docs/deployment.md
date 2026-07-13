# VulnaScout appliance deployment

> Just want everything on one machine? See
> [`../deploy/single-host/README.md`](../deploy/single-host/README.md) for the
> single-host deployment, which brings up VulnaDash **and** an auto-enrolled local
> Scout with one command. This document covers deploying a *remote* Scout.

VulnaScout is the remote assessment probe. It deploys as a Docker container, a
Debian package (amd64 or arm64 / Raspberry Pi-class), or a VM image, and enrolls
with VulnaDash over mutual TLS. Its identity and signed policy live in
`/var/lib/vulna`, which is never touched by upgrades or rollbacks.

## Layout

```
/opt/vulna/releases/<version>/vulnascout   # side-by-side release binaries
/opt/vulna/bin/vulnascout                  # symlink -> the active release
/opt/vulna/bin/vulna-update                # update/rollback engine
/usr/bin/vulna-appliance                   # operator console
/var/lib/vulna/                            # identity, policy, config (persistent)
/etc/systemd/system/vulnascout.service     # service unit
```

## Build packages

```sh
VERSION=1.0.0 deploy/probe/build-packages.sh   # -> dist/vulnascout_1.0.0_{amd64,arm64}.deb
```

## Docker probe

```sh
docker build -f deploy/probe/Dockerfile -t vulnascout .
docker run --rm -v vulna-data:/var/lib/vulna vulnascout enroll --server https://dash.example --token <token>
docker run -d  -v vulna-data:/var/lib/vulna vulnascout run
```

Multi-arch (amd64 + arm64):

```sh
docker buildx build --platform linux/amd64,linux/arm64 -f deploy/probe/Dockerfile -t vulnascout .
```

## Fresh VM enrollment (documented commands)

On a fresh Debian/Ubuntu VM (amd64 or arm64):

```sh
sudo dpkg -i vulnascout_1.0.0_amd64.deb || sudo apt-get -f install -y
sudo vulna-appliance enroll --server https://dash.example --token <one-time-token>
vulna-appliance status
```

The package creates the `vulna` user and data dir, installs and starts the
service, and activates the shipped release. Enrollment writes the client
certificate and signed local policy into `/var/lib/vulna`. Fully unattended
provisioning uses `deploy/probe/cloud-init.yaml` as the instance user-data.

### Raspberry Pi-class ARM64

Install the `arm64` package the same way; Nmap is pulled in as a dependency and
the probe runs unprivileged (connect-scan, no raw sockets), so it passes the same
smoke test on Pi-class hardware:

```sh
sudo dpkg -i vulnascout_1.0.0_arm64.deb || sudo apt-get -f install -y
sudo vulna-appliance enroll --server https://dash.example --token <token>
```

## Upgrade and rollback

Upgrades install a new release beside the current one and re-point the symlink;
identity and policy in `/var/lib/vulna` are untouched. Rollback re-points the
symlink at the previous release.

```sh
sudo vulna-appliance update 1.1.0 /path/to/vulnascout   # install + activate + restart
sudo vulna-appliance rollback                           # revert to the prior release
vulna-appliance version
```

The `deploy/probe/smoke_test.sh` check proves that an upgrade preserves identity
and policy and that a rollback restores the prior version.

## Observability (VulnaPulse)

Start the monitoring stack (Prometheus, Grafana, and the Postgres/Redis/host/
container exporters) alongside the main stack:

```sh
docker compose --profile monitoring up -d
```

- **Grafana** (user `admin`, password `GRAFANA_PASSWORD`) loads the Prometheus
  datasource and the "Vulna Overview" dashboard automatically. The password is
  required, must be at least 16 characters, and cannot be a shipped placeholder.
- **Prometheus** scrapes VulnaDash at `api:8000/metrics`, plus the exporters, and
  evaluates the alert rules in `deploy/monitoring/prometheus/alerts.yml`
  (including a stale-CVE-feed alert).

Neither UI is published on a host port. Reach it only through an authenticated
operator tunnel or an explicit, access-controlled Compose override.

VulnaDash exposes only **aggregate, non-sensitive** metrics at `/metrics`: counts
by severity/status, probe liveness, and feed freshness. No finding titles,
descriptions, evidence, or IP addresses appear in any label or value. The public
Caddy proxy does not route `/metrics`, so it is reachable only on the internal
Docker network for Prometheus to scrape.

## Adding a remote Scout (Phase 20)

In VulnaDash, use **Add VulnaScout** on a site to generate a one-time install
command. Run it on the remote Linux host (amd64/arm64):

```sh
VULNA_SERVER=https://vulna.example.com VULNA_ENROLL_TOKEN=<token> sh install-scout.sh
```

The command downloads a **pinned, signed** release, verifies its Ed25519 signature
and checksum before installing, then enrolls. The token is single-use, expires,
and is passed via the environment so it does not linger in process listings. No
inbound port is opened on the remote host; all communication is Scout-initiated
outbound. Enrolling does **not** authorize any target — approve a scope afterward.

### Operating a remote Scout

```sh
vulnascout doctor    # staged connection test with remediation for DNS/TLS/clock/…
vulnascout stop      # local emergency stop — works even if VulnaDash is unreachable
vulnascout resume    # clear the emergency stop
vulnascout reset     # revoke this identity centrally, then wipe local state to re-enroll
```

The emergency stop and the local signed policy remain authoritative even when the
central service is unavailable or compromised. `reset` self-revokes over mTLS so
the old identity can no longer poll or upload; the private key is removed in place
and never leaves the Scout.
