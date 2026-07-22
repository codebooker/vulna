# Deploying VulnaScout and VulnaRelay endpoints

> If the central appliance can reach the target network, stop here and use its
> bundled local Scout. See
> [`../deploy/single-host/README.md`](../deploy/single-host/README.md) for the
> single-host deployment. A remote endpoint is needed only for another location
> or an isolated network segment.

## Choose the endpoint role

| | VulnaScout | VulnaRelay |
|---|---|---|
| Remote host runs | Scanner agent and approved scanner stages | WireGuard tunnel agent; no scanners |
| Scanners run | At the remote site | On the central appliance |
| Scope boundary | Signed policy enforced locally and centrally | Central egress policy plus Relay routing rules |
| Remote requirements | Linux `amd64`/`arm64` and resources for the selected scanners | Linux `amd64`/`arm64`, WireGuard, IP forwarding, and `iptables` |
| Recommended for | Most offices, sites, and network segments | Constrained sites or central-scan policies |

Prefer VulnaScout whenever the site can run it. Choose VulnaRelay deliberately
when a scanner-free endpoint is the requirement; read its
[security model and tradeoffs](relay.md) before enabling it.

Both endpoint types are linked to the appliance by a short-lived, single-use
enrollment token generated for a specific site. Enrollment issues an mTLS
identity. It does **not** authorize a target range.

## Add a remote Scout

1. Create the destination site in VulnaDash.
2. Open **Management → Appliances → Scouts**, select **Add Scout**, and choose
   the site.
3. Copy the generated command. It contains a one-time token and the exact signed
   release URL, and is shown only once.
4. Run the command as root on the remote Linux host:

   ```sh
   curl -fsSLo /tmp/install-scout.sh \
     https://github.com/codebooker/vulna/releases/download/vX.Y.Z/install-scout.sh
   VULNA_SERVER=https://vulna.example.com:8443 \
     VULNA_ENROLL_TOKEN=replace-with-the-shown-token \
     VULNA_VERSION=vX.Y.Z sh /tmp/install-scout.sh
   ```

   This is an illustrative shape only. Use the dashboard's command because it
   supplies the installed release tag, one-time token, and private-CA material
   when needed.

   With `VULNA_VERSION=latest`, the dashboard uses GitHub's
   `/releases/latest/download/install-scout.sh` route. The installer reads and
   verifies the release's signed `VERSION` asset before selecting the Scout
   binary; it does not construct a nonexistent `vlatest` tag.

5. Wait for the appliance page to show the Scout as connected, then approve the
   site's network scope. Until that approval, the Scout refuses every target.

The token is passed through the environment rather than a command argument so it
does not remain in process listings. The Scout initiates outbound mTLS traffic to
the appliance; no inbound management port is opened on the Scout.

### Operate a remote Scout

```sh
vulnascout doctor    # Check DNS, TLS, time, enrollment, and policy health.
vulnascout stop      # Engage the local emergency stop, even while offline.
vulnascout resume    # Clear the local emergency stop.
vulnascout reset     # Revoke the identity centrally and wipe local enrollment.
```

The emergency stop and signed local policy remain authoritative if VulnaDash is
unreachable. `reset` self-revokes over mTLS before removing its local private key.

## Scout packaging reference

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
docker run --rm -e VULNASCOUT_ENROLL_TOKEN=replace-with-the-shown-token \
  -v vulna-data:/var/lib/vulna vulnascout enroll --server https://dash.example:8443
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
sudo VULNASCOUT_ENROLL_TOKEN=replace-with-the-shown-token \
  vulna-appliance enroll --server https://dash.example:8443
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
sudo VULNASCOUT_ENROLL_TOKEN=replace-with-the-shown-token \
  vulna-appliance enroll --server https://dash.example:8443
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

## Add a Relay

Relay mode is off by default.

1. Open **Management → Appliances → Relay** and enable
   **Organization relay mode**.
2. Select **Add Relay**, choose a site, and run the generated command as root on
   the endpoint. The verified installer installs WireGuard dependencies when the
   host uses `apt` or `apk`, installs `vulnarelay`, enrolls it, and starts the
   hardened systemd service.
3. Enter approved CIDRs and any narrower denied CIDRs, then save the Relay scope.
   Public addresses stay blocked unless **Allow public addresses** is explicitly
   selected.
4. Confirm both the enrolled status and **Tunnel up** badge before scanning.

The Relay connects outbound to the appliance's control listener and WireGuard
endpoint. The appliance must publish TCP `8443` and UDP `51820` (or the configured
alternatives). Use the per-Relay kill switch for an immediate reversible stop;
use **Revoke** to invalidate its certificate, tear down the tunnel, and remove its
managed scope.

See [VulnaRelay](relay.md) for detailed routing, central-scanner behavior, scope
rules, recovery, and revocation.
