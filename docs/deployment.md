# VulnaScout appliance deployment

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
