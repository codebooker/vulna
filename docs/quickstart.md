# Quick start

Get from a clean, supported Linux host to a first **safe** scan. Two paths:

- **Simple path** — one host, the guided installer, a local Scout.
- **Advanced path** — pointers for distributed Scouts and reverse proxies.

> **Authorized use only.** Only assess systems and networks you own or have
> explicit written permission to test. See [authorized use](authorized-use.md).

## Before you start

- A 64-bit Linux host (amd64 or arm64) with Docker and Docker Compose.
- 2 CPU cores, 4 GB RAM, and 20 GB free disk for the dashboard (see
  [low-resource](low-resource.md) for smaller tiers).
- Outbound HTTPS if you want CVE intelligence feeds (optional; offline bundles
  work too).

## Simple path (one host)

1. **Install.** Download and review the verifying bootstrap, then run it. It
   checks a signed release before executing anything.

   ```sh
   curl -fsSLO https://vulna.dev/install.sh
   less install.sh          # review it
   sh install.sh -- install
   ```

   The stack comes up, migrates its database, seeds an administrator, and
   auto-enrolls a **scope-gated local Scout** over mutual TLS. See
   [installation](installation/README.md) for the manual path.

2. **Sign in and finish first-run.** Open the dashboard, sign in with the
   generated admin credentials, and follow the guided first-run wizard. Save your
   recovery codes somewhere safe.

3. **Approve a scope.** The local Scout can scan nothing until you approve a
   network scope. Approve a small private range you own, for example
   `192.0.2.0/24` in your own lab, and never a public range you do not control.

4. **Run a safe scan.** Pick the **Standard** preset (non-intrusive discovery,
   service detection, vulnerability checks, and TLS review) and start it. Watch
   the scan complete and findings appear.

5. **Read your findings.** See [understanding findings](understanding-findings.md)
   for what priority means and how to fix and verify.

Prefer to look around first? Turn on [demo mode](demo.md) to explore the
interface with sample data and no scanning.

## Advanced path

- **Add a remote Scout** at another site or segment:
  [deployment guide](deployment.md).
- **Put Vulna behind your own reverse proxy / change the URL or certificate**:
  [networking](networking.md).
- **Run on constrained or offline hardware**: [low-resource](low-resource.md).

## What to read next

- [Terminology](terminology.md) — scanner and vulnerability language in plain English.
- [Updates and rollback](updates.md) · [Backup and restore](backups.md)
- [Maintenance](maintenance.md) · [Troubleshooting](troubleshooting.md)
- Before exposing Vulna beyond your LAN: the
  [exposure checklist](administration/exposure-checklist.md).
