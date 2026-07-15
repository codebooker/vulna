# Quick start

Get from a clean, supported Linux host to a first **safe** scan. The appliance
includes a local Scout, so a second endpoint is not required when the appliance
can reach the network you want to assess.

> **Authorized use only.** Only assess systems and networks you own or have
> explicit written permission to test. See [authorized use](authorized-use.md).

## Before you start

- A 64-bit Linux host (amd64 or arm64) with Docker and Docker Compose.
- 2 CPU cores, 4 GB RAM, and 20 GB free disk for the dashboard (see
  [low-resource](low-resource.md) for smaller tiers).
- Outbound HTTPS if you want CVE intelligence feeds (optional; offline bundles
  work too).

## Simple path (one host)

1. **Install.** Choose an exact tag from the
   [releases page](https://github.com/codebooker/vulna/releases), download its
   bootstrap, review it, and run it. The bootstrap verifies the signed release
   manifest before executing the installer.

   ```sh
   VULNA_VERSION="vX.Y.Z"
   curl -fsSLO "https://github.com/codebooker/vulna/releases/download/${VULNA_VERSION}/install.sh"
   less install.sh
   VULNA_VERSION="${VULNA_VERSION}" sh install.sh -- install
   ```

   Replace `vX.Y.Z` with the tag you selected; do not run the placeholder
   unchanged.

   The stack comes up, migrates its database, seeds an administrator, and
   auto-enrolls a **scope-gated local Scout** over mutual TLS. See
   [installation](installation/README.md) for the manual path.

2. **Sign in and finish first-run.** Open the dashboard, sign in with the
   generated admin credentials, and follow the guided first-run wizard. Save your
   recovery codes somewhere safe.

3. **Approve a scope.** The local Scout can scan nothing until you approve a
   network scope. In the wizard, choose a small private range you own—for example
   `192.168.50.0/24` for a lab using that subnet. Public ranges require a separate
   explicit opt-in and must never be enabled for addresses you are not authorized
   to assess.

4. **Confirm the Scout.** Continue only after the wizard shows the local Scout as
   connected. If it is not connected, use **Check again** and follow the displayed
   health guidance instead of launching a job that cannot run.

5. **Run a safe scan.** Pick **Standard Security Check** (non-intrusive
   discovery, service detection, vulnerability checks, and TLS review) and start
   it. Watch the scan's stages and diagnostics on **Operations → Scans**.

6. **Read and share the result.** Review priority and evidence under
   **Operations → Findings**, then generate a PDF, CSV, or JSON artifact under
   **Management → Reports**. See
   [understanding findings](understanding-findings.md) and
   [reporting](reporting.md).

Prefer to look around first? Turn on [demo mode](demo.md) to explore the
interface with sample data and no scanning.

## Add another location

- **Remote Scout (recommended):** run the scanners at the site and enforce signed
  scope locally.
- **VulnaRelay (advanced):** run only a WireGuard endpoint at the site and scan
  through its centrally controlled tunnel.

Use the [endpoint deployment guide](deployment.md) to choose and install either
mode. Both enroll with a one-time command generated under
**Management → Appliances** and remain blocked until scope is approved.

Other advanced paths:

- **Put Vulna behind your own reverse proxy / change the URL or certificate**:
  [networking](networking.md).
- **Run on constrained or offline hardware**: [low-resource](low-resource.md).

## What to read next

- [Terminology](terminology.md) — scanner and vulnerability language in plain English.
- [Endpoint deployment](deployment.md) · [VulnaRelay](relay.md)
- [Authenticated inventory](authenticated-inventory.md) · [Inventory intelligence](passive-inventory.md)
- [Updates and rollback](updates.md) · [Backup and restore](backups.md)
- [Maintenance](maintenance.md) · [Troubleshooting](troubleshooting.md)
- Before exposing Vulna beyond your LAN: the
  [exposure checklist](administration/exposure-checklist.md).
