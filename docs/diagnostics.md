# Vulna Doctor and diagnostics

When something is wrong, you should be able to see **which component** without
grepping logs across containers.

## Two surfaces

- **`vulna doctor`** (host) — diagnoses the machine you run it on: OS/architecture,
  container runtime, disk, ports, clock, DNS/outbound, and permissions.
  `--json` emits machine-readable output for automation.
  ```sh
  vulna doctor
  vulna doctor --json
  ```
- **System Health page** (web) — the full multi-component view: application and
  database, local and remote Scout health, scanner capabilities, feed freshness,
  CA and Scout certificate expiry, storage use, failed jobs/reports, and
  update/backup posture.

Every check names the **component**, its **impact**, the **data-safety** status
(safe / at risk), and a **next step** linked to documentation — so a diagnosis is
actionable without reading logs.

## Support bundle (redacted)

The System Health page can generate a **support bundle** for sharing when you need
help. It is built from an **allowlist** — only non-sensitive fields (versions,
health summary, feed/probe status, audit action/timestamps) — and never includes
passwords, tokens, private keys, authorization headers, raw credentials,
unrestricted evidence, or full scanner output. A secret scanner runs as a second
check, and the bundle is shown as a **preview** with a manifest of what it contains
before you export it.

## Safe repairs

Administrators can run a small set of **safe, confirmed, audited** repairs over
derived state (e.g. recreating a missing storage directory). Repairs never change
scopes, permissions, users, credentials, retention, or any security setting. Retry
a feed from the Feeds panel; restart a container from your container runtime.

## Event timeline

The page shows a local timeline of recent audited actions (configuration changes,
updates, restarts) and failed jobs — action, type, and timestamp only.
