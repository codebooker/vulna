# Low-resource, ARM64, intermittent, and offline operation

Vulna is built to run on the hardware and connectivity a homelab or small site
actually has: a Raspberry Pi, an old desktop, a small VM, a remote site on a
flaky link. This page explains the operating profiles, resource budgets,
backpressure, the durable result queue, and signed offline bundles.

See [ADR 0027](adr/0027-low-resource-and-offline.md) for the design rationale.

## Operating profiles

VulnaDash picks an operating profile for each Scout from the CPU, memory, and
disk it reports in its heartbeat. Memory is the dominant constraint for the
scanners Vulna drives, so it selects the tier:

| Profile      | Example hardware                                  | Memory     | Behavior                                                        |
| ------------ | ------------------------------------------------- | ---------- | -------------------------------------------------------------- |
| **Lite**     | Raspberry Pi 3B+/4 (1-2 GB), thin client          | up to 2 GB | one heavy stage at a time; expensive components off             |
| **Standard** | Mini PC / NUC / small VM (2-6 GB)                 | 2-6 GB     | moderate concurrency; all safe stages                          |
| **Full**     | Server or large VM (6 GB+)                         | 6 GB and up| full concurrency and components                                |

Under **Lite**, expensive components are disabled to fit modest hardware: active
ZAP web testing (passive review still runs), local full-text indexing, large PDF
report rendering (CSV/JSON still available), and high-frequency CVE feed
re-matching. Heavy stages are serialized so a scan cannot exhaust memory.

Concurrency and packet rates are derived from the host but are always **clamped to
the signed local-policy limits** — a profile only ever restricts work. The
`GET /api/v1/resources` endpoint shows the current profile, budgets, and
reference tiers.

### Architecture baselines

Official Scout builds target `linux/amd64` and `linux/arm64`. The reference
minimums for a Lite assessment (discovery + service detection + non-intrusive
vulnerability checks over a small subnet):

| Tier            | CPU     | RAM    | Disk   |
| --------------- | ------- | ------ | ------ |
| Scout (Lite)    | 1 core  | 512 MB | 1 GB   |
| Scout (Standard)| 1-2 core| 1-2 GB | 2 GB   |
| VulnaDash       | 2 cores | 4 GB   | 20 GB  |

## Capability warnings

When you preview a preset for a Scout, VulnaDash warns if the preset exceeds that
Scout's recommended capability (for example, a heavy preset on Lite-tier
hardware). The warning is advisory: you can still run it, but expect longer run
times as heavy stages are serialized.

## Backpressure (fails closed)

Vulna stops taking on new heavy work before a host is in trouble, and always says
why:

- **Storage** — heavy jobs pause when the data volume is low on free space and are
  refused entirely when it is critically low, protecting evidence files and the
  database from a full volume.
- **Queue** — a full Scout queue pauses new admissions until running jobs finish.
- **Ingestion backlog** — a large backlog of unprocessed results pauses new heavy
  jobs so the dashboard can catch up.

Intrusive or scope-sensitive stages **fail closed**: they are refused whenever any
resource pressure is present. Every pause or refusal names the component, the
impact, and the next step.

## Intermittent links: the durable result queue

A Scout on an intermittent WAN link keeps finished work in an on-disk queue under
its state directory and uploads it when connectivity returns. Nothing is lost if
the link drops mid-scan or the Scout restarts.

- The backlog (item count and size) is reported in the heartbeat and visible on
  the dashboard.
- A byte cap (`result_queue_max_bytes`, default 256 MiB) provides backpressure so
  a long outage cannot fill the disk.
- Uploads are **idempotent**: each batch carries a content-derived key, so a
  Scout that resumes after a lost acknowledgement never creates a duplicate
  observation.

## Offline bundles (air-gapped sites)

Sites without internet access can import intelligence and updates from a signed
**offline bundle** carried in on removable media:

```
# Inspect before importing (metadata only, no changes)
POST /api/v1/resources/offline-bundle/inspect

# Verify and import (admin, audited)
POST /api/v1/resources/offline-bundle/import

# See what has been imported
GET  /api/v1/resources/offline-bundle/history
```

A bundle is a signed manifest describing **data only** — `intel`, `feeds`,
`templates`, or `update`. Import is signature-verified and **fails closed** on a
bad signature or a non-data kind. There is deliberately no executable or plugin
kind: an offline bundle can never side-load code. Inspection surfaces the bundle's
creation time, feed age, and content versions so you can judge freshness before
importing; a bundle older than 120 days is flagged as stale (still importable).

## Tuning knobs

Ordinary use needs none of these; they are here for constrained or offline sites.

| Setting (Scout `agent.json` / env)                    | Default   | Purpose                                       |
| ----------------------------------------------------- | --------- | --------------------------------------------- |
| `result_queue_max_bytes` / `VULNASCOUT_...`           | 256 MiB   | Cap on the durable upload backlog             |
| `heartbeat_interval_seconds` / `VULNASCOUT_HEARTBEAT_INTERVAL` | 60 | Heartbeat cadence (lower bandwidth = higher)  |
