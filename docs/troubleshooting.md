# Troubleshooting

Start from a **symptom** you can observe, not from an internal component name.
Each entry lists what to check, in order. For a full component picture, open
**System Health** (Vulna Doctor) or run `vulna doctor` on the host — see
[diagnostics](diagnostics.md).

## I can't reach the dashboard

1. Is the stack running? On the host, check the containers are up.
2. Are you using the right URL and port? A `.dev` domain requires HTTPS.
3. If you put Vulna behind a reverse proxy, is TLS terminating correctly? See
   [networking](networking.md).
4. Check System Health → application/database.

## A Scout shows offline

1. On the Scout host, run `vulnascout doctor` — it tests connectivity step by step
   and gives a remediation for each failure.
2. Confirm the Scout can reach the dashboard URL and that its certificate has not
   expired (System Health → certificates).
3. Check the Scout's local emergency stop is not set (`vulnascout resume`).

## A scan never finishes / is stuck

1. Maintenance → look for **stuck jobs** (running much longer than expected).
2. Check the target is actually reachable from the Scout and the scope is
   approved.
3. Cancel the stuck job and re-run with a lighter preset. On small hardware, see
   [low-resource](low-resource.md).

## A scan failed

1. Open the failed job and read its error. Subscribe a
   [notification](notifications.md) to *scan failed* to catch these early.
2. Confirm the required scanner is installed on the Scout (preset preview shows
   what will be skipped and why).

## No CVE / KEV enrichment

1. Maintenance / System Health → **feeds**. Feeds may be stale or blocked
   outbound.
2. Retry the feed sync from the Feeds panel, or import a signed
   [offline bundle](low-resource.md) on an air-gapped site.

## Low disk / storage warnings

1. Maintenance → **storage** shows usage by category.
2. Preview and run a safe [retention cleanup](maintenance.md); it never deletes
   data still referenced by reports, active findings, or legal holds.

## Something else

- System Health → generate a **redacted support bundle** to share for help; it is
  built from an allowlist and contains no secrets.
- Check [diagnostics](diagnostics.md) and, before exposing Vulna publicly, the
  [exposure checklist](administration/exposure-checklist.md).
