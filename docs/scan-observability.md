# Scan progress and failure diagnostics

The **Scans** page refreshes while a job is active and shows percent complete, the
current workflow stage, completed-stage counts, and an estimated time remaining
when the Scout has enough evidence to calculate one.

## What the percentage means

Progress is based on workflow stages, not a cosmetic timer. A three-stage scan is
0% until its first stage finishes, then 33%, 66%, and finally 100% only after the
server accepts successful completion. The Scout reports 99% after the last stage
while result upload/finalization remains outstanding. A failed or cancelled job
keeps its last verified percentage rather than implying unfinished work completed.

Long-running scanners do not expose safe, consistent per-host progress, so the bar
can remain at one value while a stage is working. The current stage/scanner and
elapsed seconds distinguish that state from a stalled job.

ETA uses the average elapsed time of completed stages multiplied by the remaining
stage count. It is deliberately absent before one stage finishes and can move as
later stages take more or less time. The server stores an absolute estimate capped
at the signed job expiry; it never promises a completion time.

## Failure log

When a scanner is unavailable or returns an error, Scout reports a bounded record
with a code, stage, scanner, and message. The API sanitizes the summary and each
entry before storage, including common bearer/basic credentials, secret
assignments, URL user information, PEM blocks, control characters, and excessive
length. Scanner output and credential envelopes are never copied into this log.

Users with `jobs.read` continue to see the sanitized compatibility error on the job.
Only a principal with site-scoped `jobs.manage` can use **Failure log** or call:

```text
GET /api/v1/jobs/{job_id}/diagnostics
```

The endpoint returns only the caller's organization and permitted sites, and each
view adds an audit event. Failed/rejected terminal reports add a separate audit
event containing only the error code and entry count.

For debugging, first note the stage and scanner, then compare the Scout health and
capability status. A `scanner_unavailable` entry means the signed workflow requested
a plugin that Scout did not have. A `scanner_error` means the adapter ran but the
fixed command or protocol failed. The sanitized message should identify the safe
failure reason; raw scanner output remains protected as evidence and is not exposed
through diagnostics.

## Upgrade, backups, and portability

The additive migration marks historical completed jobs 100% and leaves every other
historical job at 0% because there is no trustworthy checkpoint to reconstruct.
Older Scouts remain compatible but do not populate live progress until upgraded.

Encrypted database backups include checkpoints and failure logs. Portability
exports omit them because they are operational debugging state. Downgrade removes
these fields irreversibly while retaining the job and its compatibility summary;
take and verify an encrypted backup first.
