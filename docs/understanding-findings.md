# Understanding, fixing, and verifying findings

A **finding** is a specific issue Vulna observed on an asset or service. This
guide explains what a finding tells you and how to take it to closure.

See [terminology](terminology.md) for the vocabulary.

## Reading a finding

Each finding shows:

- **What and where** — the issue, the affected asset, and the service.
- **Severity** — info / low / medium / high / critical.
- **Priority** — Vulna's suggestion: **fix now**, **plan**, or **watch**.
  Priority is not just severity: a critical finding with low confidence is capped
  at "watch" rather than pushed to "fix now", so you are not sent chasing
  uncertain results.
- **Why it matters** — a plain-language rationale, plus any CVE, **KEV**, or EPSS
  signal. A KEV match means the vulnerability is being actively exploited in the
  wild; prioritize it.
- **Evidence** — sanitized supporting detail. Vulna never shows raw credentials or
  unbounded scanner output here.

## Deciding what to do

1. **Fix now** — exploited or high-confidence high/critical issues on exposed
   services. Remediate promptly.
2. **Plan** — real but less urgent issues; schedule them.
3. **Watch** — low-confidence or low-severity items; keep an eye on them.

If a finding is a false positive, mark it as such with a reason. If you must live
with it for a while, record a **risk acceptance** with an expiry — it will reopen
automatically when the acceptance lapses.

## Fixing and verifying

1. **Assign** an owner and a due date.
2. **Remediate** the underlying issue on the asset (patch, reconfigure, close the
   port).
3. **Verify** — use the finding's rescan action. Vulna re-runs only the relevant
   check with the same scanner. If the issue is no longer observed, the finding is
   **auto-resolved**; if it comes back later, it **reopens** automatically.

## Why a finding reopened

Reopening means a previously resolved issue was observed again — for example a
patch was rolled back or a service was reinstalled. Treat a reopened
high/critical finding as "fix now".

## Notifications

Subscribe a [notification channel](notifications.md) to *new critical or high
finding*, *KEV match*, and *verification failed* so you hear about the ones that
matter without watching the dashboard.
