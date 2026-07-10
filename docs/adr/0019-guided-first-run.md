# ADR 0019: Guided First Run and First Safe Assessment

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 19 (Guided First Run and First Safe Assessment)

## Context

After installation (Phase 18) a new operator lands on a login page with a
connected-but-idle local Scout and no obvious path to value. Phase 19 turns first
login into a short, understandable route to a first **safe** assessment, without
requiring the operator to understand scopes, jobs, workflows, or scanner syntax —
while preserving every security control.

## Decisions

### 1. A resumable, server-side wizard state

Wizard progress lives in one `OnboardingState` row per organization
(`current_step` + `completed_steps`), not in the browser. The frontend renders
whatever step the server reports, and each step is marked complete idempotently.
Refreshing or reopening the browser resumes exactly where the operator left off
and never duplicates work (re-completing a step is a no-op). This satisfies the
"refresh/close does not lose progress or create duplicate scans" criterion.

### 2. The wizard is thin; it never bypasses a control

Scope approval and job launch go through the ordinary, audited `/scopes` and
`/jobs` endpoints. The onboarding API only *assists*: it previews, suggests,
summarizes, and records progress. It cannot create an approved scope, sign a job,
widen a policy, or skip mTLS/scope/expiry checks — those remain exactly where they
were. A new user reaches a safe assessment without visiting the advanced
administration pages, but the same enforcement runs underneath.

### 3. Detected networks are advisory only

The local Scout reports the private ranges it can see (RFC1918 IPv4 only; loopback,
link-local, and public are excluded on the Scout side) in its heartbeat health.
`GET /onboarding/network-candidates` surfaces them as **suggestions**. Nothing is
saved or scanned from detection — the operator must type or accept a range and
approve it explicitly. The API and UI both state that suggestions are not
approved.

### 4. Scope guardrails reuse the real validation

Scope previews call the same `validate_cidr` used by real scope creation, so
`0.0.0.0/0`, `::/0`, malformed input, and (by default) public ranges are rejected
before anything is saved. The preview adds advisory, non-blocking warnings and a
`requires_confirmation` flag for public space and unusually broad ranges; the UI
requires an extra explicit confirmation for those. No detected subnet is ever
saved or scanned until the user approves it.

### 5. An isolated demo target: loopback

The optional demo assessment targets `127.0.0.1/32` — the Scout assessing itself
over loopback. It is private by construction, cannot reach any other host, and
cannot be exposed publicly by the standard configuration. Crucially, the demo is
**not** a bypass: the operator still approves the loopback scope through the normal
path, so the demo exercises the complete, real workflow rather than a mock.

### 6. Recovery codes follow the authentication security model

`POST /onboarding/recovery-codes` generates ten CSPRNG codes, shows them exactly
once, and stores only Argon2 hashes on the user (the same hashing as passwords).
Codes are consumed one at a time (`verify_and_consume_recovery_code`). Plaintext is
never persisted or logged.

### 7. One safe preset now; tuning later

Phase 19 ships the single **Standard Security Check** preset (safe discovery +
non-intrusive vulnerability and TLS checks; no intrusive tests, active web, or
credentials), matching the recommended default. The preset shape is
forward-compatible with the automatic tuning and additional presets that Phase 21
adds. The pre-scan summary reports targets, host estimate, checks, resource and
duration class, and data-retention behavior before launch.

## Security constraints (how they are met)

- **Network detection is advisory only** — detection never writes a scope; see §3.
- **No unsafe defaults** — the wizard cannot enable controlled pentesting,
  public-address scanning, unrestricted templates, or credentials. The only preset
  is non-intrusive; public ranges require the explicit opt-in and confirmation
  that already gate the scopes API.
- **Recovery material per the auth model** — CSPRNG generation, Argon2-hashed
  storage, one-time use; see §6.

## Consequences

- A new operator gets from login to a first safe assessment through a guided flow,
  understanding what will happen and why, without touching advanced pages.
- The wizard adds no new trust boundary and no new way to authorize a scan.
- Detection, presets, and the demo are all safe-by-construction.

## Rollback / migration

Additive and opt-in. The wizard appears only while onboarding is incomplete and
un-dismissed; it can be skipped and resumed. Existing deployments gain the
`onboarding_states` table and two nullable/defaulted `users` columns; no existing
behavior changes. Dismissing or completing the wizard leaves a fully functional
dashboard.

## Alternatives considered

- **Storing wizard progress in the browser.** Rejected: it would not be resumable
  across devices and risks duplicate scans on refresh.
- **Auto-approving a detected subnet or a default local scope for "zero-click"
  scanning.** Rejected outright — it violates the rule that scope is never
  authorized automatically.
- **A dedicated vulnerable demo container.** Deferred: a loopback self-scan is
  isolated by construction, needs no extra service, and cannot be exposed
  publicly, so it is a safer default demo for this phase.
