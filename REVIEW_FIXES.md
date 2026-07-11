# Prioritized Fix List

> **Status: all 15 items implemented** (12 from review + 3 from live Hetzner-VM
> testing). Backend 377 tests pass + release gate green; CLI and Scout
> gofmt/vet/tests clean; shell scripts syntax-checked; the installer flow, the
> scanner image (13,320 nuclei templates), and the single-host Caddy config (via
> `caddy validate` + `docker compose config`) validated end-to-end.
>
> **Second pass (#6, #9, #13 built for real).** These three were initially a
> reframe or a partial fix; they are now genuinely implemented:
> - **#6** — the workflow now dispatches a real signed scan job when it enters the
>   scanning phase and advances the discovery/vuln/TLS stages on the job's
>   completion (not just a docstring change).
> - **#9** — raw scanner evidence is encrypted at rest with a key derived from
>   `VULNA_MASTER_KEY` (Fernet), with a plaintext fallback for dev.
> - **#13** — the *proper* fix: probe mTLS moved to a dedicated `:8443` listener so
>   the browser `:443` accepts a no-SNI (raw-IP) handshake. Raw-IP LAN access now
>   works, so the installer's IP rejection was relaxed to public-mode only.

Consolidated from a full-repo review (Codex) plus a scoped review of the unpushed
VulnaRelay / release-gate commits. Ordered by blast radius: silent security
bypasses first, then false safety signals (data-loss risk), then broken/misleading
features, then hardening.

**Legend:** ✅ verified directly in the code · ⚠️ reported, not independently re-run

The common root cause across Tiers 1–3 is commands/endpoints that **return success
while only printing or recording intent**. Where a command is deliberately advisory,
the minimum fix is to stop signaling success — a security tool reporting
"completed / USABLE / applied" for work it didn't do is the real hazard.

---

## Tier 1 — Silent security bypass (fix first)

### 1. Scout accepts any signed job when it has no local policy ✅
- **Where:** `scout/internal/policy/job.go:66`, `scout/internal/cli/cli.go:310`
- **Problem:** Every scope/mode check is gated behind `if p != nil`. `SyncPolicy`
  failure only logs and keeps polling, so a Scout that never synced enforces
  signature + time-bounds only and will run any job.
- **Fix:** Treat "no policy" as fail-closed — refuse to accept/run jobs when
  `p == nil`, and make startup `SyncPolicy` failure block execution (heartbeat-only
  until a policy lands). Add a test asserting a nil policy rejects an in-signature job.

### 2. `maximum_hosts` and other policy limits are never enforced ✅
- **Where:** `dash/backend/app/services/jobs.py` (`_validate_targets`),
  `scout/internal/policy/job.go:66`, `scout/internal/scanners/nmap/nmap.go:138`
- **Problem:** Target validation checks scope containment and public/private only —
  no host-count ceiling. Approving `10.0.0.0/8` and requesting it passes despite the
  256-host default. Concurrency, duration, allowed-plugins, and policy-version /
  probe-identity are likewise unchecked.
- **Fix:** In `_validate_targets`, sum expanded host counts across targets and reject
  over `maximum_hosts`; mirror the ceiling in `job.go` so the Scout enforces it
  independently. Add the remaining policy fields to `VerifyJob`'s comparison.

---

## Tier 2 — False safety signals / data-loss risk

### 3. Empty or partial archive is certified "USABLE" ✅
- **Where:** `deploy/backup/backup.sh:21`, `cli/cmd/vulna/backup.go:100`,
  `cli/internal/backup/manifest.go:131`
- **Problem:** `backup.sh` echoes and continues (no `exit`) when no DB dump source
  exists; verification trusts declared manifest metadata over archive contents.
  Reproduced with an archive containing only `./` — reported usable.
- **Fix:** `exit 1` in `backup.sh` when no dump source is available; have verification
  inspect the archive for the components it claims (non-empty `db.dump`, populated
  data dir) rather than trusting the manifest.

### 4. `vulna backup restore` restores nothing ✅
- **Where:** `cli/cmd/vulna/backup.go:257`
- **Problem:** Prints `restore.sh` and the safety-backup command as suggestions, then
  `return 0`. No decrypt, extract, safety backup, or `restore.sh` invocation.
- **Fix:** Actually take the safety backup, decrypt/extract the bundle, and invoke
  `restore.sh` — or, if intentionally advisory, rename it and stop returning success.

### 5. `vulna update` / `rollback` mutate state before doing the work ✅
- **Where:** `cli/cmd/vulna/update.go:245`, `cli/cmd/vulna/update.go:278`
- **Problem:** `update` calls `RecordApplied(...)` before the compose commands, which
  are only printed. On fresh state it records an empty prior version, leaving no
  rollback point. `rollback` prints instructions and clears rollback metadata without
  redeploying.
- **Fix:** Either execute the compose pull/up and gate `RecordApplied` on a post-deploy
  health check, or don't record "applied" / clear rollback metadata until the
  operation actually succeeded.

---

## Tier 3 — Broken or unusable features

### 6. Full-spectrum workflow engine orchestrates nothing ✅ (built for real)
- **Where:** `dash/backend/app/api/v1/workflows.py`, `app/services/workflow.py`,
  `app/api/v1/probes.py` (`report_job_status` hook)
- **Problem:** `create_run` wrote a DB record and returned 201 — no `ScanJob`, no
  Scout dispatch, no completion callback. `/advance` was a human declaring stages
  done.
- **Fix (implemented):** When the run enters the `discovery` stage, the API now
  dispatches a real signed `ScanJob` (`create_scan_job`) for the site's enrolled
  probe over its approved scope and links it via `WorkflowRun.scan_job_id`. When the
  probe reports that job terminal (`report_job_status`), the workflow advances its
  discovery/vulnerability/TLS stages (`complete_scanning` / `fail_scanning`). Manual
  advance of a job-backed scanning stage is refused (409). The non-scan stages
  (precheck, the intrusive block behind the approval gate — controlled pentest is a
  later phase — cleanup/verification/reporting) remain operator-advanced. Covered by
  new engine unit tests and API E2E tests (dispatch → probe completes → stages
  advance; scan failure → skips to tail).

### 7. Hosted clean-host installer is unusable ⚠️
- **Where:** `scripts/install.sh:15`, `cli/cmd/vulna/main.go:212`
- **Problem:** No embedded release public key — exits unless one is supplied manually.
  Even with a key, the downloaded CLI needs `docker-compose.yml` + overlay already
  present, which the bootstrap doesn't fetch.
- **Fix:** Embed the release signing key in the hosted bootstrap and have it download
  the deployment bundle (compose files + overlay), not just the binary. Reproduce
  against the live installer before/after.

---

## Tier 4 — Hardening (real but lower urgency)

### 8. Webhook SSRF via DNS rebinding ✅
- **Where:** `dash/backend/app/services/notifications.py:190`,
  `dash/backend/app/services/notify.py:337`
- **Problem:** `validate_destination(url)` resolves and checks the hostname, then
  `httpx.Client().post(url)` re-resolves it independently — validation and connection
  aren't pinned to the same IP, so a rebinding name can pass the check and connect
  internally.
- **Fix:** Resolve once, validate the resolved IP, and connect to that pinned IP
  (custom transport/resolver, or pass the IP with a Host header). Re-check on redirects.

### 9. Evidence stored unencrypted despite the threat model ✅ (built for real)
- **Where:** `dash/backend/app/services/evidence_crypto.py` (new),
  `app/services/ingest.py`, `app/models/scan_artifact.py`, `app/core/config.py`,
  migration `e5f6a7b8c9d0_evidence_encryption.py`
- **Problem:** Scanner output was written to a plaintext TEXT column;
  `VULNA_MASTER_KEY` was documented in `.env.example` but unused by the backend.
- **Fix (implemented):** Added a `master_key` setting (`VULNA_MASTER_KEY`). Raw
  scanner output is now encrypted at rest with a Fernet key derived from it
  (HKDF-SHA256) before it touches the DB, and a new `scan_artifacts.encrypted`
  column records the form. Without a key (dev), the previous plaintext behavior is
  preserved. `sha256`/`size_bytes` still describe the plaintext for integrity and
  retention. Covered by round-trip + wrong-key/missing-key tests.

### 10. Report expiration never enforced ✅
- **Where:** `dash/backend/app/api/v1/reports.py:129`
- **Problem:** Download checks status + `storage_path` only, not `expires_at`; expired
  reports stay downloadable until a separate retention job deletes them.
- **Fix:** Reject download when `expires_at` has passed (409/410).

### 11. Relay deny-list uses containment, not overlap ✅
- **Where:** `dash/backend/app/services/relay.py` (`egress_decision` / `_within`)
- **Problem:** A denied host is reachable by targeting a containing CIDR — the deny
  check only fires on full containment, not overlap.
- **Fix:** Trigger the deny check on any overlap with a denied range. Low urgency:
  `egress_decision` isn't wired to real traffic yet.

### 12. Relay feature flag not fail-closed ✅
- **Where:** `dash/backend/app/api/v1/relays.py`, `dash/backend/app/services/relay.py`
- **Problem:** Disabling relay mode doesn't stop already-enrolled relays; only
  `enrollment_command` and `set_scope` check `_require_enabled`. The module docstring
  overstates enforcement.
- **Fix:** Gate the runtime endpoints/egress on the flag, or correct the docstring.
  Low urgency for the same reason as #11.

---

## Tier 5 — found during live Hetzner-VM testing

### 13. Single-host access by raw IP is broken (Caddy strict-SNI + Scout mTLS on :443) ✅ (proper fix)
- **Where:** `deploy/single-host/Caddyfile`, `docker-compose.single-host.yml`,
  `deploy/single-host/local-scout-entrypoint.sh`, `cli/internal/config/config.go`
- **Problem:** The Scout mTLS shared the `:443` the browser uses, so Caddy enforced
  strict SNI on it; a browser/curl connecting by raw IP sends no SNI and the
  handshake failed.
- **Fix (b, the proper one — implemented):** Moved **all** probe mTLS to a dedicated
  `:8443` listener; the browser UI stays on `:443` with no `client_auth`, so a
  no-SNI (raw-IP) handshake is accepted. The co-located Scout and any remote Scouts
  use `https://<host>:8443`. Verified with `caddy validate` (strict-SNI now only on
  the `:8443` server) and `docker compose config`. Because LAN-by-IP works again,
  the installer IP rejection was relaxed to `public` mode only (Let's Encrypt still
  needs a real domain).

### 14. nuclei ships with 0 templates → out-of-the-box scans find nothing ✅
- **Where:** `deploy/single-host/local-scout.Dockerfile`,
  `scout/internal/scanners/nuclei/nuclei.go`
- **Problem:** The scanner image installed the nuclei binary but no templates, and
  update checks are disabled by policy, so the vulnerability stage matched nothing.
- **Fix:** Bundle a pinned `nuclei-templates` release into the image (13,320
  templates, verified via a `docker build`) and point the adapter at it with
  `-templates` via `VULNA_NUCLEI_TEMPLATES`. This restores the core value prop.

### 15. `VULNA_ADMIN_EMAIL` seeded without validation → admin can't log in ✅
- **Where:** `dash/backend/app/services/bootstrap.py`, `app/cli.py`
- **Problem:** The seed accepted any string, but login validates with pydantic
  `EmailStr`, which rejects reserved domains (`.test`, `.local`, `.example`) — so a
  seeded admin using such an address could never authenticate.
- **Fix:** Validate the admin email at seed time with the same `EmailStr` validator
  and fail fast with a clear, actionable error (`BootstrapError`).

---

## Tier 6 — second Codex pass + live Hetzner re-validation

Seven follow-up findings (Codex, second pass) were fixed on the branch, then the
whole stack was re-deployed to a real Hetzner VM to validate them on live infra.

### Second-pass fixes (committed)
- **#1** — `update`/`rollback` now rewrite `VULNA_VERSION` in the deployment `.env`
  (`SetEnvVersion`) before `docker compose pull`, so an update actually installs the
  requested image tag; a `release-images` workflow publishes the versioned
  `vulna-api`/`vulna-frontend` images the compose file pins.
- **#2** — a pentest session can now execute (policy allows `controlled_pentest` mode
  + `metasploit` plugin when `probe.pentest_enabled`), and a session that was rejected
  by the probe or never ran a stage is marked `TERMINATED`, not falsely `CLEANED`.
- **#3** — the scout workflow records `StagesFailed`/`StagesSkipped`/`Errors`; the
  agent reports `failed` when a stage errored or none ran, so a scanner crash no
  longer surfaces as a successful job.
- **#4** — network-targeted jobs attribute to the *network's* site, not the scout's
  home site (`_job_site_id`), so a cross-site scout is reported correctly.
- **#5** — the installer generates `VULNA_MASTER_KEY`, so evidence encryption is on
  by default rather than silently falling back to plaintext.
- **#6** — backup content classes are each verified against their own distinct
  location, so a partial archive can't be certified `USABLE`.
- **#7** — a partial unique index (`uq_scan_jobs_active_network`) makes "one active
  job per network" a DB invariant, closing the check-then-insert race behind the
  app-level guard.

### 16. Base `deploy/Caddyfile` crash-loops when `VULNA_DOMAIN` is blank ✅
- **Where:** `docker-compose.yml` (caddy service env)
- **Problem:** Found on the live VM. The base Caddyfile's site address is
  `{$VULNA_DOMAIN:localhost}`, whose `:localhost` default only applies when the var
  is **unset**. Compose interpolation (`${VULNA_DOMAIN:-}`) always *sets* it — to `""`
  when blank — defeating the default and producing a keyless (invalid) Caddy block:
  `server block without any key is global configuration, and if used, it must be
  first`. Caddy crash-loops, so the documented "HTTP-only local lab: leave
  VULNA_DOMAIN blank" mode (compose header) never comes up.
- **Fix:** Resolve the lab default in Compose instead: `VULNA_DOMAIN:
  ${VULNA_DOMAIN:-localhost}`. Verified live — with the fix caddy comes up healthy and
  proxies `/health`. (The single-host profile was already immune: its Caddyfile uses
  explicit `:443`/`:8443` listeners — fix #13 — so an empty domain yields a valid
  `:443` address; that path is unaffected and still publishes 80/443/8443.)

### Live re-validation results (Hetzner, single private network, cross-site scout)
- Full stack (`postgres`/`redis`/`api`/`frontend`/`caddy`) deploys and reports
  healthy from a clean `docker compose up --build`; all migrations apply (head
  `a3b4c5d6e7f8`, evidence-encryption ancestor included).
- **#4 confirmed:** a Houston scout bound to a Salisbury network produced a job with
  `site_id` = Salisbury (the network's site), assigned to the Houston scout.
- **#7 confirmed:** re-running the schedule while a job was active returned
  `409 "the network is already under test"`, and a raw duplicate active-job insert
  was rejected by `uq_scan_jobs_active_network` (uppercase-enum predicate matches the
  stored status names). Exactly one active job remained.
- **#5 confirmed:** `VULNA_MASTER_KEY` present; evidence-encryption migration applied.
- Hetzner resources torn down after the run (0 servers/volumes/IPs billing).

---

## Tier 7 — third Codex pass (1 P0, 6 P1, 2 P2)

### P0 — Pentest options bypass the authorized target scope ✅
- **Where:** `scout/.../metasploit/console.go`, `services/pentest_policy.py`,
  `pentest/policy.go`, `PentestPage.tsx`
- **Problem:** the scout set the validated `RHOSTS`, then applied free-form user
  options AFTER it, so `{"RHOSTS":"8.8.8.8"}` overrode the signed, in-scope target;
  the approval UI showed only the module, so the override was invisible.
- **Fix:** `RHOSTS`/`RHOST`/`PAYLOAD` are now reserved — rejected as options for
  every module on the **server** (`validate_module_allowed`), mirrored on the
  **scout** (`ValidateModule`), and re-checked at the edge in `buildResourceScript`.
  The session now pins the resolved `target` at request time (new column) and
  dispatch runs that exact target; the approval UI shows target, payload, options,
  and RoE so the approver sees what they authorize.

### P1 — Restore could proceed without its safety backup ✅
- `runBackup` used a cwd-relative script path and silently "skipped" (returning
  success) when absent, so a destructive restore continued unprotected; it also set
  `VULNA_BACKUP_DIR` while the script reads its dir from `$1`. Now it resolves the
  script under the deployment dir (or cwd), **fails closed** if missing, and passes
  the output dir positionally.

### P1 — Backups claimed configuration they did not contain ✅
- `backup.sh` copied only `VULNA_DATA`, never the deployment `.env` (DB password +
  evidence master key), yet the classifier treated any `data/` file as proof of both
  `config` and `scout_state`. Now `backup.sh` archives the `.env` under `config/`,
  `restore.sh` restores it, and the classifier requires each class's OWN path
  (`config/` for config; `data/scout*/` for scout_state) — so a `.env`-less backup is
  correctly UNUSABLE.

### P1 — Published image tags didn't match update/install versions ✅
- The image workflow published `v1.0.0` while compose/CLI use `1.0.0`. The workflow
  now strips the leading `v`; the CLI build injects `buildinfo.Version` via ldflags
  on a tag, and its default is now `dev` (not a real-looking `0.1.0` that would pull
  a nonexistent tag).

### P1 — Failed updates left `.env` at the failed version ✅
- `update` rewrote `VULNA_VERSION` before pulling; a failed pull/up left it pinned to
  a release that never came up. It now captures the prior version and reverts it on
  any pull/up failure.

### P1 — Metasploit cleanup failures were reported as cleaned ✅
- Teardown errors were discarded and every finished exploit job was marked `CLEANED`.
  The scout now **verifies** teardown (`sessions -l` shows none / all Worker stops
  succeeded) and reports `cleanup_verified`; the backend marks `CLEANED` only when
  verified, else `CLEANUP_PENDING` for manual follow-up.

### P1 — Pentest image ran an unpinned remote script as root ✅
- The Dockerfile fetched the Metasploit installer from `master` and ran it as root.
  It is now pinned to an immutable commit and its SHA-256 is verified before it runs.

### P2 — Most Rules-of-Engagement fields were decorative ✅
- `allowed_hours` (permitted days/hours, tz-aware) is now enforced at dispatch — a
  session firing outside the window is not dispatched (`within_allowed_hours`).

### P2 — The network lock turned races into unhandled 500s ✅
- `create_scan_job` now inserts inside a SAVEPOINT and converts the unique-index
  `IntegrityError` into a graceful `JobValidationError`, so a lost race can't 500 or
  roll back an entire scheduler sweep.

All suites green: backend (mypy/ruff/pytest + release gate), scout & CLI
(gofmt/vet/test), frontend (build/lint/test), backup smoke + shellcheck, migrations
up/down, `docker build --check` on the pentest image.

---

## #6 expansion — Networks, staged jobs, timeout (Phases 1–3)

Follow-on work turning the workflow orchestration into a real product capability.

### Phase 1 — Networks + Scout association ✅
- **New:** `Network` (named range group under a site), `network_scouts` M2M binding
  (with a primary), and `NetworkScope.network_id`. Full `/api/v1/networks` CRUD +
  range/scout management, and a frontend **Networks** page.
- `build_policy_document` now unions the legacy site-wide/pinned scopes with the
  ranges of any network a scout is bound to — **cross-site by design**, so a
  Houston scout can scan a Salisbury network across an SD-WAN/VPN.

### Phase 2 — Per-stage jobs + network-targeted dispatch ✅
- `create_scan_job` takes a `stages` subset; the workflow dispatches **one job per
  scanning stage** (discovery → vulnerability → TLS) and advances each on its
  job's real result (`services/workflow_dispatch`).
- A workflow can target a `network_id`; dispatch routes to a bound, enrolled scout
  (primary preferred) over the network's ranges, else falls back to the site's
  first probe / whole scope.

### Phase 3 — Timeout reaper ✅
- `services/reaper.reap_stale_jobs` expires active jobs past their deadline and
  fails the linked workflow's scanning stage so a dead/stalled scout can't hang a
  run. Runs opportunistically on probe heartbeats (org-scoped) and via an admin
  `POST /api/v1/jobs/reap`.

Backend 384 tests + release gate green; frontend builds + 22 tests; Go builds.
Controlled pentest (the intrusive stages) remains Phase 4 — next.

---

## Suggested sequencing

1. **#1 and #2** — highest risk; they let unauthorized or oversized scans actually run.
2. **#3, #4, #5** — recovery/upgrade paths that report success without acting.
3. **#6, #7** — feature integrity.
4. **#8–#12** — hardening.

#1 (Scout fail-closed) is self-contained and the best starting point.
