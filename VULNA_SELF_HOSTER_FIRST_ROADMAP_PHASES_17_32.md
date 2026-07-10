# Vulna - Self-Hoster-First Roadmap After Phase 16

> **Planning assumption:** Phases 0 through 16 in `VULNA_CODEX_BUILD_PLAN.md` are complete, tested, documented, and released.
>
> **Primary product goal:** Make Vulna the security-assessment platform that a homelabber, small business, consultant, or technically curious self-hoster can install, understand, operate, update, back up, and recover without needing a security team or a Kubernetes platform.
>
> **Authorized use only:** Vulna must assess only systems and networks the operator owns or has explicit permission to test.

---

## 1. Product Direction

Vulna should not win by having the longest feature list. It should win by making a difficult category of software approachable without weakening its safety model.

The desired experience is:

```text
1. Start with one supported command or a small downloaded installer.
2. Pass an automatic environment and safety preflight.
3. Open one local URL.
4. Create the administrator account.
5. Review and explicitly approve the suggested local network scope.
6. Choose a plain-language scan preset.
7. Run a first safe assessment.
8. Receive understandable, prioritized results and concrete next steps.
9. Update, back up, diagnose, and restore Vulna from the UI or one CLI.
10. Add remote VulnaScouts later only when the user actually needs them.
```

The default installation must require:

- No vendor account.
- No mandatory cloud service.
- No Kubernetes cluster.
- No external PostgreSQL, Redis, object storage, identity provider, or observability stack.
- No manual certificate generation.
- No hand-written YAML for the normal path.
- No separate VulnaScout host for a single-site deployment.
- No arbitrary scanner flags.
- No enabling intrusive assessment features to obtain useful results.

Advanced deployments may still use distributed VulnaScouts, VulnaRelay, external services, custom certificates, API automation, and scanner plugins. Those capabilities must not make the simple path harder.

---

## 2. Product North Star and Measurable Targets

Use the following as release gates, not aspirational marketing claims.

### 2.1 Installation targets

On a clean, supported Linux host with a working container runtime and Internet connection:

- Installation to login page: no more than 10 minutes in the reference environment.
- Required interactive installation questions: no more than five.
- Manual file edits for the default deployment: zero.
- Required commands after downloading the installer: one.
- Default exposed application ports: only the documented web port or ports.
- Default deployment includes a usable local VulnaScout automatically.

### 2.2 First-value targets

After first login:

- Administrator bootstrap, site setup, local Scout confirmation, scope approval, and first job creation are one guided flow.
- A user can start a safe first assessment in no more than five minutes, excluding scan duration.
- Every preset explains expected duration, network impact, required resources, and which checks it includes.
- Missing scanner capabilities never produce a mysterious failure. Vulna either installs the supported capability, offers a clear action, or safely skips it with an explanation.

### 2.3 Day-two operation targets

The following tasks must be possible through both the web interface and a documented CLI:

- Check health.
- View the installed version.
- Update and roll back.
- Back up and verify the backup.
- Restore to a clean host.
- Rotate or recover required secrets and certificates.
- View disk usage and retention.
- Export a redacted diagnostic bundle.
- Stop all active scanning.

### 2.4 Usability rules

- Default screens use plain language first and security terminology second.
- Advanced controls stay available, but they are not shown in the first-run path unless required.
- Every error shown to a user includes what failed, whether data is safe, and the next action.
- Destructive actions show exactly what will be deleted and whether recovery is possible.
- Safety-sensitive defaults may not be weakened merely to reduce clicks.

---

## 3. Supported Deployment Profiles

Vulna should officially support three deployment profiles. The first is the product default.

### 3.1 Single-host deployment - default

Use one Linux server, mini PC, VM, or capable NAS-hosted VM to run:

- VulnaDash
- PostgreSQL
- Redis
- report worker
- scheduler and workers
- a local VulnaScout
- the standard safe scanner capability pack

The local VulnaScout remains a separate service and preserves signed policy, typed plugin inputs, cancellation, resource limits, and local target enforcement. It is automatically enrolled during installation so the user does not have to understand the distributed architecture on day one.

### 3.2 Distributed deployment - optional growth path

Use VulnaDash centrally and install one or more VulnaScouts at remote locations. This remains the recommended model for multiple sites, segmented networks, or assessments that should execute at the edge.

### 3.3 Relay deployment - specialized and opt-in

Use VulnaRelay only for deliberate thin-site deployments. Keep it out of the default setup wizard unless the operator selects an advanced deployment path.

---

## 4. Roadmap Order

| Release train | Phases | Outcome |
|---|---:|---|
| **A - Install and get value** | 17-21 | A non-expert can deploy Vulna and complete a useful first scan with safe defaults |
| **B - Own it confidently** | 22-28 | Daily use, networking, updates, backups, diagnostics, and low-resource operation are understandable and reliable |
| **C - Fit the self-hosting ecosystem** | 29-32 | Notifications, documentation, privacy, portability, packaging, and release quality are mature |

Recommended order:

```text
17 -> 18 -> 19 -> 20 -> 21 -> 22 -> 23 -> 24
                                      |           |
                                      +-> 25 -> 26
                                              |
                                              +-> 27 -> 28 -> 29 -> 30 -> 31 -> 32
```

Do not begin a later release train merely because its features are more interesting. Complete the measurable setup and recovery experience first.

---

## 5. Phase 17 - First-Class Single-Host Deployment

### Objective

Make a one-machine deployment the obvious, fully supported starting point while preserving VulnaScout's security boundaries.

### Deliver

- A production-oriented `single-host` Compose profile containing VulnaDash and an automatically enrolled local VulnaScout.
- Automatic creation of the initial organization, site, and local Scout record during first-run bootstrap.
- A narrowly privileged local Scout container or service with only the capabilities and writable paths required by scanners.
- No Docker socket mount in VulnaDash, the local Scout, or scanner services.
- Separate persistent volumes for database data, queue data, reports, evidence, Scout state, certificates, and configuration.
- A generated deployment identifier and internal one-time enrollment mechanism that is never reused or exposed in browser logs.
- A default standard capability pack containing Nmap, safe Nuclei checks, and TLS checks.
- Heavy or intrusive tools, including active ZAP profiles and Metasploit, disabled in the default profile.
- A clean path to convert the deployment from local-only to distributed without recreating assets, findings, or the organization.
- Health checks that distinguish application health, local Scout health, scanner capability health, and external-feed health.

### User experience

The user should see one initial site and one local Scout already connected. The interface may explain the architecture, but it must not force the user to create those objects manually before the first scan.

### Acceptance criteria

- A new single-host deployment reaches the login page without the user creating a site, enrollment token, or Scout configuration.
- The local Scout can run an authorized lab assessment end to end.
- The local Scout rejects an out-of-scope target even though it shares a host with VulnaDash.
- VulnaDash and its workers run without scanner network capabilities.
- The scanner service has no access to PostgreSQL credentials, application signing keys, report encryption keys, or the Docker socket.
- Removing and re-creating application containers does not lose identity, findings, reports, or local Scout state.
- A user can later add a remote Scout without changing the deployment model or database.

### Security constraints

- Automatic local enrollment must not bypass policy signing, job signing, certificate identity, job expiration, or scope checks.
- Do not use host-wide privileged mode for convenience.
- Any host networking required by local discovery must be isolated to the Scout/scanner boundary and clearly disclosed before installation.

---

## 6. Phase 18 - Safe Installer and Environment Preflight

### Objective

Provide one supported installation workflow that detects common problems before files are changed or services are started.

### Deliver

- A small `vulna` installation and administration CLI distributed as a signed release artifact.
- A convenience bootstrap script that downloads a pinned CLI release, verifies its checksum and signature, and then invokes the CLI.
- A fully documented manual installation path for users who do not use a shell pipeline.
- Preflight checks for:
  - supported operating system and architecture
  - container runtime and Compose support
  - CPU, memory, and free disk space
  - required kernel features and network capabilities
  - port conflicts
  - time synchronization
  - DNS and outbound access to selected intelligence/update sources
  - filesystem permissions
  - incompatible existing Vulna installation
- Automatic generation of cryptographically strong secrets and a restrictive configuration directory.
- Interactive choices limited to installation directory, access mode, hostname or URL, data directory, and optional update checks.
- An idempotent installer that can be rerun to repair generated deployment files without overwriting data or user-managed settings.
- A `--dry-run` mode that reports intended changes.
- A `--non-interactive` mode using a versioned answer file for automation.
- A clean uninstall command that never deletes persistent data unless an explicit separate purge flag is provided.

### Acceptance criteria

- A supported clean host installs with one documented command and no manual file edits.
- The bootstrap refuses an artifact with an invalid signature or checksum.
- Preflight detects insufficient disk, occupied ports, clock skew, missing container support, and unsupported architecture before deployment changes occur.
- Generated secret files are readable only by the intended service account or administrator.
- Rerunning the installer does not rotate secrets, overwrite custom settings, or destroy volumes unexpectedly.
- The dry run accurately lists files, directories, services, ports, and capabilities that would be created.
- Uninstall leaves data intact; purge requires an explicit confirmation naming the data path.

### Security constraints

- Do not instruct users to execute unverified remote shell content.
- Do not print generated secrets to normal logs.
- The installer must never weaken host firewall, mandatory access control, or file permissions silently.

---

## 7. Phase 19 - Guided First Run and First Safe Assessment

### Objective

Turn first login into a short, understandable route to a useful assessment.

### Deliver

- A resumable first-run wizard covering:
  1. administrator creation
  2. recovery-code download or confirmation
  3. deployment health
  4. site name
  5. local Scout status
  6. detected local network candidates
  7. explicit scope approval
  8. scan-preset selection
  9. first assessment launch
  10. result walkthrough
- Local interface and route detection used only to suggest private network ranges. Suggested ranges must never be authorized automatically.
- Clear warnings and an additional confirmation for public IP space, large CIDRs, or unusually broad target counts.
- An optional isolated demo target so a user can test the complete workflow without scanning their real network.
- A pre-scan summary showing targets, host estimate, checks, expected resource use, rough duration class, and data-retention behavior.
- Live progress written for non-specialists, with an expandable technical view.
- A first-results walkthrough explaining assets, services, findings, confidence, priority, remediation, and verification.
- A persistent setup checklist that disappears when complete but remains available from Help.

### Acceptance criteria

- A new user can launch a safe assessment without visiting the advanced administration pages.
- No detected subnet is saved or scanned until the user explicitly approves it.
- The wizard rejects `0.0.0.0/0`, `::/0`, malformed ranges, and targets outside local policy.
- The demo target is isolated, disabled by default after setup, and cannot be exposed publicly by the standard configuration.
- Refreshing or closing the browser does not lose wizard progress or create duplicate scans.
- Technical errors remain accessible, but the primary view explains the failure and next step in plain language.

### Security constraints

- Network detection is advisory only.
- The wizard may not enable controlled pentesting, public-address scanning, unrestricted templates, or credentials by default.
- Recovery material must be generated and stored according to the authentication security model.

---

## 8. Phase 20 - Frictionless Remote VulnaScout Deployment

### Objective

Make adding a second site nearly as simple as adding the local Scout while retaining outbound-only communication and local enforcement.

### Deliver

- A per-site **Add VulnaScout** wizard that generates a short-lived, single-use installation command.
- Signed packages for supported `amd64` and `arm64` systems.
- Supported installation paths for:
  - Debian and Ubuntu package
  - containerized Scout
  - cloud-init
  - prebuilt VM image
  - Raspberry Pi-class 64-bit image or image-builder recipe
- Architecture and operating-system detection in the installer.
- Automatic server-CA installation and URL validation.
- Enrollment progress visible in both the installer and VulnaDash.
- A connection test covering DNS, TLS, time, enrollment, heartbeat, policy delivery, scanner health, and result upload.
- A site-network setup step that suggests but never automatically approves local ranges.
- Clear remediation for proxy, custom-CA, DNS, clock, MTU, and outbound-firewall failures.
- A local emergency-stop command that works when VulnaDash is unreachable.
- Safe reset and re-enrollment workflows that preserve useful diagnostics and revoke old identity.

### Acceptance criteria

- A supported remote host installs and enrolls from one copied command.
- The token expires, is single-use, is stored hashed centrally, and is not present in persistent process listings after use.
- No inbound management port is required on the remote site.
- A failed enrollment gives an actionable reason without leaking token or key material.
- The Scout's private key never leaves the Scout.
- Revoking or resetting a Scout prevents the old identity from polling or uploading.
- A remote Scout can continue an accepted job and upload later after a temporary WAN outage, according to policy.

### Security constraints

- Convenience commands must verify release signatures before installing.
- Enrollment may not imply automatic target authorization.
- The local kill switch and local signed policy remain authoritative even when the central service is compromised or unavailable.

---

## 9. Phase 21 - Opinionated Scan Presets and Automatic Tuning

### Objective

Replace scanner-centric configuration with a small set of safe, understandable outcomes.

### Deliver

Built-in presets with versioned definitions:

| Preset | Intended use | Default behavior |
|---|---|---|
| **Quick Check** | Frequent lightweight visibility | discovery, common ports, basic service detection |
| **Standard Security Check** | Default homelab and small-business scan | discovery, broader service detection, safe vulnerability checks, TLS checks |
| **Fragile / IoT Safe** | Printers, cameras, appliances, embedded devices | conservative discovery and connection rates, no active web attack |
| **Web and TLS Check** | Known websites and internal applications | scoped passive web checks and TLS analysis |
| **Deep Safe Check** | Planned maintenance window | broader safe checks, longer duration, still no exploitation |
| **Custom** | Expert use | explicit advanced controls with validation |

Additional deliverables:

- A capability manager that reports installed, missing, unhealthy, unsupported, and update-available scanner components.
- Hardware-aware concurrency and rate recommendations based on CPU, memory, storage, architecture, and recent job behavior.
- Automatic downgrade or stage skipping when a capability is unavailable, only when the user has approved that behavior.
- A preview showing exactly which stages and plugins the preset will use.
- Preset version pinning so historical reports remain reproducible.
- A simple custom-preset editor that exposes validated choices rather than raw command strings.
- A **Why was this skipped?** explanation for every omitted stage.
- Scan estimates expressed as ranges and workload classes rather than false precision.

### Acceptance criteria

- The standard preset works on the documented reference deployment without editing plugin arguments.
- Fragile mode enforces lower rates locally and blocks stages classified as active or intrusive.
- A missing scanner produces a clear preflight result before the job begins.
- Updating a built-in preset does not silently change an existing schedule; the user reviews and adopts the new version.
- Custom profiles cannot introduce arbitrary executable paths, shell fragments, unrestricted Nmap scripts, or unreviewed Nuclei template sets.
- Resource tuning never exceeds the hard limits in local Scout policy.

### Security constraints

- Presets are convenience layers over the same signed job and local-policy controls.
- Intrusive checks remain disabled by default and cannot be hidden inside a friendly preset name.
- Scanner and template updates must retain classifications and signature verification.

---

## 10. Phase 22 - Everyday UX for Homelabs and Small Teams

### Objective

Make the product useful to people who do not spend their day reading CVEs, scanner output, or enterprise risk dashboards.

### Deliver

- A home dashboard centered on:
  - what changed
  - what needs attention now
  - which systems were not assessed
  - whether Vulna itself is healthy
  - the next recommended action
- Plain-language finding summaries with expandable technical detail.
- A consistent finding layout:
  1. what Vulna observed
  2. why it matters
  3. how confident Vulna is
  4. affected system and service
  5. practical remediation steps
  6. how to verify the fix
  7. references and raw evidence
- A simple priority model that distinguishes **fix now**, **plan a fix**, **watch**, and **informational**, while retaining formal severity and CVSS data.
- One-click **Mark fixed and verify**, **Accept temporarily**, **False positive**, and **Assign** workflows with guardrails.
- A change-focused view for new devices, newly opened ports, new vulnerabilities, resolved issues, and reopened issues.
- Human-readable scan and stage failures.
- Responsive layouts for tablets and phones, particularly for dashboard, scan status, finding review, and emergency stop.
- Accessibility checks for keyboard navigation, focus order, labels, contrast, and screen-reader landmarks.
- A global command/search interface for assets, findings, scans, sites, reports, and settings.

### Acceptance criteria

- A user can identify the highest-priority unresolved issue and its suggested action from the home dashboard.
- Every finding shows detection confidence and the evidence source without requiring the user to inspect raw output.
- Marking a finding fixed does not close it until the configured verification policy succeeds.
- Risk acceptance always has an owner, reason, and expiration by default.
- Technical data remains available and exports remain stable.
- Core workflows pass automated accessibility tests and a documented keyboard-only review.

### Security constraints

- Simplified labels must not overstate uncertain matches as confirmed vulnerabilities.
- Scanner evidence displayed in the browser must remain sanitized.
- Bulk actions must enforce per-object authorization and produce audit events.

---

## 11. Phase 23 - Networking, URL, TLS, and Reverse-Proxy Assistant

### Objective

Eliminate one of the most common self-hosting failure points: reaching the application securely from the intended network.

### Deliver

Supported access modes:

1. Local host only.
2. Private LAN with an IP address or local hostname.
3. Public or private DNS name with automated TLS through the bundled reverse proxy.
4. Existing reverse proxy with documented trusted-proxy configuration.
5. Manually supplied certificate and key.

Additional deliverables:

- An installer and UI assistant that validates hostname, DNS, listening ports, certificate chain, expiry, callback URL, proxy headers, and browser reachability.
- Clear separation between application access TLS and Scout mutual TLS.
- A safe URL-change workflow that updates allowed origins, callbacks, generated links, and Scout server configuration without breaking existing enrollment.
- Strict trusted-proxy configuration with no blanket trust of forwarding headers.
- Detection and explanation for NAT loopback, split DNS, mixed HTTP/HTTPS content, incorrect system time, and certificate-name mismatch.
- A generated reverse-proxy snippet for advanced users.
- A **Test from this browser** and **Test from a Scout** action.
- No default exposure of PostgreSQL, Redis, metrics, internal worker ports, or scanner services.

### Acceptance criteria

- Each supported access mode has an automated installation test and a documented recovery path.
- A URL change either completes atomically or leaves the prior URL functional with rollback instructions.
- Invalid proxy headers cannot spoof the source address or secure-connection state from an untrusted peer.
- Certificate failures display the failing hostname, chain status, and corrective action.
- Scout mutual-TLS identity remains valid when the browser-facing certificate changes.

### Security constraints

- Do not disable certificate validation as a troubleshooting shortcut.
- Private keys are never displayed in the UI or written to diagnostics.
- Public access mode must warn about authentication, updates, backups, and rate limiting before activation.

---

## 12. Phase 24 - Boring, Safe Updates and Rollback

### Objective

Make keeping Vulna current less risky than leaving it outdated.

### Deliver

- `vulna update check`, `vulna update`, `vulna update status`, and `vulna rollback` commands.
- A web update center showing:
  - current version
  - available version
  - release channel
  - security relevance
  - compatibility notes
  - database migration impact
  - Scout compatibility
  - scanner and template changes
- Signed release manifests and checksum verification for all application, Scout, and plugin artifacts.
- Pre-update checks for active jobs, free disk, backup status, database health, release compatibility, and local modifications.
- An automatic pre-update backup unless the operator explicitly uses a documented override.
- Versioned database migration preflight and post-migration validation.
- Health-based rollback when the new version cannot reach a known-good state.
- Explicit separation of:
  - Vulna application updates
  - VulnaScout updates
  - scanner binary updates
  - scanner-template updates
  - intelligence-feed refreshes
- Stable, candidate, and development channels; stable is the default.
- Optional scheduled update checks. Automatic installation remains opt-in.

### Acceptance criteria

- A supported update completes without losing configuration, identity, scopes, schedules, findings, evidence metadata, reports, or audit history.
- An interrupted update either resumes safely or restores the prior known-good application version.
- No update begins while an incompatible active assessment is running.
- The operator can review release notes and migration impact before installation.
- Rollback behavior is tested for both application-only and schema-changing releases.
- Unsigned, altered, incompatible, or expired release metadata is rejected.

### Security constraints

- No forced remote update path.
- The update mechanism must not become an arbitrary package-execution channel.
- Rollback must not silently restore known-vulnerable secrets, certificates, or incompatible database state.

---

## 13. Phase 25 - Backups, Restore, and Recovery That Users Will Actually Test

### Objective

Make data ownership real by providing an understandable, verifiable recovery process.

### Deliver

- `vulna backup create`, `list`, `verify`, `restore`, and `prune` commands.
- A backup center in VulnaDash with schedule, destination, age, size, verification status, and retention.
- A versioned backup manifest covering:
  - PostgreSQL data
  - generated configuration
  - certificate authority and required key material
  - Scout identity metadata
  - reports and evidence, optionally by retention class
  - branding and templates
  - plugin and preset metadata
- Encrypted backup bundles with a user-controlled recovery secret or external key reference.
- Local filesystem and generic S3-compatible destinations, while local remains the default.
- Automatic backup verification and periodic test-restore workflow.
- A clean-host restore wizard that validates version compatibility and explains which URLs, certificates, or Scout settings may need repair.
- A printable recovery sheet containing non-secret identifiers, backup location, key-custody instructions, and restore commands.
- A prominent warning when no recent verified backup exists.

### Acceptance criteria

- A verified backup restores a clean supported host to a functionally equivalent deployment.
- A backup missing required files or failing a checksum is marked unusable before destructive restore steps.
- Restore never overwrites an existing deployment without an explicit confirmation and a safety backup.
- Losing the VulnaDash host does not require re-enrolling every Scout when the required CA and state were backed up.
- Backup logs and manifests do not contain passwords, tokens, private-key content, or sensitive evidence plaintext.
- The documentation states clearly what cannot be recovered if the backup encryption key or CA key is lost.

### Security constraints

- Encryption is required for backups containing credentials, CA material, evidence, or application secrets.
- Backup destinations receive minimum required permissions.
- Restore validates signatures, hashes, schema version, and organization ownership metadata.

---

## 14. Phase 26 - Vulna Doctor, Diagnostics, and Safe Self-Healing

### Objective

Help users solve common problems without searching logs across eight containers.

### Deliver

- A `vulna doctor` command with human-readable and JSON output.
- A System Health page that combines:
  - application and database health
  - queue health
  - worker and scheduler health
  - local and remote Scout health
  - scanner capability health
  - feed freshness
  - update state
  - backup state
  - certificate expiry
  - storage use
  - failed schedules and reports
- Tests for common faults such as:
  - full or read-only disk
  - incorrect ownership
  - port conflict
  - failed migration
  - unreachable database or queue
  - stale clock
  - broken DNS
  - invalid certificate chain
  - Scout policy mismatch
  - revoked or expiring Scout certificate
  - missing scanner binary
  - corrupted result chunk
  - stale feed
- Actionable remediation instructions linked to exact documentation sections.
- Safe repair actions for narrowly defined, reversible problems such as recreating a missing directory, restarting a failed stateless worker, retrying a feed, or rebuilding a generated proxy file.
- A redacted support-bundle generator with a manifest of included files and fields.
- A bundle preview and secret scanner before export.
- A local event timeline showing configuration changes, updates, restarts, failed jobs, and health transitions.

### Acceptance criteria

- A user can identify which component is failing without opening container logs.
- Every failed health check names the affected component, impact, data-safety status, and next step.
- Repair actions require confirmation and never alter scopes, permissions, users, credentials, or retention silently.
- The support bundle excludes passwords, tokens, private keys, authorization headers, raw credentials, unrestricted evidence, and full scanner output by default.
- Automated tests seed representative failures and verify the diagnosis.

### Security constraints

- Diagnostic endpoints and bundles follow normal authorization and are audited.
- Self-healing may restart or regenerate known derived state; it may not weaken security settings.
- Bundle redaction must be allowlist-based rather than relying only on pattern matching.

---

## 15. Phase 27 - Low-Resource, ARM64, Intermittent, and Offline-Friendly Operation

### Objective

Make Vulna practical on the hardware and connectivity common in homelabs and small sites.

### Deliver

- A documented **Lite** operating profile for modest hardware.
- Dynamic queue and concurrency limits based on measured CPU, memory, storage, and Scout capability.
- One-heavy-stage-at-a-time scheduling on constrained Scouts.
- Optional disabling of expensive components such as active ZAP, local full-text indexing, large report rendering, or high-frequency feed matching.
- Resource budgets and hard limits for every scanner stage.
- Graceful backpressure when result ingestion, report generation, or feed matching falls behind.
- Incremental and resumable downloads for releases, scanner assets, templates, and offline intelligence bundles.
- Durable Scout queues for intermittent WAN links, with visible backlog and storage estimates.
- Signed offline intelligence and update bundles that can be imported through CLI or UI.
- Storage-pressure behavior that stops accepting new heavy jobs before evidence or database corruption risk.
- Architecture-specific performance baselines for supported `amd64` and `arm64` tiers.
- A low-bandwidth heartbeat and upload mode.

### Acceptance criteria

- The Lite profile completes the documented safe assessment on the minimum reference hardware without out-of-memory termination.
- A disconnected Scout preserves accepted work and resumes upload without duplicate observations after connectivity returns.
- Hitting a resource limit stops or pauses work predictably and records a clear reason.
- Offline bundles are signature-verified and expose creation time, feed age, content versions, and import history.
- Low-resource mode never bypasses target checks, signatures, cancellation, or evidence integrity.
- The UI warns when a requested preset exceeds the Scout's recommended capability.

### Security constraints

- Resource pressure must fail closed for intrusive or scope-sensitive stages.
- Offline import is not an unsigned plugin or executable side-loading mechanism.
- Temporary scanner data follows the same permissions and cleanup requirements as normal mode.

---

## 16. Phase 28 - Unified Maintenance Center

### Objective

Give a self-hoster one place to understand whether Vulna needs attention.

### Deliver

- A Maintenance page covering:
  - application version and updates
  - Scout versions and compatibility
  - scanner and template versions
  - CVE/KEV/EPSS feed freshness
  - backup age and verification
  - certificate expiration
  - disk and artifact growth
  - retention and cleanup estimates
  - failed schedules
  - stuck jobs
  - report failures
  - plugin health
- Clear green, warning, and action-required states with textual explanations.
- Retention previews that show what will be deleted before a cleanup policy is saved.
- Storage budgets for raw output, evidence, reports, database, Scout queues, and backups.
- A safe cleanup workflow that preserves report snapshots, active findings, legal holds, required audit history, and backup dependencies.
- Certificate rotation workflows with preflight and recovery guidance.
- Maintenance reminders delivered through the configured notification channels.
- A monthly self-hosting health report summarizing updates, backups, feed age, storage, failed scans, and expiring certificates.

### Acceptance criteria

- An administrator can determine whether updates, backups, feeds, certificates, and storage are healthy from one page.
- Cleanup previews match actual deletion behavior and provide an auditable manifest.
- Vulna refuses to delete objects still referenced by retained reports, active jobs, legal holds, or configured recovery points.
- The maintenance center remains usable when optional monitoring services are not installed.
- Every warning links to a specific action or explanation rather than a generic log page.

### Security constraints

- Maintenance actions require appropriate roles and recent reauthentication for high-impact operations.
- Certificate and key rotation must be atomic or recoverable.
- Storage metrics must not expose sensitive asset or finding data in labels.

---

## 17. Phase 29 - Simple Notifications and Self-Hosted Integrations

### Objective

Notify users where they already work without requiring an enterprise ticketing deployment.

### Deliver

- A guided SMTP setup and test flow.
- Generic signed webhooks with reusable templates for self-hosted notification services and automation systems.
- Optional inbound links that deep-link to the relevant Vulna object but never contain secrets.
- Event choices designed for small operators:
  - Scout offline
  - scan completed or failed
  - new critical or high-priority finding
  - newly known-exploited CVE match
  - verification succeeded or failed
  - backup failed or stale
  - feed stale
  - certificate expiring
  - storage pressure
  - update available
- Immediate, hourly digest, daily digest, and weekly summary policies.
- Per-site quiet hours and deduplication.
- Delivery history, retry state, test action, and clear error messages.
- Secret rotation for webhook signing keys and SMTP credentials.
- A documented outbound-only integration model.

### Acceptance criteria

- A user can configure and test email or a webhook from the UI without editing environment files.
- Repeated identical events are grouped according to policy rather than flooding the recipient.
- Webhook payloads are versioned, signed, replay-resistant, and contain only selected fields.
- Notification failures never block scan completion or finding persistence.
- Quiet hours delay non-emergency notifications but do not discard them.
- Credentials are encrypted and never returned through the API after creation.

### Security constraints

- Do not send raw evidence, credentials, scanner output, or report files in default notifications.
- Prevent webhook destinations from being used as an unrestricted SSRF primitive.
- Test delivery uses the same destination validation and audit controls as real delivery.

---

## 18. Phase 30 - Documentation, Demo, and Guided Learning

### Objective

Treat documentation as part of the product rather than a repository appendix.

### Deliver

- A tested quick start that begins from a clean supported host and reaches a first safe scan.
- Task-oriented guides for:
  - single-host installation
  - adding a remote Scout
  - choosing a scan preset
  - understanding findings
  - fixing and verifying a finding
  - updates and rollback
  - backup and clean-host restore
  - changing the URL or certificate
  - moving data to a new host
  - troubleshooting common failures
  - uninstalling without losing data
- Separate **Simple path** and **Advanced path** sections.
- A terminology guide translating scanner and vulnerability language into plain English.
- Architecture diagrams for single-host, distributed Scout, and Relay deployments.
- Copy-paste commands that are tested in CI or documentation smoke tests.
- Contextual help links from errors, setup steps, findings, maintenance warnings, and update screens.
- A safe demo mode with sample assets and findings for evaluating the interface without scanning.
- An administrator checklist for exposing Vulna beyond a private LAN.
- A concise security and authorized-use guide displayed during setup.
- Migration notes for every release that changes user-visible behavior or configuration.

### Acceptance criteria

- The documented clean-install quick start passes in CI for each officially supported platform class.
- Every CLI command and configuration key in the guide is checked against the shipped version.
- A new user can distinguish single-host, Scout, and Relay use cases from one page.
- Troubleshooting guides begin with symptoms and observable checks, not internal component names.
- The demo mode cannot create real scan jobs or contact arbitrary targets.

### Security constraints

- Documentation must not recommend disabling TLS verification, running all services privileged, opening database ports, or using default secrets.
- Examples use private or reserved documentation addresses and clearly state authorization requirements.
- Screenshots and sample bundles contain no real user or infrastructure data.

---

## 19. Phase 31 - Privacy, Data Ownership, and Portability

### Objective

Make Vulna trustworthy for people who self-host specifically to retain control of their data.

### Deliver

- No mandatory account, license server, hosted control plane, or remote telemetry endpoint.
- Update checks configurable and disableable.
- Optional anonymous usage telemetry only after explicit opt-in, with a field-level preview and local audit record.
- A local-only product-analytics option for operators who want usage information without external transmission.
- Complete export for organizations, sites, Scouts, policies, assets, services, findings, reports, and remediation history using versioned schemas.
- Import and migration tooling that validates ownership, identifiers, hashes, schema versions, and conflicts.
- A **Move Vulna to another host** workflow combining backup, validation, restore, URL update, and post-move Scout checks.
- Configurable retention and deletion with previews and audit records.
- A privacy page showing what leaves the deployment: feed requests, update checks, SMTP, configured webhooks, and explicitly enabled integrations.
- Secret inventory and rotation status without revealing secret values.
- A machine-readable data map and threat-model update.

### Acceptance criteria

- Disabling update checks and telemetry does not disable core scanning, reporting, remediation, or local intelligence import.
- The outbound-connections page accurately reflects enabled features and destinations.
- An export can be validated independently with published schemas and checksums.
- Host migration preserves Scout trust where the backed-up CA and identity state are restored correctly.
- Deletion jobs honor report snapshots, legal holds, backup policy, and audit requirements.
- No opt-in is obtained through preselected controls or misleading wording.

### Security constraints

- Telemetry, when enabled, must never contain IP addresses, hostnames, usernames, findings, CVEs tied to assets, evidence, credentials, report contents, or stable cross-installation user identifiers.
- Imports are untrusted and must not overwrite trust roots, privileged users, or signing keys without an explicit recovery workflow.
- Data portability must not become a cross-organization authorization bypass.

---

## 20. Phase 32 - Release Qualification and Self-Hosting Ecosystem Packaging

### Objective

Make the easy path consistently work across a small, honest support matrix and make community packaging sustainable.

### Deliver

- A published support matrix for:
  - Linux distributions
  - container runtime and Compose versions
  - `amd64` and `arm64`
  - single-host resource tiers
  - supported browsers
  - VulnaDash/VulnaScout compatibility
  - scanner and template versions
- Automated clean-install, upgrade, rollback, backup, restore, and first-scan tests for every officially supported platform class.
- Reference deployment recipes for common self-hosting environments using VMs or containers where the security model is supportable.
- A packaging policy distinguishing:
  - officially maintained packages
  - community-maintained templates
  - experimental examples
- Release artifacts that include signatures, checksums, SBOMs, migration notes, compatibility notes, and recovery instructions.
- A stable release channel with a defined support period and a slower-moving maintenance channel once the project has capacity.
- A public issue template focused on install diagnostics and a privacy-safe support-bundle workflow.
- A release-blocking regression suite for setup, target enforcement, job signatures, cancellation, upgrades, restore, and data authorization.
- Small, standard, and constrained reference benchmarks.
- A contributor guide for preserving the simple path when adding advanced features.

### Acceptance criteria

- Every supported release passes a clean single-host install through first safe assessment.
- Upgrade and rollback are tested from every supported prior minor release.
- A release cannot be promoted when install, scope enforcement, signing, backup, restore, or authorization regression tests fail.
- Community templates cannot be presented as officially supported unless they meet the same upgrade and recovery tests.
- Support requests can include useful diagnostics without requiring users to publish secrets or raw evidence.
- The support matrix is intentionally limited to environments the project can test continuously.

### Security constraints

- Convenience packaging may not require privileged containers, host filesystem access, host networking, or Docker socket access beyond the documented Scout/scanner boundary.
- Third-party templates must not replace signed official images silently.
- Project release keys and artifact-signing workflows require documented rotation and compromise recovery.

---

## 21. Features to Defer Until There Is Clear Demand

The following may be valuable later, but they should not displace the self-hoster-first roadmap:

- SAML, SCIM, and complex identity-provider lifecycle management.
- MSP-grade multi-tenancy and customer portals.
- Kubernetes as a primary installation target.
- Multi-region high availability.
- Large-scale distributed object storage as a default dependency.
- Broad cloud-account inventory suites.
- Complex ticket-system integrations.
- An unrestricted plugin marketplace.
- AI-generated remediation or autonomous action.
- Exposure graphs that require a separate graph database.
- Large-enterprise policy engines.

These features may be developed as optional, isolated extensions after the default path meets the installation, first-value, update, backup, and recovery targets. They must not add required services or screens to the normal single-host installation.

---

## 22. Cross-Phase Simplicity Rules

Every phase after Phase 16 must follow these rules:

1. **One default path.** Documentation and UI must identify one recommended path rather than presenting every deployment choice equally.
2. **No required YAML for ordinary use.** Advanced configuration files remain supported, but common settings belong in the installer or UI.
3. **Safe defaults stay safe.** Public scanning, intrusive checks, credentials, active web attacks, and exploit validation remain off by default.
4. **Advanced is optional.** Enterprise, HA, external-service, and custom-plugin features may not become dependencies of the single-host profile.
5. **No hidden cloud dependency.** Core operation must continue without a vendor service.
6. **No mystery failures.** User-visible errors must name the problem, impact, and next step.
7. **Reversible changes.** Updates, migrations, URL changes, certificate rotations, cleanup, and restores require preflight and rollback or recovery guidance.
8. **Resource awareness.** Every heavy feature must declare CPU, memory, disk, network, and duration implications.
9. **Same security boundary.** Convenience may automate enrollment and configuration but may not bypass signatures, scopes, approvals, cancellation, or least privilege.
10. **Test the tutorial.** The exact default installation and first-scan guide is an end-to-end release test.
11. **Do not expose internals unnecessarily.** The normal user should not need to understand queues, workers, migrations, parsers, or scanner command syntax.
12. **Preserve escape hatches.** Experts retain APIs, versioned schemas, advanced configuration, and raw evidence without making those mandatory for everyone.

---

## 23. Definition of Done for the Self-Hoster-First Roadmap

This roadmap is complete when:

- A supported user can install Vulna on one host with one verified workflow and no manual configuration edits.
- A local VulnaScout is ready automatically, while still enforcing signed local scope policy.
- The user can safely approve a local scope and launch a first useful assessment through a guided flow.
- The default presets work without scanner-specific knowledge.
- Results explain what happened, why it matters, how confident Vulna is, what to do, and how to verify the fix.
- A remote Scout can be installed from one short-lived command when needed.
- URL, TLS, and reverse-proxy setup have guided tests and recovery paths.
- Updates perform preflight, backup, migration validation, health checks, and rollback.
- Backups can be verified and restored to a clean host.
- `vulna doctor` and the health page diagnose common failures without log archaeology.
- Vulna operates predictably on documented modest `amd64` and `arm64` hardware.
- Intermittent and offline sites have supported update, feed, queue, and upload workflows.
- Maintenance, storage, feeds, certificates, backups, and updates are visible in one place.
- Email and generic webhooks cover common notification needs without an enterprise integration stack.
- Documentation is tested as part of the release.
- Core operation requires no vendor account and no telemetry.
- Complete export, host migration, and deletion workflows protect data ownership.
- Every release passes clean install, first scan, update, rollback, backup, restore, scope enforcement, and authorization tests.

---

## 24. Recommended Immediate Product Decisions

Use these defaults unless testing shows a better self-hoster experience:

- Default deployment: single-host Docker Compose with an automatically enrolled local VulnaScout.
- Default access: private LAN or localhost, with an explicit guided choice to enable public DNS and TLS.
- Default scan: Standard Security Check.
- Default intrusive capability: disabled.
- Default public-address scanning: denied.
- Default heavy web scanning: disabled until explicitly selected.
- Default update behavior: check and notify; do not install automatically.
- Default backup destination: local encrypted bundle with a warning to copy it off-host.
- Default notification behavior: none until configured; provide an obvious test flow.
- Default telemetry: off.
- Default advanced settings: collapsed but discoverable.
- Default error presentation: plain-language summary plus expandable technical details.
- Default support policy: a small, continuously tested platform matrix rather than broad unverified claims.

---

## 25. First Codex Prompt for This Roadmap

Use this prompt after Phases 0 through 16 are complete:

```text
Read VULNA_CODEX_BUILD_PLAN.md completely.
Read VULNA_SELF_HOSTER_FIRST_ROADMAP_PHASES_17_32.md completely.

Implement Phase 17 only: First-Class Single-Host Deployment.
Do not begin Phase 18 or any enterprise expansion work.

Primary outcome:
A new user must be able to start VulnaDash and a local VulnaScout on one supported
Linux host without manually creating a site, enrollment token, or Scout record.
The local Scout must still enforce the same signed policy, job signature, target
scope, expiration, cancellation, typed-plugin, and resource-limit controls as a
remote Scout.

Required work:
- Add a production-oriented single-host deployment profile.
- Automatically bootstrap the initial organization, site, and local Scout through
  a secure one-time internal enrollment workflow.
- Keep scanner privileges isolated from VulnaDash and its workers.
- Do not mount the Docker socket.
- Do not run the whole stack privileged.
- Keep heavy and intrusive scanners disabled by default.
- Preserve persistent identity and data across container recreation.
- Add an end-to-end VulnaLab test for clean startup, local enrollment, an authorized
  safe assessment, result ingestion, and out-of-scope rejection.
- Document the security boundaries and how to add a remote Scout later.

Before coding:
1. Create an ADR for the single-host deployment and privilege boundaries.
2. Identify every secret, volume, network, Linux capability, and trust transition.
3. Define rollback and migration behavior for existing distributed installations.

After implementation:
1. Run linting, type checks, unit tests, integration tests, and the end-to-end test.
2. List every file created or changed.
3. Provide exact startup and verification commands.
4. Report resource use on the reference environment.
5. Document known limitations and unsupported host environments.
6. Stop. Do not implement Phase 18.
```

---

## 26. Final Product Principle

Vulna should expose sophisticated security capabilities through a simple operational model:

> **Install one box. Approve what it may assess. Run a safe check. Understand the result. Keep your data.**

A feature is not complete merely because it works in a development environment. For this audience, it is complete only when a person can discover it, configure it safely, recover from mistakes, update it, back it up, and understand when it fails.
