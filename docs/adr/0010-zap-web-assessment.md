# ADR 0010: ZAP Web Assessment

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 9 (ZAP web assessment)

## Context

Network discovery and Nuclei/TLS checks do not exercise a web application's own
logic. Phase 9 adds OWASP ZAP so Vulna can crawl and analyze web apps, while
keeping the strong safety properties the platform requires: stay in scope, do no
active attacking unless explicitly approved, and never accept free-form scanner
arguments (build plan Section 12.5).

## Decisions

### 1. Drive ZAP through a generated Automation Framework plan

The probe generates a ZAP Automation Framework plan and runs
`zap.sh -cmd -autorun <plan>` — allowlisted arguments only, like every other
adapter. The plan is the single place scope and profile are expressed, so the
safety behavior is a property of one generated document rather than scattered
flags. The plan is emitted as JSON (which is valid YAML, so the framework accepts
it), keeping the probe dependency-free and stdlib-only.

### 2. Scope is enforced by the context's include paths, and validated twice

The plan defines one ZAP context whose `includePaths` are regexes bound to the
in-scope hosts (with IP dots escaped, so only the exact host matches). ZAP only
crawls and attacks in-context URLs, so a redirect to an out-of-scope host is not
followed — the redirect-restriction requirement falls out of the context scope
rather than a separate setting. Start URLs are validated against the scope in two
places: the backend rejects an out-of-scope start URL at job creation (defense in
depth), and the probe re-validates every IP-literal start-URL host against the
signed job's approved targets before ZAP is ever launched.

### 3. Profiles: passive by default, active is opt-in and allowlisted

The passive profile runs `spider` + `passiveScan-wait` only — no active-scan job
is emitted, so it performs no attacks. The limited-active profile adds an
`activeScan` whose `policyDefinition` sets `defaultThreshold: off` and enables
only a small allowlist of conservative injection/traversal rules; intrusive and
DoS rules are never enabled. This mirrors the Nuclei safe-template policy: the
adapter owns the allowlist, so a job cannot widen it.

### 4. Active assessment requires approval via role, not a free flag

An active web assessment is intrusive, so the build plan requires approval. Job
creation admits administrators, operators, and pentest approvers; the handler
then enforces that only an administrator or pentest approver may request the
limited-active profile (an operator is limited to regular scans and passive web
assessments). This satisfies "active profile requires approval" with the existing
RBAC, and dovetails with the fuller approval workflow arriving in Phase 11.

### 5. ZAP output is normalized like every other scanner

A defensive `traditional-json` parser maps each ZAP alert to the shared
`ParsedFinding` (type `web_application_issue`, severity from ZAP's riskcode, HTML
stripped from text), so ZAP findings flow through the same dedup, lifecycle, and
change-event machinery as Nmap/Nuclei/testssl findings. The upload endpoint routes
`scanner=zap` to store-artifact + parse + ingest.

## Consequences

- Web findings join the unified findings database and reports with no special
  casing downstream.
- The passive/active split and the approval gate keep the default safe and make
  intrusive scanning a deliberate, authorized action.
- Adding ZAP required no change to the scanner interface: the web worker locates
  its own stage config within the signed job workflow.

## Alternatives considered

- **Talking to a long-running ZAP daemon over its REST API:** rejected for now;
  the Automation Framework is self-contained, reproducible from the generated
  plan, and needs no persistent service or API key on the probe.
- **Letting the job specify raw ZAP options / an arbitrary active-rule set:**
  rejected; free-form scanner configuration is exactly the injection/abuse risk
  the allowlist model exists to prevent. The active-rule allowlist lives in the
  adapter.
- **A global maximum-redirects setting instead of context scope:** rejected;
  binding scope through the context is stronger (it governs the whole
  crawl/attack surface, not just redirect hops) and is what ZAP is designed for.
