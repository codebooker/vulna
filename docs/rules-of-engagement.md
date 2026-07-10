# Rules of Engagement (RoE)

Rules of Engagement define the boundaries, approvals, and safety expectations for
an assessment. A completed RoE is **required** for Controlled Pentest and
Full-Spectrum modes, and recommended for any production assessment.

> This document describes the RoE concept and the fields Vulna captures. In the
> product, RoE records are created and versioned via the Administration area and
> the `/api/v1/rules-of-engagement` API (implemented in a later phase).

## What an RoE must specify

- **Authorization statement** — an explicit affirmation that testing is
  permitted, plus a ticket or authorization reference.
- **Scope** — the exact sites, network scopes (CIDRs), and any excluded targets.
- **Testing window** — allowed start/end times and allowed hours of day.
- **Allowed actions** — the assessment mode and the categories of activity
  permitted (e.g. discovery, safe checks, allowlisted validation).
- **Prohibited actions** — explicitly disallowed activity (always includes the
  project non-goals: DoS, destruction, persistence, brute force, etc.).
- **Contacts** — named owner, business contact, technical contact, and an
  emergency contact reachable during the window.
- **Evidence policy** — what proof may be collected and how it is retained,
  redacted, and eventually destroyed.
- **Session policy** — maximum session lifetime and automatic-termination rules
  for any validation session.
- **Cleanup requirement** — confirmation that temporary artifacts and sessions
  are removed and verified.
- **Approvals** — the privileged approver(s); optional second-person approval
  for intrusive stages.

## Safety expectations

- Intrusive stages are disabled by default and require confirmation immediately
  before they run.
- Every active scan is cancellable (web, API, probe CLI, job expiry, or automatic
  safety trigger).
- The probe terminates scanner processes gracefully, then forcibly after a
  configurable timeout.
- Nothing outside the approved scope is assessed, even if discovered mid-scan.

## Prohibited by default (non-negotiable)

Denial of service, data destruction, persistence, ransomware simulation,
unrestricted brute force, broad password spraying, credential dumping, disabling
endpoint security, monitoring evasion, domain-wide lateral movement, arbitrary
payload upload, and real user-data exfiltration.

If any requested activity falls outside these rules, stop and obtain explicit
written authorization before proceeding.
