# Authorized Use

**Vulna performs network scanning and, when explicitly enabled, authorized
penetration-testing actions. You may only use it against systems and networks
you own or have explicit, written authorization to assess.**

Unauthorized scanning, enumeration, or exploitation of computer systems may
violate laws such as the U.S. Computer Fraud and Abuse Act, the UK Computer
Misuse Act, and equivalent legislation in other jurisdictions, as well as
contracts and acceptable-use policies. You are solely responsible for ensuring
you have proper authorization before running any assessment.

## Operator responsibilities

Before running any scan you must:

1. Confirm ownership of, or written permission to test, every target in scope.
2. Define approved network ranges (CIDRs) and record who approved them.
3. Choose an assessment mode appropriate to the sensitivity of the environment.
4. For intrusive modes, complete a Rules of Engagement document (see
   [`rules-of-engagement.md`](rules-of-engagement.md)), including a testing
   window, named owner, and emergency contact.
5. Notify relevant stakeholders (network, security, and system owners) as
   required by your organization's change-management process.

## How Vulna helps enforce authorization

Vulna is designed so that authorization is enforced in depth, but **the platform
cannot know whether you are legally permitted to test a target** — that
responsibility remains with the operator. Technical controls include:

- Per-probe signed local policy with approved/denied CIDRs.
- Rejection of `0.0.0.0/0`, `::/0`, and (by default) public IP ranges.
- DNS re-resolution and redirect scope enforcement at execution time.
- Signed, expiring job envelopes.
- Intrusive stages disabled by default and gated behind explicit approval.

## Assessment modes

- **Vulnerability Detection** — mostly non-destructive discovery and safe
  vulnerability checks. No shells, persistence, lateral movement, or data
  extraction.
- **Controlled Pentest** — explicitly authorized validation of selected
  weaknesses using allowlisted modules, with approvals and automatic cleanup.
- **Full-Spectrum Assessment** — a guarded, multi-stage workflow combining the
  above, where intrusive stages require stronger approvals and may be skipped.

If you are unsure whether an action is authorized, **do not run it.** Stop and
obtain written confirmation first.
