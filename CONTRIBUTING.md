# Contributing to Vulna

Thanks for your interest in contributing! Vulna is built in small, testable
milestones. Please read [`VULNA_CODEX_BUILD_PLAN.md`](VULNA_CODEX_BUILD_PLAN.md)
and [`docs/architecture.md`](docs/architecture.md) before starting.

## Ground rules

Vulna is security-sensitive. Contributions must uphold the safety guarantees in
[`SECURITY.md`](SECURITY.md). In particular:

1. **Never** introduce arbitrary command execution or accept unstructured command
   strings from the web/API for a probe to run.
2. **Never** weaken local scope checks (CIDR / DNS / redirect enforcement).
3. **Never** hard-code secrets. Use environment variables and the provided
   `.env.example` template.
4. Treat all scanner output as untrusted; parse strictly and sanitize before
   rendering or reporting.
5. Use typed plugin inputs and allowlisted arguments only.
6. Add negative authorization tests for every new endpoint.
7. Use database migrations for schema changes and keep API/JSON schemas versioned.

## Development setup

See the [README](README.md#quick-start-development). In short:

```bash
cp .env.example .env
make dev        # start the dev stack
make test       # run all tests
make lint       # run all linters / type checks
```

Component-specific commands live in the `Makefile` (`make backend-test`,
`make frontend-test`, `make probe-test`, etc.).

## Branches, commits, and PRs

- Work on a feature branch; keep changes commit-sized and focused.
- Reference the build-plan phase you are implementing (e.g. "Phase 1: ...").
- Every feature change should include or update tests.
- Run `make lint` and `make test` before opening a PR.
- Fill in the pull-request template, including a security-impact note.

## Working one phase at a time

Follow the phased build plan (§31). Do not attempt to implement multiple phases
in one unreviewed change. For each phase, document: files added/changed, commands
to run, tests added, security assumptions, and known limitations.

## Preserving the simple path

Vulna is self-hoster-first: one person must be able to install it on one host and
reach a first safe scan without expertise. When you add an advanced feature, keep
that path intact:

- **One default path.** Ordinary use must not require editing YAML, enabling flags,
  or reading advanced docs. Advanced capabilities (distributed Scouts, VulnaRelay,
  custom certs, API automation, plugins) are **opt-in and off by default**, and
  must never become a dependency of the single-host path.
- **Safe defaults stay safe.** Public scanning, intrusive/active-web, credentials,
  exploit modules, and telemetry stay OFF by default. No opt-in via preselected
  controls.
- **Same security boundary.** Convenience may automate enrollment/config but must
  never bypass signatures, scopes, approvals, cancellation, or least privilege, and
  must not require privileged containers, host networking, or Docker socket access
  beyond the documented Scout/scanner boundary.
- **No mystery failures.** Every failure names the problem, its impact, and the
  next step. Changes are reversible (preflight + rollback).
- **Test the tutorial.** The default install and first scan are a release test; the
  security-critical [release gate](docs/release-process.md)
  (`deploy/release/release_gate.sh`) must stay green.

If a change makes the simple path harder, it needs a different design.

## Code of conduct

All participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
