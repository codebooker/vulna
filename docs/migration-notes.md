# Migration notes

User-visible behavior and configuration changes, per release. Vulna is in
pre-release active development; until the first tagged release, this page tracks
changes on `main`. Full detail is in the [CHANGELOG](../CHANGELOG.md).

## How to read this

Each release that changes user-visible behavior or configuration lists:

- **What changed** for an operator.
- **Action required**, if any (a new setting, a migration to run, a command that
  moved).

Database migrations run automatically on start (`alembic upgrade head`); no manual
step is needed for schema changes unless noted.

## Unreleased (on `main`)

- **Notifications (Phase 29).** New email/webhook notification channels. No action
  required; opt in by creating a channel under Notifications. Credentials are
  stored encrypted and never returned.
- **Maintenance center (Phase 28).** New maintenance overview, storage budgets,
  and a fail-closed retention cleanup. Retention cleanup is opt-in and
  administrator-only; no data is removed unless you run it.
- **Low-resource / offline (Phase 27).** New Lite/Standard/Full operating
  profiles derived from Scout resources, plus a durable result queue. No action
  required; new `result_queue_max_bytes` Scout setting defaults sensibly.
- **Diagnostics & maintenance (Phase 26–28).** New System Health and Maintenance
  pages. Read-only; no action required.

New configuration keys are additive and default to safe values; existing
deployments continue to work without changes. See the per-phase entries in the
[CHANGELOG](../CHANGELOG.md) for specifics.
