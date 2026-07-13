# ADR 0040: Database-backed scheduler and worker runtime

## Status

Accepted for the post-Phase-39 worker gate.
This supersedes the deferred Redis task-framework choice in ADR 0001.

## Context

The API process previously ran a local `asyncio` loop. Multiple API replicas could
duplicate sweeps, a restart lost in-flight ownership, and there was no durable retry,
dead-letter, cancellation, or health surface. Later connector phases require failure
isolation and backpressure before they can safely add outbound work.

## Decision

Use PostgreSQL itself as the durable queue. A task has an idempotency key, schedule,
priority, bounded attempts, and an expiring worker lease. Claims use row locking with
`SKIP LOCKED`; workers renew leases and failed work retries with exponential backoff.
Only code-defined handlers are executable. PostgreSQL advisory locking elects one
scheduler leader, while idempotency remains the final duplicate barrier.

Run `vulna scheduler` and `vulna worker` as separate services from the existing API
image. The API lifespan handles schema/bootstrap only. Keep existing synchronous APIs
and add queued endpoints so `/api/v1` remains backward-compatible.

## Consequences

- API replicas no longer own periodic work.
- A worker crash delays a task until lease expiry but does not lose it.
- Handler transactions roll back before retry, and dead letters remain inspectable.
- Long-running handlers must remain idempotent because an external side effect can
  succeed immediately before a process failure.
- Queue state is backup-only operational data and is not a portability contract.
