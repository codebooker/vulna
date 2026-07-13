# Durable scheduler and worker

Vulna runs scheduled and potentially slow internal work outside the web process.
Single-host production and development Compose installations start two services from
the same API image:

- `vulna scheduler` elects one leader and creates idempotent task records.
- `vulna worker` claims database-leased work and records heartbeats.

The API does not run an in-process scheduler. Restarting or scaling API containers
therefore cannot duplicate scheduled work.

The worker and API share the persistent key volume so automatically created scan
jobs use the same Ed25519 signing identity as interactive jobs. Reports and evidence
volumes are also shared; the scheduler needs database access only.

## Task lifecycle

`background_tasks` stores an allowlisted task type, non-secret JSON payload,
idempotency key, priority, schedule time, attempts, lease owner/expiry, result, and
error metadata. States are `queued`, `running`, `retry`, `completed`, `cancelled`,
and `dead_letter`.

Workers claim due rows with a database lock, renew the lease while a handler runs,
and release it on completion. A worker crash leaves a recoverable expired lease.
Failures use bounded exponential backoff and move to the dead letter state after the
configured maximum attempts. Scheduler replicas use a PostgreSQL advisory lock;
only the elected leader enqueues a tick. Queue depth backpressure stops new periodic
work before the database is overwhelmed.

Task payloads never select Python modules, commands, or executable expressions. The
worker dispatches only code-reviewed handler names. Payloads must contain identifiers
and non-secret options only—never credentials, evidence, raw scanner output, or token
values.

## Operations

Administrators with `tasks.read` can use **Task operations** or:

- `GET /api/v1/tasks` for history and dead-letter inspection;
- `GET /api/v1/tasks/health` for queue counts and process heartbeats; and
- `GET /api/v1/tasks/{id}` for one task.

`tasks.manage` permits audited cancellation and retry. Cancellation of queued work is
immediate. Running work receives a durable cancellation request; its handler finishes
or rolls back, and the worker records the task as cancelled rather than completed.

The additive queued interfaces are `POST /api/v1/feeds/{source}/tasks` and
`POST /api/v1/reports/tasks`. Clients may supply `Idempotency-Key`; the returned task
is the existing record when that key was already accepted.

## Deployment and recovery

The queue and heartbeat tables live in PostgreSQL and are covered by the encrypted
database backup. They are deliberately excluded from portability exports because
they are transient operational state. After restore, start the API first so migrations
and bootstrap finish, then the scheduler and worker. Any lease owned by the old host
is reclaimed after expiry.
