# Remediation SLAs and ticket synchronization

Phase 43 adds governed remediation deadlines and a durable boundary between finding
persistence and external ticket systems. SLA calculations work without internet
access. Ticket connectors are optional and disabled until an administrator tests
and explicitly enables each destination.

## Ordered policies and fallback

Policies use unique integer priorities; the lowest number is evaluated first and
the first matching policy wins. Match input is bounded JSON over severity, finding
type, known-exploited state, site, and minimum risk score. There are no executable
expressions. A severity fallback always applies when no policy matches:

| Severity | Default due time |
|---|---:|
| Critical | 7 days |
| High | 30 days |
| Medium | 60 days |
| Low | 90 days |
| Informational | 180 days |

The initial deadline is anchored to first-seen time. Every calculation stores the
selected policy, priority, matching inputs, severity, duration, source, and previous
calculation link. The compatibility `finding.due_at` field is a projection of the
latest immutable calculation. Once a calculation exists, clients must use the SLA
exception workflow instead of directly editing `due_at`.

## Exceptions and accepted risk

An exception request documents a later proposed deadline and reason. A separate,
step-up-authorized decision appends a new calculation; it never overwrites the old
one. Rejections remain in history.

Risk acceptance does **not** pause SLA time by default. A policy must explicitly set
`pause_on_risk_acceptance`. For such a policy, acceptance records the pause time and
expiry appends a resume calculation that extends the deadline by exactly the paused
duration. History records calculations, exceptions, pauses, resumes, breaches, and
completion for metric reconstruction.

## Structured guidance

Guidance is finding-bound and source-attributed. It has a classification (patch,
configuration, upgrade, compensating control, remove, or investigate), a summary,
bounded remediation steps, bounded validation steps, and references. Steps are data,
not commands: Vulna never executes guidance text.

## Connector safety boundary

Connector secrets use a ticket-specific HKDF encryption context. Read APIs,
portability exports, audit metadata, task payloads, and UI state expose only
`has_secret` and non-secret configuration. HTTPS origins cannot contain embedded
credentials or fragments. Test and update operations require recent step-up, and a
connector cannot be enabled until it passes a test.

The API queues an allowlisted `tickets.sync` database task only after the finding is
already durable. The worker creates a selected-field payload (title, bounded summary,
severity/priority/status, CVEs, remediation, due date, and verification time); raw
evidence and scanner output are excluded. A remote failure is stored on the sync and
does not roll back or delay the finding.

Each adapter implements the same idempotent `test`, `upsert`, and `close` contract.
External tickets close only after the finding is resolved by a successful
verification scan, or when an authorized caller supplies an explicit reason that is
captured in the audit event. Provider adapters are delivered as separate stacked
changes so each protocol can be reviewed and qualified independently.

## Backup and portability

Encrypted database backups contain SLA history, connector ciphertext, task state,
and synchronization records. Portability schema v7 exports SLA policy/calculation/
guidance data and sanitized connector/sync metadata, but never connector ciphertext.
Restoring a usable connector therefore requires an encrypted backup, not a
portability bundle.
