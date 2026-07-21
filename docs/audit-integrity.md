# Audit integrity

Vulna authenticates every new audit event with HMAC-SHA-256 and links events in
an organization-local SHA-256 chain. The HMAC key remains in the application
environment; PostgreSQL receives only signatures and hashes. A database-only
attacker therefore cannot rewrite an event and produce a valid replacement.

PostgreSQL serializes inserts per organization, assigns the authoritative chain
sequence, and rejects updates and deletes on `audit_events`. The same production
trigger also makes Rules-of-Engagement authorization versions immutable.

Set `VULNA_AUDIT_INTEGRITY_KEY` to a dedicated random secret for the strongest
separation from evidence and session keys. If it is omitted, Vulna uses
`VULNA_MASTER_KEY`. During a key rotation, keep prior keys in the comma-separated
`VULNA_AUDIT_INTEGRITY_PREVIOUS_KEYS` setting until the required retention period
has elapsed.

Operators with `audit.read` can verify their complete organization chain with:

```text
GET /api/v1/audit/integrity
```

The response reports the number of checked events, the last chain hash, and the
first failure if a row was edited, removed, reordered, or signed by an unknown
key. Rows that existed before the integrity migration are linked as explicitly
identified legacy events; they were not retroactively HMAC-authenticated.

For regulated or adversarial evidence requirements, periodically export the
reported last hash and event count to a separately administered SIEM or WORM
store. An external checkpoint is what exposes deletion of an entire chain tail
by a fully privileged database administrator.
