# Shared Schemas

Versioned, language-agnostic contracts shared between VulnaDash (Python) and
VulnaScout (Go). These JSON Schemas (Draft 2020-12) are the source of truth for
the documents that cross the trust boundary between the orchestrator and probes.

| Schema | Purpose |
|---|---|
| `schemas/job.schema.json` | Signed job envelope delivered to a probe |
| `schemas/result.schema.json` | A chunk of uploaded scan results |
| `schemas/plugin.schema.json` | Scanner plugin manifest (VulnaForge) |
| `schemas/policy.schema.json` | Signed local policy enforced by a probe |

Examples live in `examples/` and are validated in CI against their schemas.

## Versioning

Every document carries a `schema_version`. Breaking changes bump the version and
must be accompanied by migration notes. Signatures always cover the canonical
serialization of the document excluding the `signature` field itself.
