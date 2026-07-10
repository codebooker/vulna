# VulnaWatch

Continuous CVE / CISA KEV / EPSS intelligence synchronization and matching
workers. Delivered in **Phase 7**. See `VULNA_CODEX_BUILD_PLAN.md` §14.

In the MVP these workers run inside the VulnaDash backend (`dash/backend/app/intelligence`,
`app/tasks`); this directory is reserved for extracting them into an independently
deployable service later.
