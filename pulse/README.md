# VulnaPulse

Optional operational-observability layer for Vulna itself: Prometheus, Grafana,
exporters, provisioned dashboards, and alert rules, wired to a Docker Compose
`monitoring` profile. Delivered in **Phase 14**. See `VULNA_CODEX_BUILD_PLAN.md`
§25.

- `prometheus/` — scrape config and alert rules (version-controlled)
- `grafana/` — provisioned data sources and dashboards (version-controlled)
