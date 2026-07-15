# Capability status

This page describes the capabilities implemented in the current codebase. It is
intentionally conservative: **available** means the API, authorization boundary,
user interface or documented operator workflow, and automated tests exist.
Availability is not the same as a production-readiness guarantee; Vulna remains
pre-1.0 software until the release-qualification process is complete.

Some capabilities are deliberately disabled until an administrator opts in.

## Assessment and deployment

| Capability | Status | Notes |
|---|---|---|
| Single-host appliance with local Scout | Available | The Scout enrolls automatically but starts with no approved scope. |
| Remote VulnaScout | Available | Signed Linux `amd64` and `arm64` installer paths; outbound mTLS control channel. |
| VulnaRelay | Available, opt-in | Scanner-free WireGuard endpoint with central egress policy and kill switches. |
| Asset and service discovery | Available | Nmap-based, scope-controlled discovery and change tracking. |
| Vulnerability and TLS assessment | Available | Nuclei and testssl.sh stages with bounded, signed workflows. |
| Web assessment | Available, gated | ZAP workflows remain subject to scope and active-scan approval. |
| Controlled pentest | Available, gated | Requires per-Scout enablement and explicit session approval. |
| Scheduling, cancellation, and live diagnostics | Available | Includes progress, stage state, failure codes, and retry context. |

## Inventory and context

| Capability | Status | Notes |
|---|---|---|
| Asset inventory and change history | Available | Assets, services, observations, and material changes are retained. |
| Tags, dynamic groups, and ownership | Available | Used for filtering, assignment, reporting, and authorization-aware views. |
| Authenticated software inventory | Available, opt-in | Fixed read-only SSH and WinRM collectors with encrypted credential delivery. |
| Passive inventory connectors | Available, opt-in | DHCP, DNS, Active Directory, Entra, UniFi, vCenter, Proxmox, XCP-ng, AWS, Azure, Google Cloud, CSV, and generic API adapters. |
| Reconciliation and lifecycle analytics | Available | Source links are reversible and observations retain provenance. |

## Risk, remediation, and reporting

| Capability | Status | Notes |
|---|---|---|
| CVE intelligence | Available | NVD, CISA KEV, EPSS, and advisory synchronization and matching. |
| Explainable risk scoring | Available | Versioned profiles, normalized inputs, factor contributions, and history. |
| Finding decisions and risk acceptance | Available | Evidence-backed, expiring decisions with audit history. |
| Remediation units and verification | Available | Exact grouping, reviewed proposals, ownership, and targeted verification scans. |
| SLAs and ticket synchronization | Available, opt-in | Policy-driven deadlines plus Jira, GitHub, GitLab, GLPI, and generic idempotent adapters. |
| Reports and exports | Available | Executive, technical, pentest, and full-spectrum PDF; CSV; and JSON. |
| Analytics and report templates | Available | Permission-scoped trends and scheduled report definitions. |

## Identity, administration, and integrations

| Capability | Status | Notes |
|---|---|---|
| User lifecycle and site assignment | Available | Invitation, suspension, reactivation, and durable attribution. |
| Revocable sessions | Available | Device/session inventory, refresh rotation, and immediate revocation. |
| TOTP, recovery codes, and WebAuthn | Available | Includes organization policy and step-up authentication. |
| OIDC and SAML SSO | Available, opt-in | Validation, test sign-in, break-glass safeguards, JIT, and group mappings. |
| SCIM 2.0 provisioning | Available, opt-in | Users, groups, deprovisioning, token rotation, and mapped grants. |
| Granular RBAC and service accounts | Available | Built-in/custom roles, scoped grants, and expiring restricted API tokens. |
| SMTP email and signed webhooks | Available, opt-in | Event subscriptions, digests, quiet hours, retries, and delivery history. |
| Audit log | Available | Security, administration, scan, and integration actions are attributed. |

## Operations and data ownership

| Capability | Status | Notes |
|---|---|---|
| Durable scheduler and worker | Available | PostgreSQL-leased tasks, retries, idempotency, and dead-letter operations. |
| System health and diagnostics | Available | Component health, support bundles, appliance doctor, and failure guidance. |
| Maintenance and observability | Available | Storage/retention checks plus optional Prometheus, Grafana, and alerts. |
| Backup, restore, update, and rollback | Available | Versioned, verified operational workflows. |
| Low-resource and offline modes | Available | Resource profiles and offline intelligence/update bundles. |
| Privacy and portability | Available | Data map, telemetry opt-in, bounded exports, and verified import workflows. |

Historical implementation phases are recorded in the
[architecture decision records](adr/) and [migration notes](migration-notes.md);
they are intentionally not used as product-facing capability names.
