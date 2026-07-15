# Vulna documentation

Documentation is part of the product. Start here.

> **Authorized use only.** Vulna must only assess systems and networks you own or
> have explicit written permission to test. See [authorized use](authorized-use.md).

## Start here

- **[Quick start](quickstart.md)** — clean host to first safe scan.
- **[Terminology](terminology.md)** — scanner and vulnerability language in plain
  English.
- **[Demo mode](demo.md)** — explore the interface with sample data, no scanning.

## Choose a topology

Every topology starts with the central appliance. It hosts the dashboard, API,
database, scheduler, workers, reports, and a scope-gated local Scout. Add an edge
endpoint only when the appliance cannot directly reach a network.

## Deployment models

A new user should be able to tell these apart at a glance.

### Single-host (start here)

Everything on one machine, including a co-located, scope-gated Scout.

```
        ┌──────────────────────────────┐
        │  one host                    │
        │  VulnaDash  ──mTLS──  Scout   │──▶ your LAN
        └──────────────────────────────┘
```

Use when: a homelab, one office, or any network directly reachable from the
appliance. See [installation](installation/README.md).

### Distributed Scouts

One dashboard, Scouts placed at other sites or segments, each connecting outbound
over mutual TLS.

```
                     ┌── Scout (office LAN)
   VulnaDash ──mTLS──┼── Scout (DMZ)
     (central)       ├── Scout (site B)
                     └── Scout (cloud VPC)
```

Use when: multiple locations or network segments a single box cannot reach. See
[deployment](deployment.md).

### Relay (optional, advanced)

A scanner-free WireGuard endpoint for a constrained site. The appliance's local
Scout runs the scanners and reaches only the Relay's approved ranges through the
tunnel. Relay mode is organization-wide opt-in and the smart Scout remains the
recommended default.

```
   appliance local Scout ── central egress ── WireGuard ── Relay ── site LAN
```

Use when: a site can run Linux and WireGuard routing but should not host scanner
engines. See [VulnaRelay](relay.md) and the [deployment guide](deployment.md).

## Task guides

| I want to… | Guide |
|---|---|
| Install on one host | [installation](installation/README.md) |
| Add a remote Scout or Relay | [endpoint deployment](deployment.md) · [Relay security model](relay.md) |
| Approve networks and choose a scan preset | [quick start](quickstart.md) · [terminology](terminology.md) |
| Track assets, tags, groups, and ownership | [asset context](asset-context.md) |
| Understand a finding | [understanding findings](understanding-findings.md) |
| Prioritize, fix, and verify findings | [explainable risk](explainable-risk.md) · [understanding findings](understanding-findings.md) |
| Generate PDF, CSV, or JSON reports | [reporting](reporting.md) |
| Update and roll back | [updates](updates.md) |
| Back up and restore | [backups](backups.md) |
| Change the URL or certificate | [networking](networking.md) |
| Keep it healthy / clean up | [maintenance](maintenance.md) |
| Configure email or signed-webhook notifications | [notifications](notifications.md) |
| Invite, suspend, or assign users | [user lifecycle](user-lifecycle.md) |
| Review or revoke signed-in devices | [sessions](sessions.md) |
| Set up MFA, passkeys, or recovery codes | [multi-factor authentication](mfa.md) |
| Configure OIDC, SAML, JIT, or break-glass access | [single sign-on](sso.md) |
| Provision users and groups from a directory | [SCIM provisioning](scim.md) |
| Create scoped roles, service accounts, or API tokens | [authorization](authorization.md) |
| Run read-only SSH or WinRM software inventory | [authenticated inventory](authenticated-inventory.md) |
| Set remediation SLAs or synchronize tickets | [SLA and ticketing](sla-ticketing.md) |
| Import passive inventory, reconcile assets, or build scheduled reports | [inventory intelligence](passive-inventory.md) |
| Inspect scheduler/worker tasks and dead letters | [durable tasks](background-tasks.md) |
| Run on small or offline hardware | [low-resource](low-resource.md) |
| Diagnose a problem | [diagnostics](diagnostics.md) · [troubleshooting](troubleshooting.md) |
| Choose a dashboard experience | [experience profiles](experience-profiles.md) |
| Expose Vulna beyond my LAN | [exposure checklist](administration/exposure-checklist.md) |

## Product areas

- **Operations:** overview, assets, findings, scans, sites, and activity.
- **Management:** remediation, reports, appliances, authenticated and passive
  inventory, SLAs and ticketing, networks, presets, and controlled pentests.
- **Administration:** users, SSO, SCIM, roles and service accounts, sessions,
  MFA, CVE feeds, integrations, system health, durable tasks, and settings.

Navigation is permission-aware. A user sees only the areas allowed by their
roles, grants, and site assignments.

## Reference

- [Architecture](architecture.md) · [Threat model](threat-model.md)
- [Security review checklist](security-review-checklist.md)
- [Capability status](capabilities.md)
- [Migration notes](migration-notes.md)
- [Architecture decision records](adr/)
