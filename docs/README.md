# Vulna documentation

Documentation is part of the product. Start here.

> **Authorized use only.** Vulna must only assess systems and networks you own or
> have explicit written permission to test. See [authorized use](authorized-use.md).

## Start here

- **[Quick start](quickstart.md)** — clean host to first safe scan.
- **[Terminology](terminology.md)** — scanner and vulnerability language in plain
  English.
- **[Demo mode](demo.md)** — explore the interface with sample data, no scanning.

## Two paths

- **Simple path** — one host, the guided installer, a local Scout, safe presets.
  Everything in the quick start.
- **Advanced path** — distributed Scouts, reverse proxies, constrained/offline
  sites, and custom presets. Each guide below has advanced notes where relevant.

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

Use when: a homelab or a single site. See [installation](installation/README.md).

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

A thin relay for constrained sites where a full Scout cannot run. Opt-in and
advanced; the smart Scout stays the default.

```
   VulnaDash ──── Relay ──── constrained site
```

Use when: a site can only run a minimal footprint. Optional; see the roadmap's
VulnaRelay notes.

## Task guides

| I want to… | Guide |
|---|---|
| Install on one host | [installation](installation/README.md) |
| Add a remote Scout | [deployment](deployment.md) |
| Choose a scan preset | [terminology](terminology.md) |
| Understand a finding | [understanding findings](understanding-findings.md) |
| Fix and verify a finding | [understanding findings](understanding-findings.md) |
| Update and roll back | [updates](updates.md) |
| Back up and restore | [backups](backups.md) |
| Change the URL or certificate | [networking](networking.md) |
| Keep it healthy / clean up | [maintenance](maintenance.md) |
| Get notified | [notifications](notifications.md) |
| Invite, suspend, or assign users | [user lifecycle](user-lifecycle.md) |
| Review or revoke signed-in devices | [sessions](sessions.md) |
| Set up MFA, passkeys, or recovery codes | [multi-factor authentication](mfa.md) |
| Run on small or offline hardware | [low-resource](low-resource.md) |
| Diagnose a problem | [diagnostics](diagnostics.md) · [troubleshooting](troubleshooting.md) |
| Choose a dashboard experience | [experience profiles](experience-profiles.md) |
| Expose Vulna beyond my LAN | [exposure checklist](administration/exposure-checklist.md) |

## Reference

- [Architecture](architecture.md) · [Threat model](threat-model.md)
- [Security review checklist](security-review-checklist.md)
- [Capability status](capabilities.md)
- [Migration notes](migration-notes.md)
- [Architecture decision records](adr/)
