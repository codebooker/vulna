# Packaging policy

Vulna keeps a small, testable set of official packages and welcomes community
packaging — as long as it is clearly labeled and never masquerades as official.

## Tiers

- **Officially maintained** — built, signed, and tested by the project (the
  `vulna` installer, the single-host Compose overlay, the official Scout/relay
  images). These pass the full [release qualification](release-process.md),
  including upgrade, rollback, backup, and restore.
- **Community-maintained templates** — deployment recipes contributed by the
  community for environments the project does not test continuously. They may be
  linked from the docs but are marked community-tier and are not covered by the
  release gate.
- **Experimental examples** — illustrative only; not for production.

A community template **cannot be presented as officially supported** unless it
meets the same upgrade and recovery tests as official packages.

## Security requirements for any packaging

Convenience must not weaken the security model. Packaging (official or community)
**must not** require:

- privileged containers,
- host filesystem access beyond the documented data/keys volumes,
- host networking, or
- Docker socket access beyond the documented Scout/scanner boundary.

Third-party templates **must not** silently replace the signed official images.
Pull official images by their signed reference; verify signatures and checksums.

## Reference deployment recipes

Supported reference deployments (VM or container) where the security model is
supportable:

- **Single host (Docker Compose)** — the default; see
  [installation](installation/README.md) and
  [`deploy/single-host`](../deploy/single-host/README.md).
- **Distributed Scouts** — a central VulnaDash with Scouts per site; see
  [deployment](deployment.md).
- **VulnaRelay (advanced, opt-in)** — thin-site tunnel; see [relay](relay.md).

Each recipe uses non-privileged containers and keeps data ports private.
