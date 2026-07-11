# Privacy and data ownership

Vulna is self-hosted so you keep control of your data. This page explains what
Vulna does and does not send, how to inspect it, and the controls you have. See
[ADR 0031](adr/0031-privacy-and-portability.md) and the machine-readable
[data map](data-map.md).

## No mandatory anything

- **No account** on a vendor service, **no license server**, **no hosted control
  plane**, and **no telemetry endpoint** are required to run Vulna.
- The application **never contacts a release server**. Update checks and updates
  are run by you with the signed `vulna` CLI; the running app does not phone home.

## What can leave the deployment

The Privacy page (`GET /api/v1/privacy/outbound`) lists every outbound
destination and whether it is enabled:

- **Intelligence feeds** — NVD, CISA KEV, and EPSS, to enrich findings. Disable
  with the *intelligence feeds* toggle; you can instead import signed
  [offline bundles](low-resource.md).
- **SMTP and webhooks** — only the [notification](notifications.md) channels you
  configure, to the destinations you set.
- **Telemetry** — off unless you explicitly opt in (see below).

Nothing else leaves the deployment.

## Telemetry is opt-in and anonymous

Telemetry is **off by default** and is never enabled by a preselected control.
Before opting in, preview the exact payload (`GET /api/v1/privacy/telemetry/preview`):
it contains only the product version and **aggregate counts** (sites, assets,
scans, findings, critical findings). It **never** contains IP addresses,
hostnames, usernames, findings, CVEs tied to assets, evidence, credentials, report
contents, or any stable cross-installation identifier. Opt-in and opt-out are
audited.

Prefer to keep usage information entirely local? The **local analytics** option
(`GET /api/v1/privacy/analytics`) reports the same aggregate counts and is **never
transmitted**.

## Disabling does not break Vulna

Disabling update checks or telemetry does not disable scanning, reporting,
remediation, or local intelligence import. These features are independent.

## Secret inventory

`GET /api/v1/privacy/secrets` lists configured secrets — the application secret
key, the administrator account, the internal CA key, the job/policy signing key,
the optional NVD API key, and notification channel secrets — and whether each is
set. It **never returns a value**. Rotate secrets through their own workflows
(for example, notification channel secrets via
[notifications](notifications.md)).

## Retention and deletion

Retention and deletion are configurable, preview exactly what will be removed, and
are audited; they never delete data still referenced by report snapshots, active
findings, legal holds, or backups. See [maintenance](maintenance.md).
