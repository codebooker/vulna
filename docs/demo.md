# Demo mode

Demo mode lets you explore the Vulna interface with **sample data and no
scanning**. It is useful for evaluating the UI, giving a walkthrough, or testing
integrations before pointing Vulna at a real network.

## What it does

- Seeds a self-contained **Demo Environment** site with a couple of sample hosts,
  services, and findings (including a sample critical and a KEV-flagged finding).
- All sample hosts use **reserved documentation address ranges** (`198.51.100.0/24`
  and `203.0.113.0/24`), never a routable target.
- While demo mode is on, Vulna **refuses to create real scan jobs**, so it cannot
  contact any target.

## Turning it on and off

Demo mode is an administrator action:

- **Enable** — `POST /api/v1/demo/enable` (or the Settings toggle). Seeding is
  idempotent.
- **Status** — `GET /api/v1/demo/status`.
- **Disable** — `POST /api/v1/demo/disable` removes the seeded sample data.

Both enabling and disabling are audited.

## Notes

- Demo data is clearly synthetic and is scoped to your organization's Demo
  Environment site.
- Because real scans are blocked while demo mode is on, disable it before running
  an actual assessment.
- Demo mode changes nothing about the safety model: scopes, approvals,
  signatures, and mutual TLS all still apply to real work once demo mode is off.
