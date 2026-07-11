# Notifications

Vulna can notify you by **email** or **signed webhook** when something important
happens — a scan fails, a known-exploited CVE matches an asset, a certificate is
expiring — without editing environment files. Everything is **outbound-only**. See
[ADR 0029](adr/0029-notifications.md) for the design.

## Channels

Configure channels under **Notifications** (admin). Two types:

- **Email (SMTP)** — host, port, `from`, recipients, and (optionally) a username;
  the SMTP password is stored encrypted.
- **Webhook (HTTPS)** — a `url` and a signing secret.

A channel subscribes to a set of **events** and has a **delivery policy**.
Credentials are stored encrypted and are **never returned** by the API (reads show
only whether a secret is set). Rotate a secret with
`POST /api/v1/notifications/channels/{id}/rotate-secret`.

Use **Send test** (`POST .../{id}/test`) to verify a channel; the test goes through
the same validation and transport as real delivery, and is audited.

## Events

Scout offline · scan completed · scan failed · new critical/high finding · KEV
match · verification succeeded/failed · backup stale · feed stale · certificate
expiring · storage pressure · update available.

`GET /api/v1/notifications/events` returns the catalogue.

## Policies, quiet hours, deduplication

- **Policy** — `immediate`, or an `hourly` / `daily` / `weekly` digest.
- **Deduplication** — repeated identical events collapse to one delivery so you
  are not flooded.
- **Quiet hours** — set a window to **delay** non-emergency notifications (they are
  never dropped; they send when the window ends). Emergencies (KEV match, storage
  pressure, Scout offline) are not delayed.

Emission is decoupled from delivery: an event only queues a pending delivery, so a
notification problem never blocks a scan or finding. Delivery runs via
`POST /api/v1/notifications/dispatch` (an operator action, or a scheduled call).
`GET /api/v1/notifications/deliveries` shows history, retry state, and errors.

## Webhook payloads

Payloads are versioned JSON with **selected fields only** — no evidence, scanner
output, credentials, or report files:

```json
{
  "version": "1",
  "id": "<delivery id>",
  "type": "scan_failed",
  "occurred_at": "2026-07-11T12:00:00+00:00",
  "severity": "high",
  "title": "Scan failed",
  "summary": "…",
  "site_id": "…",
  "object": { "type": "job", "id": "…" },
  "deep_link": "https://vulna.example/jobs/…",
  "data": { "error_code": "timeout" }
}
```

Headers:

```
X-Vulna-Event:      scan_failed
X-Vulna-Delivery:   <unique id, use for idempotency>
X-Vulna-Timestamp:  <unix seconds>
X-Vulna-Signature:  t=<unix seconds>,v1=<hex hmac-sha256>
```

### Verifying a webhook

Compute `HMAC-SHA256(signing_secret, "<timestamp>.<raw body>")` and compare with
the `v1=` value using a constant-time comparison. Reject the request if the
timestamp is more than a few minutes from now (replay protection). Deduplicate on
`X-Vulna-Delivery`.

## Destination safety (SSRF)

A webhook URL must be `https` and must not resolve to a loopback, link-local,
cloud-metadata, multicast, unspecified, or reserved address. Private
(RFC1918/ULA) addresses are rejected **unless** you enable "allow private
destination" for a trusted service on your own network; the cloud-metadata address
(`169.254.169.254`) is blocked even then. Validation runs at configuration, on the
test action, and again at send time.
