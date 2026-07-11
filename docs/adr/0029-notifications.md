# ADR 0029: Simple Notifications and Self-Hosted Integrations

- **Status:** Accepted
- **Date:** 2026-07-11
- **Phase:** 29 (Simple Notifications and Self-Hosted Integrations)

## Context

A self-hoster wants to hear about important events (a scan failed, a KEV match, an
expiring certificate) where they already work — email, or a webhook into a
self-hosted notifier or automation system — without deploying an enterprise
ticketing stack and without editing environment files. This phase adds outbound
email and signed-webhook channels with event subscriptions, delivery policies,
quiet hours, deduplication, delivery history, and secret rotation.

## Decisions

### 1. Outbound-only, two channel types

A channel is either **email** (SMTP) or a **signed webhook** (HTTPS POST). Both are
strictly outbound; Vulna never opens an inbound integration surface. Optional
deep links in a payload point back into Vulna but never carry a secret.

### 2. Emission is decoupled from delivery, so it never blocks

`emit_event` only **persists** pending `NotificationDelivery` rows for subscribed
channels; it never sends inline and its one call site wraps it in a suppressor.
So a notification problem can never block scan completion or finding persistence.
`dispatch_pending` does the actual sending later, records status/attempts/errors,
and isolates failures per channel.

### 3. Selected fields only — never evidence or secrets

A `NotificationEvent` carries a small, explicit set of scalar fields (type,
title, summary, severity, site, object type/id, a few data fields) plus a deep
link. Raw evidence, scanner output, credentials, and report files are never
included, in email or webhook payloads.

### 4. Webhook payloads are versioned, signed, and replay-resistant

The body is a versioned JSON document. The signature is
`HMAC-SHA256(signing_key, "<timestamp>.<body>")`, sent as `X-Vulna-Signature:
t=<ts>,v1=<hex>` with the timestamp also in `X-Vulna-Timestamp`. Binding the
timestamp into the signed material lets a receiver reject replays outside a short
window. A per-delivery id (`X-Vulna-Delivery`) provides idempotency at the
receiver.

### 5. Destinations are validated against SSRF

A webhook URL must be `https` and must not resolve to a loopback, link-local,
cloud-metadata, multicast, unspecified, or reserved address. Private (RFC1918/ULA)
addresses are rejected unless the operator explicitly opts in for a trusted
service on their own network; the cloud-metadata address is blocked even then.
The same validation runs at configuration, at the test action, and again at send
time, so a webhook cannot be turned into a request-forgery primitive.

### 6. Policies, quiet hours, and dedup

A channel delivers **immediate**, or as an **hourly / daily / weekly** digest.
Repeated identical events dedup against an existing unsent delivery so a recipient
is not flooded. Quiet hours **delay** non-emergency notifications (they are never
discarded) and are re-evaluated at dispatch; emergency events (KEV match, storage
pressure, Scout offline) are not delayed.

### 7. Credentials encrypted at rest, never returned

The SMTP password / webhook signing key is encrypted with a Fernet key derived
from the deployment secret and stored in `encrypted_secret`. The API never
serializes it — reads show only `has_secret` — and it can be rotated through a
dedicated, audited endpoint. It is decrypted only at send time.

### 8. Test uses the real path

The test action builds a real event and sends through the same validation and
transport as production delivery, and is audited, so a successful test means real
delivery will work.

## Security constraints (how they are met)

- **No sensitive content** — selected fields only; no evidence, credentials,
  scanner output, or report files.
- **No SSRF** — https-only, address classification, private opt-in, metadata
  always blocked, validated at config/test/send.
- **Never blocks core work** — emission only persists and is suppressed at its
  call site; delivery is separate.
- **Credentials protected** — encrypted at rest, never returned, rotatable.
- **Auditing** — channel create, secret rotation, and test are audited.

## Consequences

- An operator configures and tests email or a webhook entirely from the UI.
- Receivers can verify authenticity and reject replays.
- Notification issues degrade gracefully and never affect scanning.

## Rollback / migration

Two additive tables (`notification_channels`, `notification_deliveries`); a
representative emit point (scan completed/failed) is wired, and other event
emitters call the same `emit_event`. Delivery is triggered by
`POST /notifications/dispatch` (an operator or a scheduled call); a background
dispatcher can be layered on later without changing the model.

## Alternatives considered

- **Send inline at the event site.** Rejected: a slow or failing destination would
  block scan/finding persistence. Persist-then-dispatch keeps them independent.
- **Ed25519-signed payloads.** HMAC-SHA256 with a shared secret is simpler for
  self-hosted receivers to verify and sufficient for authenticity + replay
  resistance; the deployment already uses Ed25519 where asymmetric trust is
  needed (jobs/policy/releases).
- **Allowing any webhook URL.** Rejected by the SSRF constraint.
