# ADR 0023: Networking, URL, TLS, and Reverse-Proxy Assistant

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 23 (Networking, URL, TLS, and Reverse-Proxy Assistant)

## Context

Reaching a self-hosted app securely from the intended network is a top failure
point: wrong hostname, missing DNS, occupied ports, an expired or mismatched
certificate, mixed content, a clock that's off, or a misconfigured reverse proxy.
This phase adds an assistant and, more importantly, hardens how the API trusts
proxy-forwarded information.

## Decisions

### 1. Five explicit access modes

Localhost, private LAN, public DNS with automatic TLS (bundled Caddy), an existing
reverse proxy, and a manually supplied certificate. `app/services/networking.py`
maps each mode to `VULNA_DOMAIN`/`CADDY_TLS`/CORS settings and its warnings; the
bundled proxy already terminates TLS for the first three.

### 2. Trusted-proxy enforcement (the security core)

The API honors forwarded information — `X-Forwarded-For` and the Scout client-cert
fingerprint header — **only** when the immediate peer is within
`VULNA_TRUSTED_PROXIES` (default: loopback only; bundled Compose supplies Caddy's
exact static address). `get_request_context` derives the client IP from `X-Forwarded-For` only from
a trusted peer, and `probe_auth` rejects the fingerprint header from an untrusted
peer. An untrusted peer that reaches the API directly therefore cannot spoof the
source address or a Scout identity. There is **no blanket trust** of forwarding
headers.

### 3. Application TLS is separate from Scout mutual TLS

The browser-facing certificate and the internal CA that signs Scout client
certificates are independent. Changing the app URL or browser certificate never
invalidates an enrolled Scout — the assistant, the URL-change plan, and the docs
state this explicitly, and it is enforced by construction (separate CAs).

### 4. Validation and detection with plain-language remediation

`POST /networking/validate` checks the hostname, certificate chain (public parts
only), expiry, and name match, and detects split-DNS/NAT-loopback, mixed
HTTP/HTTPS, clock skew, and certificate-name mismatch — each with a corrective
action. `GET /networking/test-browser` reports exactly what the server observed
(peer, whether it is a trusted proxy, forwarded scheme) so a *Test from this
browser* confirms the proxy is right. `GET /networking/test-scout` reports local
Scout connectivity, and remote Scouts use `vulnascout doctor`.

### 5. A safe, reversible URL-change plan

`POST /networking/url-change` validates a new URL and returns an **atomic change
plan** (the exact `VULNA_*` values) plus rollback values, without mutating the live
(environment-sourced) configuration. The prior URL keeps working until the plan is
applied and the proxy/API restart, so the change is reversible.

### 6. Generated reverse-proxy snippet, and no default exposure

`reverse_proxy_snippet` emits an nginx block for the "existing proxy" mode that
forwards TLS state, keeps the private key on the proxy, and does not forward the
Scout fingerprint header from the browser path. By default only the bundled proxy
publishes ports (80/443); PostgreSQL, Redis, the API, the frontend, and the
metrics stack stay on the internal network.

## Security constraints (how they are met)

- **Never disable certificate validation** — the assistant explains and remediates
  certificate problems; nothing here weakens verification (§4).
- **Private keys never in the UI or diagnostics** — the API refuses any submitted
  PEM containing a private key; certificate inspection returns public parts only
  (§4).
- **Public mode warns first** — the assistant surfaces the auth/updates/backups/
  rate-limiting warning before public access is chosen (§1).

## Consequences

- Each access mode has a documented recovery path (`docs/networking.md`) and an
  automated validation surface.
- Spoofed proxy headers from an untrusted peer are ignored (tested).
- A URL change is deliberate and reversible; Scout identity survives a browser-cert
  change.

## Rollback / migration

Additive. The new `trusted_proxies` setting defaults to the private ranges the
bundled proxy already uses, so existing single-host and documented deployments are
unchanged; only a direct-from-public-peer request (which the threat model already
forbids) is now additionally rejected. The assistant endpoints are new.

## Alternatives considered

- **Trusting `X-Forwarded-*` unconditionally** (the framework default). Rejected:
  it lets any direct caller spoof the source IP and, worse, the Scout fingerprint.
- **Mutating live settings on URL change.** Rejected: settings come from the
  environment; returning a validated plan with rollback is safer and keeps the
  prior URL working until the operator applies it.
