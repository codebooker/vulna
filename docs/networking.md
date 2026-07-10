# Networking, URL, TLS, and reverse proxy

Reaching VulnaDash securely from the intended network is the most common
self-hosting stumbling block. This guide covers the five supported access modes,
how to test them, and how to recover when something is wrong. The in-app
**Networking & access** assistant validates a configuration and can *Test from
this browser*.

> **Application TLS is separate from VulnaScout mutual TLS.** The browser-facing
> certificate (below) is unrelated to the internal CA that signs Scout client
> certificates. Changing the browser certificate or URL never invalidates an
> enrolled Scout's identity.

## No default exposure

By default only the reverse proxy publishes ports (80/443). PostgreSQL, Redis, the
API, the frontend, and the metrics stack (Prometheus/Grafana, behind the opt-in
`monitoring` profile) are reachable only on the internal Docker network. Do not
publish them.

## Supported access modes

| Mode | Use | `VULNA_DOMAIN` | `CADDY_TLS` | Notes |
|---|---|---|---|---|
| **Local host only** | Single machine | `localhost` | `internal` | Self-signed; browser warns. |
| **Private LAN** | Home/office LAN | LAN IP or `*.local` | `internal` | Self-signed; trust the CA to avoid warnings. |
| **Public DNS + automatic TLS** | Internet-reachable name | public FQDN | your email (ACME) | Let's Encrypt via the bundled proxy. **Read the public-access warning below.** |
| **Existing reverse proxy** | You run nginx/Traefik | your FQDN | (your proxy) | Use the generated snippet and set `VULNA_TRUSTED_PROXIES`. |
| **Manual certificate** | Corporate/internal CA | your FQDN | your cert/key on the proxy | Provide the cert/key to the proxy out-of-band; **never paste keys into Vulna.** |

## Trusted proxies (anti-spoofing)

The API honors forwarded headers — `X-Forwarded-For` and the Scout client-cert
fingerprint — **only** from a peer within `VULNA_TRUSTED_PROXIES`. The default
trusts loopback and RFC1918/ULA (where the bundled proxy runs). Behind your own
reverse proxy, set it to that proxy's exact address. A request that reaches the API
directly from an untrusted peer cannot spoof the source address or a Scout
identity — the headers are ignored.

## Public access — read before enabling

Exposing the login to the internet means:

- Use a **strong administrator password** and keep updates current.
- Keep **backups** current and copied off-host.
- Consider **rate limiting** at the proxy.

The assistant surfaces this warning before you choose public mode.

## Testing and recovery

Use the **Networking & access** assistant: pick a mode, enter the hostname, and
**Validate**. It detects and explains invalid hostnames, split-DNS / NAT-loopback /
private-name mismatches, mixed HTTP/HTTPS, clock skew, certificate expiry, and
certificate-name mismatch — each with a corrective action. *Test from this browser*
reports exactly what the server sees (peer, whether it is a trusted proxy,
forwarded scheme).

| Symptom | Recovery |
|---|---|
| Browser can't reach the URL | Check DNS resolves from where you browse; confirm 80/443 are open and not in use (installer preflight); for NAT loopback use split DNS or the LAN IP. |
| Certificate name mismatch | Use a certificate whose SAN includes the hostname, or browse to a covered name. Never disable certificate validation. |
| Certificate expired | Renew/replace it and check the system clock (NTP). |
| "Not secure" / mixed content | Serve everything over HTTPS; set `VULNA_DOMAIN` and reach the site by that name. |
| Forwarded headers ignored behind your proxy | Set `VULNA_TRUSTED_PROXIES` to the proxy's address. |

## Changing the URL safely

`POST /api/v1/networking/url-change` returns an **atomic change plan** (the exact
`VULNA_*` values to set) plus rollback values. The prior URL keeps working until
you apply the plan and restart, so the change is reversible. Enrolled Scouts keep
their identity; update a Scout's `--server` only if the hostname changed.
