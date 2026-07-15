# Single-host Vulna deployment

Run the entire Vulna platform — dashboard, database, reverse proxy, **and** a
working local VulnaScout — on one machine, with no second host, no cloud
dependency, and no manual token copying. This is the recommended starting point
for self-hosters and small deployments.

The local Scout comes up **enrolled but idle**: it authenticates with the same
mutual-TLS certificate, signed policy, and signed jobs as any remote Scout, and
it can scan **nothing** until you approve a network scope. Safe defaults stay
safe.

## Prerequisites

- Docker and the Docker Compose plugin.
- ~2 GB free RAM and a few GB of disk.

## 1. Configure

```bash
cp .env.example .env
```

Set at least these in `.env`:

| Variable | Purpose |
|---|---|
| `POSTGRES_PASSWORD` | Database password. |
| `VULNA_SECRET_KEY` | Session/JWT signing secret (e.g. `openssl rand -base64 48`). |
| `VULNA_ADMIN_EMAIL` | First administrator login. Must be a real, routable address — reserved domains such as `.test`, `.local`, and `.example` are rejected by login, and the app refuses to start if this address can't be used to sign in. |
| `VULNA_ADMIN_PASSWORD` | First administrator password. |
| `VULNA_DOMAIN` | Leave as `localhost` for a local box, a hostname, or a bare IP for LAN access. Public (Let's Encrypt) mode needs a real domain. |
| `CADDY_TLS` | `internal` for a self-signed local CA, or your email for Let's Encrypt when `VULNA_DOMAIN` is public. |

Never commit `.env`; it is git-ignored.

> **Probe mTLS runs on its own `:8443` listener.** The browser UI is served on
> `:443` with no client-certificate requirement, so the dashboard is reachable by
> hostname **or by raw IP** (a self-signed cert warning is expected with the
> internal CA). VulnaScout probes — including the co-located local Scout —
> authenticate on `:8443`. If you grow to remote Scouts, point them at
> `https://<host>:8443`. Public mode still needs a real domain because Let's
> Encrypt cannot issue a certificate for a bare IP.

## 2. Start

```bash
docker compose -f docker-compose.yml -f docker-compose.single-host.yml up -d
```

The first start builds the images (including the local-Scout image with the
standard scanner pack — Nmap, Nuclei, testssl.sh — plus Metasploit for controlled
pentests, which stays inert until you enable pentest on the scout and approve a
session) and then, in order:

1. applies database migrations automatically;
2. seeds the default organization, a **Local Site**, the admin, and a one-time,
   auto-approve enrollment token written to an internal volume (never shown in the
   UI or logs);
3. brings up Caddy with probe mutual-TLS enabled;
4. auto-enrolls the co-located local Scout, which then heartbeats.

Watch it converge:

```bash
docker compose -f docker-compose.yml -f docker-compose.single-host.yml ps
docker compose -f docker-compose.yml -f docker-compose.single-host.yml logs -f local-scout
```

You should see `local-scout: enrolled` followed by `running as probe … against
https://vulna-dash:8443`.

## 3. Verify

Open `https://localhost/` (accept the internal-CA certificate warning for a local
box) and log in with your admin credentials.

Per-component health, including the local Scout, is available to any
authenticated user:

```bash
curl -sk https://localhost/api/v1/system/component-health \
  -H "Authorization: Bearer $TOKEN"
# {"application":"ok","database":"ok","local_scout":"connected", ...}
```

`local_scout: connected` means the co-located Scout is enrolled and its heartbeat
is current.

## 4. Approve a scope, then scan

The local Scout is connected but has **no approved scope**, so it will refuse
every target. To scan your own network, add and approve a network scope in the UI
(Sites → Local Site → Scopes). Only after you approve a scope can any job run, and
the Scout still rejects out-of-scope targets locally.

Private ranges are allowed; scanning public ranges requires the explicit
`allow_public_addresses` opt-in. Only assess systems you are authorized to test —
see [`../../docs/authorized-use.md`](../../docs/authorized-use.md).

## Data and upgrades

State lives on named volumes (`postgres_data`, `redis_data`, `reports`,
`evidence`, `scout_state`, `keys`, `caddy_data`, `bootstrap`). Recreating the
application containers is safe — identity, findings, reports, and Scout
enrollment persist. To upgrade, pull/rebuild and `up -d` again; migrations reapply
idempotently.

## Growing to remote sites

This is the same data model and enrollment flow as a distributed deployment.
Adding a remote VulnaScout later is the normal **Add Scout** flow against the
same database and organization — no migration, no data loss. The single-host
profile is a packaging choice, not a different product.

The profile also includes the central WireGuard egress namespace needed by
VulnaRelay. Relay mode stays off until an administrator enables it under
**Management → Appliances → Relay**. A remote Scout remains the recommended
choice when a site can run scanners; use a Relay when the site requires a
scanner-free endpoint. See the [endpoint deployment guide](../../docs/deployment.md)
and [Relay security model](../../docs/relay.md).

## Advanced knobs

| Variable | Default | Effect |
|---|---|---|
| `VULNA_RUN_MIGRATIONS` | `true` | Set `false` to skip auto-migration (run it as a separate job). |
| `VULNA_BOOTSTRAP_LOCAL_SCOUT` | `true` (set by this overlay) | Enables the auto-enrolled local Scout. Unset for a dashboard-only host. |
| `VULNA_LOCAL_SCOUT_TOKEN_TTL_MINUTES` | `60` | Lifetime of the one-time enrollment token. |

See [ADR 0017](../../docs/adr/0017-single-host-deployment.md) for the design and
the security rationale.
