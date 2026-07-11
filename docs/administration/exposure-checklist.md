# Exposing Vulna beyond your LAN

Vulna is designed to run on a private network. Before you make it reachable from
the internet or an untrusted network, work through this checklist. The same list
is available in the UI (`GET /api/v1/help/exposure-checklist`).

> **Authorized use only.** Exposing the dashboard does not change what you are
> permitted to assess. See [authorized use](../authorized-use.md).

## Checklist

1. **Terminate TLS at a reverse proxy** with a valid certificate. Do not serve the
   dashboard over plain HTTP. See [networking](../networking.md).
2. **Keep data ports private.** The database and Redis must stay bound to
   localhost / the internal Docker network. Never publish those ports.
3. **Use strong, unique secrets.** Set `VULNA_SECRET_KEY` and a strong admin
   password. Never run with default or example secrets.
4. **Require mutual TLS for Scouts** and keep `VULNA_TRUSTED_PROXIES` accurate so
   forwarded client identity cannot be spoofed.
5. **Firewall the host.** Allow only your reverse proxy / port 443 from outside;
   deny everything else.
6. **Turn on notifications** so you are told about failures, expiring
   certificates, and storage pressure. See [notifications](../notifications.md).
7. **Take a verified, encrypted, off-host backup** before exposing the service.
   See [backups](../backups.md).
8. **Review the security material** — the
   [security review checklist](../security-review-checklist.md) and the
   [threat model](../threat-model.md).

## Things to never do

- Do not disable TLS verification to "make it work"; fix the certificate instead.
- Do not run the stack with elevated/privileged containers to avoid a permission
  error; fix the permission instead.
- Do not open the database port to the network for a remote client; use a tunnel
  or run the client on the host.
- Do not reuse the example values from `.env.example` in production.
