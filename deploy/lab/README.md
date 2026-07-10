# VulnaLab

An **isolated, intentionally-vulnerable** target environment for demonstrating
and testing Vulna end to end.

> ⚠️ **For isolated lab use only.** These services are deliberately vulnerable
> and out of date. Never run this where it is reachable from production or the
> internet. Use it only to exercise Vulna's assessment workflow against safe,
> disposable targets.

## Run

```sh
docker compose -f deploy/lab/docker-compose.yml up -d
```

- `dvwa` — a classic deliberately-vulnerable web app (SQLi/XSS/…): a target for
  the ZAP web-assessment and Nuclei stages.
- `legacy-web` — an old web server with a known-old banner: a target for
  discovery/service fingerprinting and CVE matching.

## Assess it

Enroll a VulnaScout probe with an approved scope that covers the lab network,
then create a job (or a full-spectrum workflow) targeting the lab hosts. Because
the lab is intentionally vulnerable, expect discovery, findings, CVE enrichment,
web findings, and — under explicit approval — controlled validation to populate.

Tear it down when finished:

```sh
docker compose -f deploy/lab/docker-compose.yml down -v
```
