# ADR 0030: Documentation, Demo, and Guided Learning

- **Status:** Accepted
- **Date:** 2026-07-11
- **Phase:** 30 (Documentation, Demo, and Guided Learning)

## Context

Documentation is part of the product, not a repository appendix. A self-hoster
should be able to go from a clean host to a first safe scan by following a tested
quick start, understand findings in plain English, evaluate the interface without
scanning, and find the right guide from wherever they are stuck. This phase adds
task-oriented documentation, a safe demo mode, a contextual help catalogue, and
tests that keep documentation honest.

## Decisions

### 1. A documentation home with Simple and Advanced paths

`docs/README.md` is the entry point: a quick start, a **Simple path** (one host)
and **Advanced path** (distributed Scouts, proxies, offline), the three
**deployment models** (single-host, distributed Scouts, Relay) on one page so a
new user can tell them apart, a task-guide index, and reference links. New guides
fill the gaps prior phases left: quick start, terminology, understanding findings,
troubleshooting, demo mode, and the exposure checklist.

### 2. Troubleshooting starts from symptoms

`docs/troubleshooting.md` is organized by observable symptom ("I can't reach the
dashboard", "a Scout shows offline"), not by internal component name, and points
at System Health / `vulna doctor` for the component picture.

### 3. Safe demo mode

Demo mode seeds a self-contained **Demo Environment** with sample assets,
services, and findings and is safe by construction: sample hosts use only
**reserved documentation address ranges** (RFC 5737), and while demo mode is on
the jobs API **refuses to create real scan jobs**, so the demo can never contact a
target. The flag lives in the organization's `settings_json` (no schema change);
disabling removes the seeded data. Enable/disable is admin-only and audited.

### 4. A contextual help catalogue

`app/services/help_topics.py` maps a topic key to a title, summary, and a `docs/`
path, plus lookups by job error code and maintenance domain, and the administrator
exposure checklist. The UI deep-links errors, setup steps, findings, and
maintenance warnings to the right guide instead of a generic log page.

### 5. Documentation is tested

A test asserts every help-topic `doc` path exists (a renamed guide fails CI) and
that error/domain mappings reference known topics. A documentation lint asserts
the new and security-sensitive guides do **not** recommend insecure practices
(disabling TLS verification, privileged containers, exposing the database, default
secrets). Examples use documentation/reserved addresses and state authorization
requirements.

## Security constraints (how they are met)

- **Demo cannot scan** — real job creation is blocked in demo mode; sample hosts
  are documentation ranges only.
- **No insecure guidance** — a docs lint forbids recommending TLS-verification
  disablement, privileged runs, open database ports, or default secrets; the
  exposure checklist calls these out as things never to do.
- **No real data in samples** — demo data is synthetic and scoped to the Demo
  Environment site.

## Consequences

- A new user has a single, tested path to a first scan and a place to look things
  up in plain language.
- The interface can be evaluated safely with no risk of touching a real target.
- Documentation drift (a renamed guide, an insecure recommendation) is caught in
  CI.

## Rollback / migration

Additive: new docs, a demo-mode flag in `settings_json` (no schema change), a help
catalogue, and read/enable/disable endpoints. Removing demo data is a delete of
the Demo Environment site's rows.

## Alternatives considered

- **A full multi-platform clean-install CI matrix.** Deferred: booting each
  supported platform class to run the quick start end-to-end needs real VM
  infrastructure. This phase ships the tested quick start plus documentation
  integrity/lint tests; the platform matrix can be added to CI later.
- **Demo mode as a separate database/tenant.** Rejected as heavier than needed; a
  scoped Demo Environment site plus a job-creation guard is simpler and safe.
