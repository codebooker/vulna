# ADR 0009: Reports (VulnaReport)

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 8 (Reports)

## Context

Assessment data is only useful if it can leave the system in the forms different
audiences need: a PDF for executives and auditors, CSVs for spreadsheets and
ticketing, and a machine-readable JSON bundle for integrations. Reports must also
be reproducible — a report handed to an auditor must not silently change when the
underlying findings are later re-triaged (build plan Section 16).

## Decisions

### 1. One snapshot feeds every format

Generation first builds a single, plain-dict snapshot of the scan's data
(organization, site, scan job, assets, services, findings, CVE exposure,
changes). Every renderer — PDF, each CSV, the JSON bundle — reads from that one
snapshot. This guarantees the formats agree with each other and localizes all
database access to one place. The snapshot is also, verbatim, the body of the
JSON bundle, so the bundle is the canonical machine-readable export.

### 2. Reproducibility comes from storing rendered bytes

Each artifact is rendered once, written to the reports directory, and its path +
SHA-256 recorded on the `Report` row. Downloads stream the stored file, so a
report is byte-identical on every download regardless of later database changes.
The checksum lets a consumer verify integrity. There is no re-render on download.

### 3. Pure-Python PDF rendering (fpdf2), Latin-1-safe

PDFs are generated with fpdf2, which is pure-Python and needs no system libraries
(unlike HTML-to-PDF engines that require cairo/pango). This keeps CI simple and
the appliance lean. Because the core fonts are Latin-1, all text is coerced to
Latin-1 with replacement before rendering, so arbitrary scanner output (a finding
title with an em dash or a check mark) can never crash a report. Every section
named in the build plan is emitted even when its data is empty, so a report never
has missing sections.

### 4. Stable, documented CSV columns — including placeholders

CSV column orders are fixed and documented (Section 16.2). Columns for data that
later phases introduce (owner, due date, priority, risk-acceptance expiration) are
present now but empty, so downstream consumers can bind to a stable schema that
does not churn when Phase 10 lands remediation workflow.

### 5. Organization-scoped download authorization

Reports belong to an organization. Generation, listing, and download all require
an authenticated user in that organization; a report owned by another
organization returns 404 (not 403, to avoid confirming existence), and an
unauthenticated download is rejected. This satisfies "unauthorized user cannot
download report" without a separate ACL layer — the organization boundary that
governs every other resource governs reports too.

## Consequences

- Reports are consistent across formats and reproducible from stored bytes.
- Adding a format is: a renderer `(snapshot) -> bytes` plus an `ARTIFACTS` entry.
- No heavy system dependencies are pulled into the image or the appliance.

## Alternatives considered

- **HTML→PDF via WeasyPrint/wkhtmltopdf:** rejected; the richer styling is not
  worth the cairo/pango/system-Chromium dependencies for a self-hosted appliance
  and CI. fpdf2 covers the structured, sectioned reports the plan requires.
- **Rendering on download instead of storing bytes:** rejected; it breaks
  reproducibility (a re-render reflects the current database) and wastes work.
  The stored artifact is the source of truth; the database rows back new reports.
- **Signed, tokenized public download URLs:** deferred; organization-scoped
  authenticated download meets the requirement now. Time-boxed share links can be
  layered on later without changing storage.
