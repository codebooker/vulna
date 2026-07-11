# Terminology

Plain-English translations of the scanner and vulnerability language Vulna uses.

## Core concepts

- **Asset** — a device or host Vulna has seen on your network (identified by IP,
  hostname, or MAC). "198.51.100.10" is an asset.
- **Service** — something listening on an asset, like a web server on port 443 or
  SSH on port 22.
- **Finding** — a specific issue on an asset or service: a weak protocol, a
  missing patch, an exposed admin page. Findings have a severity and a status.
- **Scope** — the network ranges you have approved for assessment. Nothing is
  scanned outside an approved scope.
- **Scout** — a lightweight agent that does the actual scanning at a location. The
  dashboard coordinates one or more Scouts.
- **Preset** — a named, safe bundle of scan stages (for example "Standard" or
  "Fragile / IoT Safe"). You pick an outcome, not scanner flags.

## Severity and priority

- **Severity** — how bad the issue is in the abstract: info, low, medium, high,
  critical.
- **Priority** — what Vulna suggests you do about it now: **fix now**, **plan**,
  or **watch**. Priority combines severity with confidence and exploitation data,
  so a low-confidence critical is not pushed to "fix now".
- **KEV (Known Exploited Vulnerability)** — the issue is on CISA's list of
  vulnerabilities attackers are actively exploiting. Treat these urgently.
- **EPSS** — a probability score that a vulnerability will be exploited soon.
- **CVE** — a public identifier for a specific known vulnerability, like
  `CVE-2026-0001`.

## Scan language

- **Discovery** — finding which hosts are up and which ports are open (Nmap).
- **Service / version detection** — identifying what software a port is running.
- **Passive checks** — observing without sending intrusive traffic. Safe by
  default.
- **Active / intrusive checks** — sending traffic that could affect a target.
  These are off by default and gated behind approval.
- **TLS review** — checking certificate and protocol configuration (testssl.sh).
- **Web assessment** — passive or limited-active analysis of a web application
  (OWASP ZAP).

## Workflow language

- **Verification** — re-scanning just one finding to confirm a fix worked. A
  verified, no-longer-observed finding is auto-resolved.
- **Risk acceptance** — formally deciding to accept a finding for a time, with an
  expiry after which it reopens.
- **Change event** — something that changed since last time: a new open port, a
  service version change, a host that appeared or disappeared.
