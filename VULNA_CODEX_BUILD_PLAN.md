# Vulna — Detailed Codex Build Plan

> **Project name:** Vulna  
> **Purpose:** Build an open-source, self-hosted, distributed platform for vulnerability detection, authorized penetration testing, continuous CVE monitoring, and multi-location security assessment.  
> **Audience:** Codex or another coding agent, maintainers, security engineers, and contributors.  
> **Recommended license:** Apache-2.0 for broad adoption, or AGPL-3.0 if hosted modifications should remain open.  
> **Authorized use only:** The software must only assess systems and networks the operator owns or has explicit permission to test.

---

## 1. Product Vision

Vulna is a self-hosted security-assessment platform consisting of:

1. A **VulnaDash central orchestrator** installed with Docker Compose.
2. Lightweight **VulnaScout remote appliances** deployed at each location.
3. Secure, outbound-only communication between VulnaScouts and the orchestrator.
4. A plugin-based scanner framework using established open-source tools.
5. A central asset inventory, findings database, CVE intelligence service, remediation workflow, and reporting engine.

The target experience is:

```text
1. Install the orchestrator with Docker Compose.
2. Log in and create an organization and site.
3. Generate a one-time probe enrollment token.
4. Deploy the probe as a VM, Raspberry Pi, mini PC, or Linux service.
5. Enroll the probe.
6. Approve the networks that probe may assess.
7. Select a scan mode and profile.
8. Run or schedule an assessment.
9. Review assets, changes, vulnerabilities, validation evidence, and reports.
10. Assign remediation and automatically verify fixes.
```

## 1.1 Product Family and Component Names

Use the following names consistently in source code, documentation, release artifacts, and the user interface:

| Name | Purpose |
|---|---|
| **Vulna** | Overall project, product family, and GitHub organization/repository identity |
| **VulnaDash** | Self-hosted web application, API, scheduler, findings database, reporting controls, and central orchestration |
| **VulnaScout** | Remote assessment appliance deployed as a VM, mini PC, Raspberry Pi-class device, container, or Linux service |
| **VulnaWatch** | CVE, CISA KEV, EPSS, advisory, and vulnerability-intelligence synchronization and matching |
| **VulnaVerify** | Remediation workflow, targeted rescanning, resolution confirmation, reopen detection, and risk acceptance |
| **VulnaForge** | Scanner plugin SDK, adapter manifests, parser contracts, and community integration framework |
| **VulnaPulse** | Prometheus metrics, Grafana dashboards, alerting, health telemetry, and operational observability |
| **VulnaLab** | Isolated development, demonstration, integration-test, and intentionally vulnerable target environment |
| **VulnaReport** | PDF, CSV, JSON, report snapshot, redaction, and artifact-generation subsystem |

The public-facing installation should primarily expose **VulnaDash** and **VulnaScout**. The remaining names may initially represent feature areas or internal services and may later become independently deployable components.

The platform must support three primary assessment modes:

### 1.2 Vulnerability Detection Scan

A regular, mostly non-destructive production assessment that performs:

- Network discovery
- Port and service discovery
- Device and operating-system fingerprinting
- Safe vulnerability checks
- Web and TLS checks
- Optional credentialed inventory
- CVE matching
- CISA Known Exploited Vulnerabilities enrichment
- EPSS enrichment
- Findings prioritization
- Asset and service change detection

This mode must not intentionally create command shells, establish persistence, perform lateral movement, or extract real user data.

### 1.3 Controlled Penetration Test

An explicitly authorized assessment that attempts to validate whether selected weaknesses are genuinely exploitable.

It may perform:

- Deeper enumeration
- Active web application scanning
- Authentication validation with supplied credentials
- Selected auxiliary and validation modules
- Allowlisted exploit validation
- Limited proof-of-access collection
- Temporary session creation where explicitly approved
- Automatic cleanup and verification

This mode must not perform denial of service, destructive payloads, unrestricted credential attacks, persistence, malware installation, or indiscriminate exploitation.

### 1.4 Full-Spectrum Assessment

This is the formal name for the requested **“mac daddy all-in-one scan.”**

It is not a single uncontrolled command. It is a guarded workflow containing:

1. Authorization and safety preflight
2. Target reachability validation
3. Asset discovery
4. Port and service discovery
5. Device and operating-system fingerprinting
6. Vulnerability detection
7. Web and TLS analysis
8. Optional authenticated assessment
9. Controlled exploit validation
10. Limited post-validation evidence collection
11. Cleanup and session termination
12. Verification scan
13. Findings normalization and correlation
14. CVE, KEV, and EPSS enrichment
15. Risk prioritization
16. Executive PDF report
17. Technical PDF report
18. CSV and JSON data exports
19. Remediation workflow creation
20. Optional ticket-system synchronization

Intrusive stages must require stronger approvals and may be skipped while still completing the rest of the workflow.

---

## 2. Product Positioning

Do not build another vulnerability engine from scratch.

Vulna should be:

> An easy-to-deploy orchestration, safety, asset-correlation, evidence, remediation, and reporting layer around proven open-source security tools.

Primary differentiators:

- Simple Docker Compose orchestrator installation
- Lightweight ARM64 and x86-64 VulnaScouts
- Virtual-appliance and physical-drop-box support
- Outbound-only probe connectivity
- Local enforcement of approved target ranges
- No arbitrary remote shell
- Production-safe profiles for fragile devices
- Vulnerability assessment and controlled penetration testing in one platform
- Continuous CVE monitoring after scans finish
- Reports suitable for technical teams, management, auditors, and customers
- Historical asset and vulnerability change tracking
- Verification scans tied to remediation
- Open APIs and scanner plugins
- Self-hosted operation without a vendor cloud

---

## 3. Goals and Non-Goals

### 3.1 Initial public-release goals

The first stable release should include:

- Docker Compose orchestrator
- PostgreSQL
- Redis-backed task queue
- Web application and REST API
- Local authentication and role-based access
- VulnaScout enrollment and certificate lifecycle
- VulnaScout health monitoring
- Approved network scopes
- Manual and scheduled scans
- Vulnerability Detection mode
- Controlled Pentest mode with limited allowlisted validation
- Full-Spectrum workflow
- Nmap integration
- Nuclei integration
- OWASP ZAP integration
- testssl.sh integration
- Optional Metasploit RPC integration
- Asset and service inventory
- Findings normalization
- Continuous CVE intelligence
- CISA KEV and EPSS enrichment
- PDF, CSV, and JSON reports
- Remediation workflow
- Verification rescans
- Audit logs
- x86-64 and ARM64 VulnaScout packages
- Debian and Ubuntu installation scripts
- Containerized probe option
- Basic appliance-image build instructions

### 3.2 Later goals

- Greenbone/OpenVAS adapter
- Trivy adapter
- SSH and WinRM credentialed inventory
- SNMP enrichment
- Cloud inventory integrations
- OIDC and SAML
- Multi-tenant MSP mode
- High availability
- Passive network sensor integration
- Software bill of materials ingestion
- GLPI, Jira, ServiceNow, and other ticket integrations
- Signed automatic updates with rollback
- OVA, QCOW2, VHDX, and Raspberry Pi images
- Distributed report storage
- Prometheus and OpenTelemetry
- Offline or air-gapped intelligence bundles

### 3.3 Explicit non-goals

The initial releases must not automate:

- Denial-of-service testing
- Data destruction
- Persistence
- Ransomware simulation
- Unrestricted brute force
- Broad password spraying
- Credential dumping
- Endpoint security disabling
- Evasion intended to bypass monitoring
- Domain-wide lateral movement
- Arbitrary payload upload
- Real user-file exfiltration
- Unbounded exploit selection
- Internet-wide scanning
- Patch deployment
- Full SIEM functionality
- EDR functionality

---

## 4. Core Security Principles

### 4.1 Defense in depth

Every job must be validated:

1. In the web application
2. In the API service
3. In the scheduler
4. When signed
5. When received by the probe
6. Before each scanner stage
7. Before following redirects or discovered targets

### 4.2 Local target enforcement

Each probe stores a signed local policy containing:

- Approved CIDRs
- Denied CIDRs
- Whether public IP ranges are allowed
- Allowed assessment modes
- Allowed scanner plugins
- Maximum host count
- Maximum concurrency
- Packet-rate limits
- Maximum job duration
- Allowed web domains
- Redirect behavior
- DNS-resolution rules
- Credentialed-scan permissions
- Exploit-validation permissions

The probe must reject a job when:

- Any target is outside an approved range
- A DNS name resolves outside the allowed scope
- An HTTP redirect exits scope
- A discovered target is outside scope
- The job signature is invalid
- The job has expired
- The local policy is stale
- The requested profile is prohibited locally
- Resource or safety limits are exceeded
- The probe certificate is revoked

### 4.3 Outbound-only communication

The probe initiates all communication to the orchestrator over HTTPS with mutual TLS.

No inbound management ports should be required.

### 4.4 No arbitrary remote shell

The orchestrator must never accept or transmit an arbitrary command string for execution by the probe.

Plugins use:

- Versioned manifests
- Typed configuration
- Predefined executable paths or signed container images
- Allowlisted flags
- Strict timeouts
- Resource controls
- Output-size controls
- Environment-variable allowlists
- Sandboxed working directories

### 4.5 Strong approval model

Controlled Pentest and Full-Spectrum jobs require:

- Privileged user role
- Explicit authorization statement
- Rules-of-engagement selection
- Start and end window
- Target scope
- Named owner
- Emergency contact
- Business or technical contact
- Ticket or authorization reference
- Optional second-person approval
- Confirmation immediately before intrusive stages

### 4.6 Kill switch

Every active scan must be cancellable through:

- Web interface
- REST API
- Local probe CLI
- Optional local console
- Job expiration
- Automatic safety triggers

The probe must terminate scanner processes gracefully, then forcibly after a configurable timeout.

---

## 5. User Roles

Implement these initial roles:

### Administrator

- Full system access
- Manage users and roles
- Manage organizations and sites
- Enroll and revoke VulnaScouts
- Approve network scopes
- Configure scan profiles
- Configure CVE feeds
- Configure credentials
- Approve pentest jobs
- View all reports and audit logs

### Security Operator

- Run approved vulnerability scans
- Create schedules
- Review assets and findings
- Generate reports
- Create remediation tasks
- Request pentest approval
- Cannot alter trust settings or public-range policy

### Pentest Approver

- Approve or reject intrusive jobs
- Approve individual exploit-validation modules
- Review rules of engagement
- Stop active jobs
- View pentest evidence

### Remediation Owner

- View assigned findings
- Add notes
- Mark findings ready for verification
- Upload remediation evidence
- Request rescans

### Auditor

- Read-only access
- View reports, history, risk acceptances, and audit logs
- Export approved data
- Cannot start scans

### Viewer

- Dashboard and report access according to assigned sites

---

## 6. High-Level Architecture

```text
                                  ┌─────────────────────────────┐
                                  │        Web Browser          │
                                  └──────────────┬──────────────┘
                                                 │ HTTPS
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           VULNADASH CENTRAL ORCHESTRATOR                              │
│                                                                             │
│  ┌──────────────┐  ┌────────────────┐  ┌───────────────────────────────┐   │
│  │ Caddy        │─▶│ Web/API        │─▶│ Workflow and Queue Workers    │   │
│  │ TLS/Proxy    │  │ FastAPI        │  │ Scheduling/Normalization      │   │
│  └──────────────┘  └───────┬────────┘  └──────────────┬────────────────┘   │
│                             │                          │                    │
│                     ┌───────▼────────┐        ┌────────▼────────┐           │
│                     │ PostgreSQL     │        │ Redis           │           │
│                     │ Assets/Findings│        │ Queue/Cache     │           │
│                     └───────┬────────┘        └─────────────────┘           │
│                             │                                               │
│                     ┌───────▼────────┐        ┌─────────────────┐           │
│                     │ Report Service │        │ CVE Intelligence │           │
│                     │ PDF/CSV/JSON   │        │ NVD/KEV/EPSS     │           │
│                     └────────────────┘        └─────────────────┘           │
└───────────────────────────────┬─────────────────────────────────────────────┘
                                │ Outbound HTTPS + mTLS
           ┌────────────────────┼─────────────────────┐
           │                    │                     │
           ▼                    ▼                     ▼
  ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
  │ VulnaScout Site A   │   │ VulnaScout Site B   │   │ VulnaScout Site C   │
  │ Mini PC        │   │ Raspberry Pi   │   │ Virtual Machine│
  │ Local Policy   │   │ Local Policy   │   │ Local Policy   │
  │ Scanner Plugins│   │ Scanner Plugins│   │ Scanner Plugins│
  └───────┬────────┘   └───────┬────────┘   └───────┬────────┘
          │                    │                    │
          ▼                    ▼                    ▼
     Approved CIDRs       Approved CIDRs       Approved CIDRs
```

---

## 7. Recommended Technology Stack

### 7.1 Backend

Recommended:

- Python 3.12+
- FastAPI
- SQLAlchemy 2.x
- Alembic
- Pydantic
- PostgreSQL
- Redis
- Celery or Dramatiq
- Pytest
- OpenAPI generated by FastAPI
- WebSockets or Server-Sent Events for live job updates

Alternative implementations are acceptable, but preserve the service boundaries.

### 7.2 Frontend

- React
- TypeScript
- Vite
- React Router
- TanStack Query
- TanStack Table
- React Hook Form
- Zod
- Recharts or Apache ECharts
- Playwright
- Vitest
- Accessible UI components such as shadcn/ui

### 7.3 VulnaScout agent

- Go
- Single statically linked binary where possible
- systemd service
- YAML configuration with environment overrides
- SQLite for local durable state
- HTTPS with mutual TLS
- Structured JSON logging
- Child-process isolation
- Linux cgroups or container resource limits
- Cross-compilation for `linux/amd64` and `linux/arm64`

### 7.4 Reverse proxy

Default to Caddy for simple TLS configuration.

### 7.5 Reporting

Recommended:

- Jinja2 HTML templates
- WeasyPrint for HTML-to-PDF generation
- Python `csv` module or Pandas only where useful
- Object storage abstraction for report artifacts
- Local filesystem storage in the MVP
- Optional S3-compatible storage later

### 7.6 Scanner tools

Initial adapters:

- Nmap
- Nuclei
- OWASP ZAP
- testssl.sh
- Optional Metasploit Framework RPC

Later adapters:

- Greenbone/OpenVAS
- Trivy
- Nikto
- Lynis
- Scout Suite
- Prowler
- Custom organization plugins

---

## 8. Repository Layout

```text
vulna/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── CHANGELOG.md
├── Makefile
├── .env.example
├── docker-compose.yml
├── docker-compose.dev.yml
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── authorized-use.md
│   ├── rules-of-engagement.md
│   ├── installation/
│   ├── administration/
│   ├── development/
│   └── reporting/
├── dash/                         # VulnaDash
│   ├── backend/
│   │   ├── app/
│   │   │   ├── api/
│   │   │   ├── auth/
│   │   │   ├── core/
│   │   │   ├── db/
│   │   │   ├── intelligence/
│   │   │   ├── models/
│   │   │   ├── reports/
│   │   │   ├── schemas/
│   │   │   ├── services/
│   │   │   ├── tasks/
│   │   │   ├── workflows/
│   │   │   └── main.py
│   │   ├── alembic/
│   │   ├── tests/
│   │   ├── pyproject.toml
│   │   └── Dockerfile
│   └── frontend/
│       ├── src/
│       │   ├── api/
│       │   ├── components/
│       │   ├── features/
│       │   ├── pages/
│       │   ├── routes/
│       │   └── types/
│       ├── tests/
│       ├── package.json
│       └── Dockerfile
├── scout/                        # VulnaScout
│   ├── cmd/vulnascout/
│   ├── internal/
│   │   ├── api/
│   │   ├── config/
│   │   ├── enrollment/
│   │   ├── executor/
│   │   ├── policy/
│   │   ├── queue/
│   │   ├── scanners/
│   │   ├── storage/
│   │   ├── telemetry/
│   │   └── updater/
│   ├── plugins/
│   │   ├── nmap/
│   │   ├── nuclei/
│   │   ├── zap/
│   │   ├── testssl/
│   │   └── metasploit/
│   ├── packaging/
│   │   ├── deb/
│   │   ├── docker/
│   │   ├── systemd/
│   │   ├── cloud-init/
│   │   └── appliance/
│   ├── tests/
│   ├── go.mod
│   └── Dockerfile
├── watch/                        # VulnaWatch intelligence workers
├── verify/                       # VulnaVerify remediation logic
├── forge/                        # VulnaForge plugin SDK and schemas
├── pulse/                        # VulnaPulse dashboards and metrics
├── lab/                          # VulnaLab integration environment
├── shared/
│   ├── schemas/
│   │   ├── job.schema.json
│   │   ├── result.schema.json
│   │   ├── plugin.schema.json
│   │   └── policy.schema.json
│   └── examples/
├── scripts/
│   ├── install-orchestrator.sh
│   ├── install-probe.sh
│   ├── backup.sh
│   ├── restore.sh
│   └── build-appliance.sh
└── .github/
    ├── workflows/
    ├── ISSUE_TEMPLATE/
    └── pull_request_template.md
```

---

## 9. Core Data Model

All tables must include UUID primary keys, creation timestamps, update timestamps where appropriate, and organization ownership where applicable.

### 9.1 Organization

Fields:

- `id`
- `name`
- `slug`
- `default_timezone`
- `settings_json`
- `retention_policy_json`
- `created_at`
- `updated_at`

The MVP may expose only one organization but must preserve organization boundaries in the schema.

### 9.2 Site

Fields:

- `id`
- `organization_id`
- `name`
- `code`
- `description`
- `address`
- `timezone`
- `business_owner`
- `technical_owner`
- `tags`
- `created_at`
- `updated_at`

### 9.3 Probe

Fields:

- `id`
- `organization_id`
- `site_id`
- `name`
- `description`
- `status`
- `certificate_fingerprint`
- `agent_version`
- `operating_system`
- `architecture`
- `hostname`
- `primary_ip`
- `capabilities_json`
- `health_json`
- `policy_hash`
- `last_seen_at`
- `last_job_at`
- `enrolled_at`
- `disabled_at`
- `upgrade_channel`

Statuses:

- `pending_enrollment`
- `online`
- `offline`
- `degraded`
- `disabled`
- `revoked`

### 9.4 Network Scope

Fields:

- `id`
- `organization_id`
- `site_id`
- `probe_id`
- `name`
- `cidr`
- `enabled`
- `allow_public_addresses`
- `approved_by`
- `approved_at`
- `expires_at`
- `maximum_hosts`
- `maximum_packets_per_second`
- `maximum_concurrency`
- `notes`
- `policy_version`

Requirements:

- Normalize CIDRs
- Detect overlaps
- Reject `0.0.0.0/0` and `::/0`
- Reject public ranges by default
- Revalidate DNS targets at execution time
- Record every policy change in the audit log

### 9.5 Scan Profile

Fields:

- `id`
- `organization_id`
- `name`
- `mode`
- `description`
- `risk_level`
- `workflow_definition_json`
- `plugin_configuration_json`
- `maximum_hosts`
- `maximum_parallel_hosts`
- `maximum_packets_per_second`
- `maximum_duration_seconds`
- `requires_approval`
- `requires_dual_approval`
- `fragile_device_safe`
- `built_in`
- `version`
- `enabled`

### 9.6 Rules of Engagement

Fields:

- `id`
- `organization_id`
- `name`
- `allowed_actions_json`
- `prohibited_actions_json`
- `allowed_hours_json`
- `emergency_contact`
- `business_contact`
- `evidence_policy_json`
- `data_retention_days`
- `session_policy_json`
- `cleanup_required`
- `created_by`
- `approved_by`
- `version`

### 9.7 Scan Schedule

Fields:

- `id`
- `site_id`
- `probe_id`
- `profile_id`
- `target_scope_ids`
- `cron_expression`
- `timezone`
- `enabled`
- `next_run_at`
- `last_run_at`
- `created_by`

Pentest schedules should be disabled by default. Scheduled intrusive jobs require an unexpired standing authorization.

### 9.8 Scan Job

Fields:

- `id`
- `organization_id`
- `site_id`
- `probe_id`
- `profile_id`
- `rules_of_engagement_id`
- `requested_targets_json`
- `normalized_targets_json`
- `mode`
- `status`
- `priority`
- `created_by`
- `approved_by`
- `second_approved_by`
- `authorization_reference`
- `created_at`
- `not_before`
- `expires_at`
- `started_at`
- `finished_at`
- `cancel_requested_at`
- `job_signature`
- `policy_version`
- `error_code`
- `error_message`
- `summary_json`

Statuses:

- `draft`
- `awaiting_approval`
- `queued`
- `offered`
- `accepted`
- `running`
- `paused_for_approval`
- `uploading`
- `processing`
- `reporting`
- `completed`
- `partially_completed`
- `failed`
- `cancelled`
- `expired`
- `rejected_by_probe`

### 9.9 Scan Stage

Fields:

- `id`
- `scan_job_id`
- `stage_type`
- `sequence_number`
- `status`
- `plugin_name`
- `started_at`
- `finished_at`
- `exit_code`
- `summary_json`
- `error_message`
- `approval_required`
- `approved_by`

### 9.10 Asset

Fields:

- `id`
- `organization_id`
- `site_id`
- `canonical_name`
- `asset_type`
- `criticality`
- `business_owner`
- `technical_owner`
- `first_seen_at`
- `last_seen_at`
- `last_assessed_at`
- `status`
- `identity_confidence`
- `operating_system`
- `manufacturer`
- `model`
- `serial_number`
- `tags_json`
- `metadata_json`

Asset types:

- workstation
- server
- network_device
- printer
- camera
- phone
- storage
- hypervisor
- virtual_machine
- cloud_instance
- IoT
- embedded
- web_application
- unknown

### 9.11 Asset Identifier

Fields:

- `id`
- `asset_id`
- `identifier_type`
- `identifier_value`
- `confidence`
- `first_seen_at`
- `last_seen_at`

Types include:

- IP address
- MAC address
- hostname
- FQDN
- SMB name
- SSH host key
- TLS certificate fingerprint
- SNMP engine ID
- cloud instance ID
- agent ID

### 9.12 Service

Fields:

- `id`
- `asset_id`
- `transport`
- `port`
- `protocol`
- `service_name`
- `product`
- `version`
- `cpe`
- `banner_hash`
- `tls_certificate_id`
- `first_seen_at`
- `last_seen_at`
- `state`

### 9.13 CVE Record

Fields:

- `cve_id`
- `published_at`
- `modified_at`
- `description`
- `cvss_v2_json`
- `cvss_v3_json`
- `cvss_v4_json`
- `cwe_ids_json`
- `cpe_matches_json`
- `references_json`
- `source`
- `rejected`
- `last_synced_at`

### 9.14 Threat Intelligence Enrichment

Fields:

- `cve_id`
- `is_kev`
- `kev_date_added`
- `kev_due_date`
- `kev_required_action`
- `known_ransomware_use`
- `epss_score`
- `epss_percentile`
- `epss_date`
- `public_exploit_available`
- `exploit_reference_json`
- `last_enriched_at`

Do not automatically execute public exploit code because it exists.

### 9.15 Finding

Fields:

- `id`
- `organization_id`
- `site_id`
- `asset_id`
- `service_id`
- `scan_job_id`
- `scanner_name`
- `scanner_finding_id`
- `canonical_finding_key`
- `finding_type`
- `title`
- `description`
- `severity`
- `cvss_score`
- `cvss_vector`
- `cve_ids_json`
- `cwe_ids_json`
- `known_exploited`
- `epss_score`
- `epss_percentile`
- `confidence`
- `validation_status`
- `validation_method`
- `evidence_json`
- `remediation`
- `references_json`
- `first_seen_at`
- `last_seen_at`
- `last_verified_at`
- `status`
- `owner_user_id`
- `due_at`
- `risk_acceptance_id`
- `false_positive_reason`
- `resolved_at`
- `reopened_count`

Finding types:

- vulnerability
- misconfiguration
- weak_protocol
- exposed_service
- default_credential
- missing_patch
- unsupported_software
- web_application_issue
- credentialed_configuration_issue
- validated_exploitability
- informational

Validation states:

- unvalidated
- likely
- confirmed_non_exploit
- confirmed_exploitable
- inconclusive
- not_applicable

Workflow states:

- new
- triage
- validated
- assigned
- remediation_in_progress
- ready_for_verification
- resolved
- reopened
- risk_accepted
- false_positive
- duplicate
- suppressed

### 9.16 Evidence Artifact

Fields:

- `id`
- `scan_job_id`
- `finding_id`
- `artifact_type`
- `storage_path`
- `sha256`
- `content_type`
- `size_bytes`
- `redaction_status`
- `encryption_status`
- `created_at`
- `expires_at`

Evidence must be encrypted at rest and access-controlled.

### 9.17 Change Event

Events include:

- asset discovered
- asset disappeared
- IP changed
- new port opened
- port closed
- service version changed
- TLS certificate changed
- new vulnerability
- CVE severity changed
- CVE added to KEV
- EPSS threshold crossed
- finding remediated
- finding reopened
- probe offline
- scope changed

### 9.18 Report

Fields:

- `id`
- `organization_id`
- `site_id`
- `scan_job_id`
- `report_type`
- `format`
- `status`
- `template_version`
- `storage_path`
- `sha256`
- `generated_by`
- `generated_at`
- `expires_at`
- `parameters_json`

### 9.19 Risk Acceptance

Fields:

- `id`
- `finding_id`
- `requested_by`
- `approved_by`
- `reason`
- `compensating_controls`
- `starts_at`
- `expires_at`
- `status`
- `review_notes`

Risk acceptances should expire by default.

### 9.20 Audit Event

Fields:

- `id`
- `organization_id`
- `actor_type`
- `actor_id`
- `action`
- `target_type`
- `target_id`
- `source_ip`
- `user_agent`
- `request_id`
- `metadata_json`
- `created_at`

Application-level audit logs must be append-only.

---

## 10. Probe Enrollment

### 10.1 Workflow

1. Administrator creates a site.
2. Administrator selects **Add Probe**.
3. Server creates a one-time token, short code, and expiration.
4. Probe generates a private key locally.
5. Probe sends a certificate-signing request with the token.
6. Server validates and consumes the token.
7. Server issues a client certificate.
8. Probe stores:
   - Private key
   - Client certificate
   - Server CA
   - Probe ID
   - Site ID
9. Probe starts heartbeat communication.
10. Administrator approves the probe and network scopes.
11. Server delivers a signed local policy.
12. Probe stores the policy and reports its hash.

### 10.2 Security requirements

- Enrollment tokens expire in 15 minutes by default
- Tokens are single-use
- Tokens are stored hashed
- Private keys never leave the probe
- Client certificates have bounded validity
- Certificate rotation is automatic
- Revocation is checked during heartbeat
- Enrollment logs include actor, source IP, and site
- Duplicate probe identities are rejected

---

## 11. VulnaScout Communication Protocol

Prefer a pull model over an always-open command channel.

### 11.1 Heartbeat

Probe calls:

```http
POST /api/v1/probes/{probe_id}/heartbeat
```

Payload includes:

```json
{
  "agent_version": "0.1.0",
  "hostname": "probe-site-a",
  "operating_system": "debian-13",
  "architecture": "amd64",
  "capabilities": ["nmap", "nuclei", "zap", "testssl"],
  "health": {
    "cpu_percent": 12.4,
    "memory_percent": 31.2,
    "disk_free_bytes": 9912345678,
    "load_average": [0.14, 0.18, 0.21]
  },
  "active_job_id": null,
  "policy_hash": "sha256..."
}
```

Response includes:

- Server time
- Certificate status
- Policy update information
- Agent update information
- Pending job count
- Cancellation requests

### 11.2 Job polling

```http
POST /api/v1/probes/{probe_id}/jobs/next
```

The server returns either no job or a signed job envelope.

### 11.3 Job envelope

```json
{
  "job_id": "uuid",
  "probe_id": "uuid",
  "site_id": "uuid",
  "mode": "vulnerability_assessment",
  "profile_version": 4,
  "policy_version": 12,
  "not_before": "2026-07-10T01:00:00Z",
  "expires_at": "2026-07-10T05:00:00Z",
  "targets": ["10.20.0.0/24"],
  "workflow": [
    {"stage": "discovery", "plugin": "nmap", "config": {}},
    {"stage": "vulnerability", "plugin": "nuclei", "config": {}}
  ],
  "limits": {
    "max_hosts": 256,
    "max_parallel_hosts": 8,
    "max_packets_per_second": 1000,
    "max_duration_seconds": 10800
  },
  "signature": "base64-signature"
}
```

### 11.4 Result upload

Support chunked, resumable result uploads.

```http
POST /api/v1/probes/{probe_id}/jobs/{job_id}/results
```

Every chunk includes:

- Sequence number
- Content hash
- Compression type
- Result schema version
- Scanner name and version
- Stage ID

The server must acknowledge durable receipt.

### 11.5 Offline resilience

The probe must use a local SQLite queue and preserve:

- Accepted jobs
- Stage state
- Raw outputs
- Normalized results
- Upload progress
- Cancellation state
- Policy version

After restart, the probe must resume safely or mark the stage interrupted.

---

## 12. VulnaForge — Plugin Framework

### 12.1 Plugin manifest

Each plugin contains a signed manifest:

```yaml
name: nmap
version: 1.0.0
runner: process
executable: /usr/bin/nmap
supported_architectures:
  - amd64
  - arm64
capabilities:
  - discovery
  - port_scan
  - service_detection
allowed_arguments:
  - name: timing
    type: enum
    values: [T2, T3, T4]
  - name: top_ports
    type: integer
    minimum: 1
    maximum: 65535
timeout_seconds: 7200
output:
  format: nmap_xml
  parser: builtin_nmap_xml
resource_limits:
  memory_mb: 1024
  cpu_percent: 100
```

### 12.2 Plugin requirements

Every adapter must implement:

- Capability discovery
- Configuration validation
- Target validation
- Command generation from typed inputs
- Safe default settings
- Cancellation
- Timeout handling
- Raw-output preservation
- Structured-output parsing
- Normalized result creation
- Version reporting
- Health test
- Unit tests
- Integration tests against lab targets

### 12.3 Nmap adapter

Responsibilities:

- ARP discovery for local networks
- ICMP and conservative TCP discovery
- TCP port scanning
- Optional UDP profile
- Service and version detection
- OS fingerprinting
- XML output
- Host and service normalization

Never allow arbitrary NSE script expressions from web input. Expose curated script groups through the plugin manifest.

### 12.4 Nuclei adapter

Responsibilities:

- Use JSONL output
- Pin or record template versions
- Maintain safe, intrusive, and prohibited template classifications
- Allow only approved template sets
- Record template ID, severity, matcher evidence, and references
- Reject templates containing prohibited behavior
- Support custom organization templates through a review process
- Verify template signatures where supported

Template policy categories:

- safe
- active
- intrusive
- prohibited
- lab_only

### 12.5 OWASP ZAP adapter

Profiles:

- Passive baseline
- Authenticated passive
- Limited active
- Full active, approval required

Use the ZAP Automation Framework with generated YAML.

Controls:

- Approved starting URLs
- In-scope domains and IPs
- Redirect restrictions
- Crawl limits
- Request-per-second limits
- Maximum depth
- Maximum duration
- Authentication context
- Excluded URLs
- Active-rule allowlist

### 12.6 testssl.sh adapter

Responsibilities:

- TLS protocol detection
- Cipher analysis
- Certificate analysis
- Security-header observations
- JSON output parsing
- Conservative connection limits

### 12.7 Metasploit adapter

Metasploit integration must be optional and disabled by default.

Architecture:

- A local Metasploit service runs on the probe or a dedicated worker.
- The probe communicates through the documented RPC interface.
- The orchestrator never receives direct RPC credentials.
- The adapter exposes only allowlisted modules.
- Modules are mapped to typed parameters.
- Module metadata includes reliability, side effects, supported targets, cleanup expectations, and evidence output.
- Denial-of-service modules are categorically blocked.
- Payloads are limited to approved proof-of-access payloads.
- Sessions have maximum lifetime and automatic termination.
- Generated artifacts are tracked and deleted.
- Every module run requires a matching target finding or explicit approval.

Module policy record:

```yaml
module: exploit/example/module
enabled: false
mode: controlled_pentest
minimum_rank: excellent
allowed_payloads:
  - cmd/unix/generic
requires_second_approval: true
cleanup_required: true
max_session_seconds: 120
prohibited_options:
  - arbitrary_command
```

Do not include exploit-specific module lists in the default repository. Maintain a reviewed policy pack separately or begin with auxiliary validation modules only.

---

## 13. Assessment Workflows

### 13.1 Vulnerability Detection workflow

```text
PRECHECK
  ↓
DISCOVERY
  ↓
PORT_AND_SERVICE_SCAN
  ↓
DEVICE_CLASSIFICATION
  ↓
SAFE_VULNERABILITY_CHECKS
  ↓
WEB_AND_TLS_CHECKS
  ↓
OPTIONAL_CREDENTIALED_CHECKS
  ↓
NORMALIZATION
  ↓
CVE_ENRICHMENT
  ↓
CORRELATION_AND_DEDUPLICATION
  ↓
REPORTING
  ↓
REMEDIATION_TASKS
```

### 13.2 Controlled Pentest workflow

```text
AUTHORIZATION_PRECHECK
  ↓
DISCOVERY_AND_ENUMERATION
  ↓
VULNERABILITY_ASSESSMENT
  ↓
CANDIDATE_VALIDATION_PLAN
  ↓
APPROVAL_GATE
  ↓
ALLOWLISTED_VALIDATION
  ↓
EVIDENCE_COLLECTION
  ↓
SESSION_TERMINATION
  ↓
CLEANUP
  ↓
VERIFICATION_SCAN
  ↓
REPORTING
```

### 13.3 Full-Spectrum workflow

```text
1. Confirm authorization
2. Confirm VulnaScout health
3. Confirm maintenance window
4. Validate target scope
5. Discover assets
6. Identify ports and services
7. Fingerprint devices and applications
8. Classify fragile assets
9. Run safe vulnerability checks
10. Run web baseline checks
11. Run TLS checks
12. Run credentialed checks when configured
13. Correlate likely vulnerabilities
14. Build validation candidate list
15. Pause for approval when required
16. Execute approved validation modules
17. Collect minimum proof necessary
18. Terminate sessions
19. Remove temporary artifacts
20. Run verification scan
21. Normalize and deduplicate findings
22. Update CVE/KEV/EPSS metadata
23. Calculate risk priority
24. Generate executive PDF
25. Generate technical PDF
26. Generate findings CSV
27. Generate asset CSV
28. Generate service CSV
29. Generate JSON bundle
30. Create remediation tasks
```

### 13.4 Stage conditions

Workflows must support:

- conditional stages
- approval gates
- retry policies
- per-stage timeouts
- failure continuation rules
- cancellation
- partial completion
- resume after interruption
- safe-mode downgrade

Example:

```yaml
- id: exploit_validation
  plugin: metasploit
  run_if:
    all:
      - job.mode in ["controlled_pentest", "full_spectrum"]
      - job.approval.validation_stage == true
      - candidates.count > 0
  on_failure: continue_with_warning
  timeout_seconds: 3600
```

---

## 14. VulnaWatch — Continuous CVE Monitoring

CVE monitoring is a core subsystem, not a report-only feature.

The central server must maintain a local vulnerability-intelligence database and continuously compare new intelligence against known assets, services, software, and existing findings.

### 14.1 Required data sources

Initial supported sources:

- NVD CVE API
- CISA Known Exploited Vulnerabilities catalog
- FIRST EPSS API or daily data
- Scanner template metadata
- Optional vendor advisory feeds
- Optional OS security feeds

### 14.2 Synchronization jobs

Create background tasks for:

- Incremental NVD CVE updates
- CISA KEV refresh
- Daily EPSS refresh
- Scanner-template update inventory
- CPE dictionary refresh
- Feed health monitoring
- Failed-sync retries
- Stale-feed warnings

Default schedules:

- NVD incremental sync every 2 hours
- CISA KEV sync every 1 hour
- EPSS sync daily
- Nuclei template inventory daily
- Full consistency check weekly

Make frequencies configurable and respect upstream rate limits.

### 14.3 CVE matching

Match CVEs to assets using multiple confidence levels:

#### High confidence

- Credentialed package inventory
- Exact product and version
- Exact CPE
- Scanner-confirmed vulnerability
- Vendor-specific detection

#### Medium confidence

- Strong service fingerprint
- Product and version inferred from banner
- Web technology fingerprint

#### Low confidence

- Generic product family
- Operating-system estimate
- Unverified banner

Do not present low-confidence CPE matches as confirmed vulnerabilities.

### 14.4 CVE watch behavior

When a new or modified CVE matches an existing asset:

1. Create or update a finding.
2. Mark the source as `continuous_cve_monitor`.
3. Record why the match occurred.
4. Assign a confidence score.
5. Enrich with CVSS, KEV, and EPSS.
6. Notify according to policy.
7. Optionally schedule a targeted verification scan.
8. Preserve the prior metadata for audit history.

### 14.5 KEV monitoring

When an existing CVE is added to CISA KEV:

- Raise the finding priority
- Create a change event
- Alert assigned owners
- Show the KEV date added
- Show required action and due date
- Flag known ransomware use when available
- Optionally shorten remediation SLA
- Include the change in daily and weekly digests

### 14.6 EPSS monitoring

Store:

- Current EPSS score
- Current percentile
- Score date
- Previous score
- Threshold-crossing history

Configurable thresholds may trigger:

- Priority increases
- Notifications
- Targeted verification scans
- Report annotations

### 14.7 Feed status dashboard

Show:

- Source name
- Last successful sync
- Last attempted sync
- Records processed
- Records changed
- Error status
- Current lag
- API rate-limit status
- Local database size

### 14.8 Air-gapped operation

Later support signed offline feed bundles:

- Export bundle from an Internet-connected system
- Verify signature
- Import NVD, KEV, EPSS, and template metadata
- Record bundle creation and import times

---

## 15. Risk Prioritization

Do not rank findings only by CVSS.

Calculate a configurable priority score using:

- Severity
- CVSS
- CISA KEV status
- EPSS probability and percentile
- Validation status
- Internet exposure
- Asset criticality
- Service exposure
- Authentication required
- Compensating controls
- Finding age
- Ransomware-use indicator
- Remediation availability
- Reopened status

Example conceptual formula:

```text
priority =
  severity_weight
  + kev_weight
  + epss_weight
  + confirmed_exploitability_weight
  + exposure_weight
  + asset_criticality_weight
  + age_weight
  - compensating_control_weight
```

Store the inputs and reason text so the score is explainable.

Priority labels:

- Emergency
- Critical
- High
- Medium
- Low
- Informational

---

## 16. VulnaReport — Reporting Requirements

Every completed scan must be able to generate PDF, CSV, and JSON outputs.

### 16.1 Report types

#### Executive PDF

Audience:

- Executives
- Department managers
- Customers
- Auditors

Contents:

- Cover page
- Organization and site
- Assessment dates
- Scope summary
- Assessment mode
- Authorization reference
- Overall risk rating
- Key findings
- Critical and high finding counts
- KEV findings
- Confirmed exploitable findings
- Asset coverage
- Comparison with previous assessment
- Top remediation priorities
- Limitations
- Plain-language conclusion

#### Technical PDF

Audience:

- IT
- Security
- System owners
- Consultants

Contents:

- Assessment metadata
- Probe and scanner versions
- Target scopes
- Rules of engagement
- Scan profiles
- Stage timeline
- Asset inventory summary
- Port and service inventory
- Findings by severity
- Detailed finding sections
- CVE, CVSS, KEV, and EPSS information
- Validation status
- Sanitized evidence
- Remediation guidance
- Affected assets
- Verification status
- False positives and accepted risks
- Scanner errors and coverage gaps
- Appendices
- Report checksum

#### Penetration-Test PDF

Contents:

- Executive summary
- Rules of engagement
- Testing window
- Scope
- Methodology
- Attack-path narrative where applicable
- Validated weaknesses
- Proof of access
- Business impact
- Cleanup confirmation
- Retest results
- Technical findings
- Limitations
- Signature/approval section

#### Full-Spectrum PDF

Combines:

- Executive summary
- Vulnerability-assessment results
- Validation results
- Asset and exposure changes
- CVE intelligence
- Remediation roadmap
- Verification and cleanup summary

#### Delta Report

Compares two scan jobs:

- New assets
- Removed assets
- New ports
- Closed ports
- Changed service versions
- New findings
- Resolved findings
- Reopened findings
- Newly KEV-listed findings
- EPSS threshold changes
- Risk-score changes

### 16.2 CSV exports

Generate separate CSV files:

#### `findings.csv`

Columns:

- organization
- site
- scan_id
- asset_id
- asset_name
- IP addresses
- service
- port
- protocol
- finding_id
- title
- finding_type
- severity
- priority
- CVSS score
- CVSS vector
- CVE IDs
- KEV status
- EPSS score
- EPSS percentile
- validation status
- confidence
- first seen
- last seen
- status
- owner
- due date
- remediation
- references
- risk acceptance expiration

#### `assets.csv`

Columns:

- site
- asset ID
- canonical name
- asset type
- IP addresses
- MAC addresses
- hostnames
- operating system
- manufacturer
- model
- criticality
- first seen
- last seen
- last assessed
- status
- open port count
- critical finding count
- high finding count
- tags

#### `services.csv`

Columns:

- asset ID
- asset name
- IP address
- transport
- port
- service
- product
- version
- CPE
- TLS certificate subject
- first seen
- last seen
- state

#### `cve_exposure.csv`

Columns:

- CVE ID
- asset ID
- asset
- service
- confidence
- CVSS
- KEV
- KEV date added
- ransomware indicator
- EPSS
- EPSS percentile
- first detected
- validation status
- remediation status

#### `changes.csv`

Columns:

- timestamp
- site
- asset
- event type
- severity
- summary
- before
- after
- related scan

### 16.3 JSON export

Create one versioned JSON bundle containing:

- Scan metadata
- Sites and scopes
- Probe information
- Scanner versions
- Assets
- Services
- Findings
- Evidence metadata
- CVE enrichment
- Changes
- Remediation states
- Report metadata

Publish and test a JSON Schema.

### 16.4 Report generation pipeline

1. User requests report or automatic report policy triggers.
2. Server snapshots relevant database records.
3. Report worker renders HTML.
4. HTML is converted to PDF.
5. CSV and JSON exports are produced.
6. Sensitive evidence is redacted according to policy.
7. SHA-256 checksums are calculated.
8. Artifacts are stored.
9. Report record is updated.
10. User receives a download link.

Reports should be reproducible from a stored snapshot even if findings later change.

### 16.5 Branding

Support:

- Organization logo
- Report title
- Primary contact
- Footer text
- Confidentiality marking
- Page numbering
- Optional consultant branding

Never embed external images at report-generation time. Store approved branding locally.

### 16.6 Report security

- Authorization checks on every download
- Signed, expiring download URLs
- Encryption at rest
- Configurable retention
- Redaction policy
- Audit every generation and download
- Mark reports confidential by default
- Avoid embedding usable secrets
- Store checksums

---

## 17. Orchestrator Docker Compose

Create a production-oriented `docker-compose.yml` with:

- Caddy
- API
- Frontend
- Worker
- Scheduler
- PostgreSQL
- Redis
- Report worker
- Optional MinIO profile
- Optional Metasploit service disabled by default

Illustrative structure:

```yaml
services:
  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./deploy/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      api:
        condition: service_healthy
      frontend:
        condition: service_healthy

  frontend:
    image: ghcr.io/example/vulna-dash-frontend:${VULNA_VERSION:-latest}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 5

  api:
    image: ghcr.io/example/vulna-dash-api:${VULNA_VERSION:-latest}
    restart: unless-stopped
    env_file: .env
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - reports:/var/lib/vulna/reports
      - evidence:/var/lib/vulna/evidence
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:8000/health"]
      interval: 30s
      timeout: 5s
      retries: 5

  worker:
    image: ghcr.io/example/vulna-dash-api:${VULNA_VERSION:-latest}
    command: ["vulna", "worker"]
    restart: unless-stopped
    env_file: .env
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  scheduler:
    image: ghcr.io/example/vulna-dash-api:${VULNA_VERSION:-latest}
    command: ["vulna", "scheduler"]
    restart: unless-stopped
    env_file: .env

  report-worker:
    image: ghcr.io/example/vulna-report:${VULNA_VERSION:-latest}
    restart: unless-stopped
    env_file: .env
    volumes:
      - reports:/var/lib/vulna/reports
      - evidence:/var/lib/vulna/evidence

  postgres:
    image: postgres:17
    restart: unless-stopped
    environment:
      POSTGRES_DB: vulna
      POSTGRES_USER: vulna
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vulna -d vulna"]
      interval: 10s
      timeout: 5s
      retries: 10

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: ["redis-server", "--appendonly", "yes"]
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 10

volumes:
  postgres_data:
  redis_data:
  reports:
  evidence:
  caddy_data:
  caddy_config:
```

The final Compose file must:

- Pin supported major versions
- Include health checks
- Use restart policies
- Avoid unnecessary exposed ports
- Use secrets where possible
- Document backups
- Document upgrades
- Support an external database configuration
- Support HTTP-only local lab mode
- Support TLS production mode

---

## 18. VulnaScout Installation and Appliance Design

### 18.1 Supported operating systems

Initial:

- Debian 12 or newer
- Ubuntu Server 24.04 LTS or newer
- Raspberry Pi OS 64-bit where dependencies are available

### 18.2 Hardware tiers

#### Discovery tier

- 2 CPU cores
- 2 GB RAM
- 16 GB storage
- Nmap only

#### Standard assessment tier

- 2 to 4 CPU cores
- 4 GB RAM
- 32 GB storage
- Nmap, Nuclei, testssl.sh

#### Full assessment tier

- 4 CPU cores recommended
- 8 GB RAM recommended
- 64 GB storage
- Nmap, Nuclei, ZAP
- Optional Metasploit

Low-power hardware may run one heavy stage at a time.

### 18.3 Filesystem layout

```text
/etc/vulna/
  agent.yaml
  policy.json
  certificates/

/var/lib/vulna/
  state.db
  jobs/
  results/
  evidence/
  plugins/
  updates/

/var/log/vulna/
  agent.jsonl
```

### 18.4 systemd hardening

Use:

- `NoNewPrivileges=true`
- `PrivateTmp=true`
- `ProtectSystem=strict`
- `ProtectHome=true`
- `RestrictAddressFamilies=`
- `CapabilityBoundingSet=`
- `AmbientCapabilities=`
- `ReadWritePaths=`
- `MemoryMax=`
- `CPUQuota=`
- `TasksMax=`

Grant raw-socket capabilities only to the scanner process or a narrowly scoped helper, not to the entire agent.

### 18.5 VulnaScout CLI

Commands:

```text
vulnascout enroll
vulnascout status
vulnascout diagnostics
vulnascout policy show
vulnascout policy verify
vulnascout scan stop
vulnascout self-test
vulnascout update check
vulnascout logs
vulnascout reset
```

Reset must require explicit confirmation and preserve a local revocation/audit record where possible.

### 18.6 Local console

Provide a text-based status screen, not a shell exposed through the web portal.

Show:

- VulnaScout name
- Enrollment status
- IP addresses
- Server URL
- Last heartbeat
- Policy status
- Active job
- Scanner health
- Disk space
- Commands for diagnostics and emergency stop

---

## 19. Web Application Pages

### Dashboard

- Online/offline VulnaScouts
- Active jobs
- Assets by site
- Findings by severity
- KEV findings
- Confirmed exploitable findings
- Overdue remediation
- New assets
- New findings
- Recently resolved findings
- CVE feed health
- Risk trend

### Sites

- Site details
- Assigned VulnaScouts
- Network scopes
- Schedules
- Asset counts
- Findings
- Reports
- Site risk trend

### VulnaScouts

- Health
- Version
- Capabilities
- Policy hash
- Last heartbeat
- Active job
- Recent jobs
- Logs and diagnostics
- Certificate status
- Upgrade status
- Revoke action

### Scans

- New scan wizard
- Mode selection
- Profile selection
- Scope validation
- Authorization
- Approval status
- Live stage timeline
- Cancellation
- Partial results
- Report generation

### Assets

- Search and filter
- Asset details
- Identifiers
- IP history
- Services
- Findings
- Change history
- Criticality
- Ownership
- Tags

### Findings

- Severity
- Priority
- CVE
- KEV
- EPSS
- Validation
- Asset
- Site
- Owner
- Status
- Due date
- Age
- Evidence
- Remediation
- Verification

### CVE Intelligence

- Search CVEs
- New CVEs affecting known assets
- KEV changes
- EPSS changes
- Feed status
- Matching confidence
- Affected asset list
- Targeted rescan action

### Remediation

- Assigned findings
- SLA status
- Notes
- Evidence
- Risk acceptance
- Verification queue
- Reopened findings

### Reports

- Generate report
- Templates
- Completed reports
- Formats
- Retention
- Download audit
- Compare scans

### Administration

- Users
- Roles
- Authentication
- Organizations
- Scan profiles
- Rules of engagement
- Credentials
- Integrations
- CVE feeds
- Retention
- Branding
- Backups
- Audit log

---

## 20. REST API

Initial API groups:

```text
/api/v1/auth
/api/v1/users
/api/v1/organizations
/api/v1/sites
/api/v1/probes
/api/v1/scopes
/api/v1/profiles
/api/v1/rules-of-engagement
/api/v1/jobs
/api/v1/schedules
/api/v1/assets
/api/v1/services
/api/v1/findings
/api/v1/cves
/api/v1/intelligence
/api/v1/remediation
/api/v1/risk-acceptances
/api/v1/reports
/api/v1/audit
/api/v1/system
```

Requirements:

- OpenAPI
- Pagination
- Filtering
- Stable sorting
- Request IDs
- Idempotency keys for job creation
- Optimistic concurrency for edits
- Consistent error format
- Rate limiting
- API tokens with scopes
- Full authorization tests

Example job request:

```json
{
  "site_id": "uuid",
  "probe_id": "uuid",
  "profile_id": "uuid",
  "mode": "full_spectrum",
  "scope_ids": ["uuid"],
  "authorization_reference": "CHG-12345",
  "rules_of_engagement_id": "uuid",
  "not_before": "2026-07-11T02:00:00Z",
  "expires_at": "2026-07-11T08:00:00Z",
  "generate_reports": [
    "executive_pdf",
    "technical_pdf",
    "findings_csv",
    "assets_csv",
    "json_bundle"
  ]
}
```

---

## 21. Credentials

Credentialed assessments require a dedicated credential vault abstraction.

MVP:

- Encrypt secrets with an application master key
- Never return full secrets through the API
- Restrict credentials by site and scope
- Track last use
- Support expiration
- Audit creation, update, test, use, and deletion

Credential types:

- SSH key
- SSH username/password
- WinRM
- SMB
- SNMPv3
- HTTP basic
- Web form or ZAP context
- API token

Future:

- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- CyberArk

Never place credentials in generated reports or scanner command-line arguments when safer alternatives exist.

---

## 22. VulnaVerify — Asset, Finding, and Remediation Correlation

Do not use IP address as the sole asset key.

Build an asset identity engine using weighted evidence:

- MAC address
- Hostname
- FQDN
- SSH host key
- TLS certificate fingerprint
- SMB computer name
- SNMP engine ID
- Serial number
- Cloud instance ID
- Stable agent identifier
- Manufacturer/model
- Service fingerprint

The engine should:

- Propose merges
- Auto-merge only above a high confidence threshold
- Preserve identifier history
- Allow manual split and merge
- Audit every merge
- Avoid merging NAT-shared services incorrectly

---

## 23. Finding Normalization and Deduplication

Create a canonical key such as:

```text
organization + asset + service + canonical weakness + scanner-specific discriminator
```

Rules:

- Multiple scanners may support one canonical finding.
- Preserve scanner-specific evidence.
- Avoid duplicate open findings for repeated scans.
- Update `last_seen_at`.
- Mark findings absent from later equivalent scans as candidates for resolution.
- Require a verification policy before automatic closure.
- Reopen a resolved finding if detected again.
- Keep all historical observations.

---

## 24. Notifications and Ticketing

MVP notifications:

- Email
- Generic webhook

Events:

- Probe offline
- Scan completed
- Scan failed
- Critical finding
- KEV match
- Confirmed exploitable finding
- Finding overdue
- Risk acceptance expiring
- Verification succeeded
- Finding reopened
- CVE feed stale

Later integrations:

- GLPI
- Jira
- ServiceNow
- Microsoft Teams
- Slack

Ticket synchronization must store:

- External ticket ID
- URL
- Status
- Last synchronization
- Mapping rules
- Errors

---

## 25. VulnaPulse Monitoring Stack

VulnaPulse is the optional operational-monitoring layer for Vulna itself. It is separate from the VulnaDash security findings dashboard.

### 25.1 Purpose

VulnaDash answers:

- What assets exist?
- What vulnerabilities were found?
- Which CVEs are known exploited?
- Which findings require remediation?
- Which VulnaScout should run an assessment?

VulnaPulse answers:

- Is Vulna healthy?
- Are VulnaScouts checking in?
- Are queues backing up?
- Are scans unusually slow?
- Are CVE feeds stale?
- Is PostgreSQL, Redis, or report generation failing?
- Is a VulnaScout low on disk or memory?

### 25.2 Components

The optional Docker Compose `monitoring` profile must include:

- Prometheus
- Grafana
- PostgreSQL exporter
- Redis exporter
- cAdvisor or equivalent container metrics
- Node Exporter for the VulnaDash host
- VulnaDash `/metrics`
- VulnaScout telemetry ingestion or remote-write bridge
- Alertmanager in a later milestone

Example startup:

```bash
docker compose --profile monitoring up -d
```

### 25.3 Metrics

VulnaDash metrics:

- HTTP request count and latency
- Authentication failures
- Queue depth
- Active jobs
- Job and stage duration
- Result-ingestion throughput
- Parser failures
- Report-generation duration and failure count
- NVD, KEV, and EPSS feed age
- Database connection-pool utilization
- WebSocket or event-stream client count

VulnaScout metrics:

- Last heartbeat
- Online state
- Agent version
- CPU
- Memory
- Disk capacity and free space
- Load average
- Active job
- Scanner-stage duration
- Scanner process exit codes
- Result queue size
- Upload retries
- Policy age
- Certificate expiration
- Plugin health

Infrastructure metrics:

- PostgreSQL connections, transactions, locks, and database size
- Redis memory, clients, queue length, and evictions
- Container restarts and resource use
- Filesystem capacity
- Report and evidence storage growth

### 25.4 Provisioned Grafana dashboards

Ship version-controlled dashboards:

1. **Vulna Overview**
   - VulnaScout availability
   - Active and queued assessments
   - Scan success rate
   - Critical platform alerts
   - Feed freshness

2. **VulnaScout Fleet**
   - Fleet status by site
   - Version distribution
   - CPU, memory, and disk
   - Heartbeat lag
   - Scanner failures
   - Policy and certificate age

3. **Assessment Operations**
   - Job duration by mode
   - Stage duration
   - Failure and cancellation rates
   - Result-ingestion rate
   - Queue depth
   - Report-generation time

4. **VulnaWatch Intelligence**
   - NVD synchronization lag
   - KEV feed age
   - EPSS feed age
   - Matching workload
   - CVE records processed
   - Feed errors

5. **VulnaDash Infrastructure**
   - API latency
   - PostgreSQL
   - Redis
   - container and host utilization
   - storage growth

### 25.5 Alert rules

Initial alerts:

- VulnaScout offline beyond configured threshold
- VulnaScout disk free space below 15%
- Certificate expires within 14 days
- CVE feed stale
- Queue depth above threshold
- Job running beyond maximum expected duration
- Report generation repeatedly failing
- PostgreSQL unavailable
- Redis unavailable
- Evidence volume nearly full
- Excessive scanner failures at one site

### 25.6 Security

- Grafana is not exposed publicly by default.
- Use the same reverse proxy and TLS boundary as VulnaDash.
- Require authentication.
- Do not place raw findings or sensitive evidence in metrics labels.
- Avoid asset IP addresses, usernames, credentials, CVE evidence, and scan output in labels.
- Metrics endpoints must be access-controlled or isolated on an internal network.
- Provisioned dashboards and alert rules must be stored in source control.

---

## 26. Backups and Restore

Provide scripts for:

- PostgreSQL logical backup
- Report and evidence backup
- Configuration backup
- Certificate-authority backup
- Restore validation
- Scheduled rotation

Document:

- Encryption
- Offsite storage
- Recovery procedure
- Recovery testing
- Key custody
- What happens if the CA key is lost

Add a dashboard warning if no recent successful backup is recorded.

---

## 27. VulnaPulse — Logging, Metrics, Grafana, and Observability

Use structured logs with:

- timestamp
- level
- service
- request ID
- job ID
- stage ID
- probe ID
- site ID
- actor ID
- event
- safe metadata

Never log:

- passwords
- private keys
- session tokens
- raw authorization headers
- sensitive evidence
- complete scanner credentials

Metrics:

- API latency
- queue depth
- job duration
- stage duration
- probe heartbeat lag
- report-generation time
- feed-sync health
- scanner failure rate
- findings processed
- upload retry count

---

## 28. VulnaLab — Testing Strategy

### 27.1 Unit tests

Cover:

- CIDR authorization
- DNS resolution validation
- redirect scope enforcement
- signature verification
- job expiration
- profile limits
- plugin argument validation
- CVE matching
- risk scoring
- finding deduplication
- report serialization
- RBAC
- audit events

### 27.2 Integration tests

Use isolated lab targets and containers.

Test:

- VulnaScout enrollment
- Certificate rotation
- Policy delivery
- Job polling
- Nmap XML parsing
- Nuclei JSONL parsing
- ZAP output parsing
- testssl parsing
- Interrupted uploads
- Job cancellation
- CVE feed update
- report generation
- backup and restore

### 27.3 Security tests

- SSRF testing
- command injection testing
- path traversal testing
- IDOR testing
- cross-organization isolation
- malicious scanner-output parsing
- oversized result uploads
- decompression bombs
- forged jobs
- replayed jobs
- stale policies
- certificate revocation
- malicious plugin packages
- report-template injection
- stored XSS in scanner evidence

### 27.4 End-to-end lab

Create a lab Compose environment containing intentionally vulnerable demo systems.

The CI environment must not expose these systems publicly.

Validate:

- Discovery
- Vulnerability finding
- Safe validation
- Cleanup
- Report generation
- Remediation simulation
- Verification closure

### 27.5 Performance tests

Test:

- 1,000 assets
- 100,000 services
- 500,000 findings
- 100 VulnaScouts
- 25 simultaneous standard scans
- Large CSV export
- 500-page technical report
- CVE database refresh
- Probe with intermittent connectivity

---

## 29. Threat Model

Create `docs/threat-model.md` using STRIDE or a similar model.

Threats to address:

- Compromised orchestrator sends malicious jobs
- Compromised probe uploads forged results
- Enrollment-token theft
- Probe private-key theft
- Cross-tenant data leakage
- Malicious scanner output attacks parser
- Malicious report content attacks browser
- Arbitrary command injection through plugin configuration
- Unauthorized public scanning
- DNS rebinding
- Redirect scope escape
- Result tampering
- Evidence theft
- Software supply-chain compromise
- Malicious update package
- Denial of service against VulnaScouts
- CVE feed poisoning
- Report forgery
- Privilege escalation inside probe

Required controls:

- mTLS
- signed jobs
- local policy
- signed plugin releases
- checksums
- strict parsers
- content sanitization
- least privilege
- encrypted evidence
- RBAC
- append-only audit trail
- software bill of materials
- dependency scanning
- reproducible releases where feasible

---

## 30. Release and Update Model

### Orchestrator

- Semantic versioning
- Container images in GHCR
- Database migration checks
- Pre-upgrade backup recommendation
- Release notes
- Rollback documentation
- Version-compatibility matrix

### Probe

- Signed release manifest
- SHA-256 checksums
- Architecture-specific binaries
- Staged update channels:
  - stable
  - candidate
  - development
- Automatic update optional
- Rollback to previous binary
- Compatibility check before upgrade
- Never update during an active scan

### Plugins

- Separate version reporting
- Compatibility constraints
- Health checks
- Approved version ranges
- Template-set version history

---

## 31. Development Phases for Codex

Codex should build the project in small, testable milestones and must not attempt the entire system in one unreviewed generation.

### Phase 0 — Repository foundation

Deliver:

- Repository structure
- License
- README
- Makefile
- Backend and frontend scaffolding
- Probe Go module
- Development Compose stack
- CI workflows
- Formatting and linting
- Architecture decision records

Acceptance criteria:

- `docker compose -f docker-compose.dev.yml up` starts development services
- Backend health endpoint works
- Frontend loads
- Probe unit-test command succeeds
- CI runs

### Phase 1 — Authentication and core inventory

Deliver:

- Local authentication
- Administrator bootstrap
- RBAC
- Organizations
- Sites
- Network scopes
- Audit logging
- Database migrations
- Basic frontend

Acceptance criteria:

- Administrator can log in
- Site and scope CRUD works
- Unauthorized users receive 403
- Scope changes create audit events

### Phase 2 — VulnaScout enrollment and heartbeat

Deliver:

- Enrollment tokens
- CSR flow
- Client certificates
- Heartbeats
- VulnaScout status page
- Revocation
- Local state database
- systemd packaging

Acceptance criteria:

- New probe enrolls once
- Reused token fails
- Revoked probe cannot poll jobs
- Offline state appears after threshold

### Phase 3 — Signed jobs and local policy

Deliver:

- Signed policy documents
- Signed job envelopes
- Job polling
- CIDR validation
- Job expiration
- Cancellation
- Local queue

Acceptance criteria:

- Probe rejects out-of-scope target
- Probe rejects altered job
- Probe rejects expired job
- Cancellation stops test worker

### Phase 4 — Nmap discovery

Deliver:

- Nmap plugin
- Safe discovery profile
- XML parser
- Asset and service models
- Scan timeline
- Raw-output retention

Acceptance criteria:

- Authorized lab subnet scan discovers hosts
- Assets and services appear
- Out-of-scope host is never scanned
- Repeated scan updates rather than duplicates

### Phase 5 — Change detection

Deliver:

- Asset identifier history
- New asset events
- Port-open and port-close events
- Service-version changes
- Delta dashboard

Acceptance criteria:

- Opening a test port creates a change event
- Closing it creates a second event
- Scan comparison displays both

### Phase 6 — Nuclei and TLS assessment

Deliver:

- Nuclei adapter
- Safe template policy
- testssl.sh adapter
- Finding normalization
- Finding workflow

Acceptance criteria:

- Safe lab vulnerability creates a normalized finding
- Repeated scan does not duplicate it
- Finding includes scanner evidence and references

### Phase 7 — CVE intelligence

Deliver:

- NVD sync
- CISA KEV sync
- EPSS sync
- CVE tables
- Feed health dashboard
- Matching engine
- CVE watch events

Acceptance criteria:

- Existing finding receives CVSS/KEV/EPSS enrichment
- Simulated KEV update raises a change event
- Feed failure is visible
- Rate limits and retries work

### Phase 8 — Reports

Deliver:

- Executive PDF
- Technical PDF
- Findings CSV
- Assets CSV
- Services CSV
- CVE exposure CSV
- JSON bundle
- Report storage
- Checksums
- Download authorization

Acceptance criteria:

- Completed scan produces all requested formats
- PDFs render without missing sections
- CSV uses stable documented columns
- Report snapshot is reproducible
- Unauthorized user cannot download report

### Phase 9 — ZAP web assessment

Deliver:

- Passive profile
- Limited active profile
- Scope controls
- Generated automation YAML
- Result parsing
- Web findings

Acceptance criteria:

- ZAP cannot follow redirect outside authorized scope
- Passive scan runs without active attacks
- Active profile requires approval

### Phase 10 — Remediation and verification

Deliver:

- Assignment
- Due dates
- Notes
- Risk acceptance
- Verification queue
- Targeted rescan
- Automatic resolve or reopen rules

Acceptance criteria:

- Owner marks finding ready for verification
- Verification scan resolves fixed finding
- Reintroduced issue reopens it
- Risk acceptance expiration triggers alert

### Phase 11 — Controlled Pentest framework

Deliver:

- Rules of engagement
- Approval gates
- Validation candidate list
- Optional Metasploit adapter
- Allowlisted module policy
- Session timeout
- Cleanup records
- Pentest report

Acceptance criteria:

- No intrusive module can run without approval
- Unapproved module is rejected locally
- Session is terminated at timeout
- Cleanup state is recorded
- Pentest PDF is generated

### Phase 12 — Full-Spectrum workflow

Deliver:

- Multi-stage workflow engine
- Conditional stages
- Approval pause
- Safe continuation after skipped intrusive phase
- Combined report
- Full audit trail

Acceptance criteria:

- Full workflow completes in lab
- Intrusive stage can be denied while reports still generate
- Stage failures are clearly reflected
- Cleanup and verification always run when applicable

### Phase 13 — Appliance packaging

Deliver:

- Debian package
- ARM64 package
- Docker probe
- cloud-init installer
- VM-image build scripts
- appliance console
- update and rollback

Acceptance criteria:

- Fresh VM enrolls with documented commands
- Raspberry Pi-class ARM64 environment passes smoke test
- Upgrade does not lose identity or policy
- Rollback restores prior version

### Phase 14 — VulnaPulse observability

Deliver:

- Prometheus service
- Grafana service
- PostgreSQL exporter
- Redis exporter
- host and container metrics
- VulnaDash `/metrics`
- VulnaScout health metrics
- provisioned data sources
- provisioned dashboards
- initial alert rules
- Docker Compose `monitoring` profile

Acceptance criteria:

- `docker compose --profile monitoring up -d` starts the stack
- Grafana loads provisioned dashboards without manual import
- Prometheus scrapes VulnaDash
- VulnaScout heartbeat and resource metrics appear
- stale CVE feed alert can be tested
- sensitive findings and evidence are absent from metric labels

### Phase 15 — Hardening and public release

Deliver:

- Threat model
- External-security review checklist
- SBOMs
- Dependency scans
- Container scans
- Documentation
- Backup and restore test
- Release signing
- Sample lab

Acceptance criteria:

- No high-severity unresolved project dependency findings
- Restore test succeeds
- Documentation covers authorized use and safety
- Release artifacts are signed and checksummed

---

## 32. Codex Working Rules

Codex must:

1. Work one phase at a time.
2. Create or update tests with every feature.
3. Avoid placeholder security logic.
4. Avoid hard-coded secrets.
5. Use migrations for schema changes.
6. Keep API and JSON schemas versioned.
7. Document architectural decisions.
8. Never add arbitrary command execution.
9. Never weaken local scope checks for convenience.
10. Treat scanner output as untrusted.
11. Sanitize HTML and report content.
12. Use typed plugin inputs.
13. Add negative tests for authorization.
14. Preserve backward compatibility or document migrations.
15. Produce concise commit-sized changes.
16. Run linting, type checks, unit tests, and integration tests.
17. Stop and document uncertainty where security behavior is ambiguous.

For every phase, Codex should provide:

- Files added
- Files changed
- Commands to run
- Tests added
- Security assumptions
- Known limitations
- Manual verification steps

---

## 33. Definition of Done

Vulna 1.0 is done when:

- A user can install the orchestrator with Docker Compose.
- A user can deploy an x86-64 or ARM64 probe.
- The probe enrolls securely.
- The probe communicates outbound only.
- The administrator can authorize exact network ranges.
- The probe locally rejects unauthorized jobs.
- Vulnerability Detection scans work.
- Controlled Pentest scans work with approval and allowlists.
- Full-Spectrum assessments work as staged workflows.
- Nmap, Nuclei, ZAP, and TLS results are normalized.
- Optional Metasploit validation is gated and disabled by default.
- The platform continuously monitors CVE data.
- Existing assets are reevaluated when CVE intelligence changes.
- KEV and EPSS affect prioritization.
- Findings can be assigned and remediated.
- Verification rescans resolve or reopen findings.
- Executive and technical PDFs are generated.
- CSV and JSON exports are generated.
- Reports have checksums and access controls.
- Audit logs capture all sensitive actions.
- Backup and restore are documented and tested.
- Security documentation is complete.
- CI tests both `amd64` and `arm64` VulnaScout builds.
- A safe demo lab demonstrates the entire lifecycle.

---

## 34. Recommended Initial Product Decisions

Use these defaults unless implementation findings justify a change:

- Backend: FastAPI
- Frontend: React and TypeScript
- Probe: Go
- Database: PostgreSQL
- Queue: Redis plus Dramatiq or Celery
- Reverse proxy: Caddy
- Report generation: Jinja2 plus WeasyPrint
- Probe connection: periodic HTTPS polling with mTLS
- Job authenticity: Ed25519 signatures
- Local state: SQLite
- Default discovery: Nmap
- Default vulnerability checks: Nuclei safe templates
- Default web checks: ZAP passive baseline
- Default TLS checks: testssl.sh
- Optional validation: Metasploit RPC with a strict allowlist
- Evidence storage: encrypted local volume, later S3-compatible
- Default public-IP policy: denied
- Default exploit-validation policy: disabled
- Default pentest schedule policy: disabled
- Default report retention: 365 days, configurable
- Default raw evidence retention: 90 days, configurable
- Default CVE synchronization: incremental
- Default intrusive approval: required
- Default dual approval: configurable

---

## 35. Official References for Implementers

Use official documentation and review current versions before implementation:

- NVD Vulnerability APIs: https://nvd.nist.gov/developers/vulnerabilities
- NVD API workflows: https://nvd.nist.gov/developers/api-workflows
- CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA KEV downloadable resources: https://www.cisa.gov/resources-tools/resources/kev-catalog
- FIRST EPSS API: https://www.first.org/epss/api
- Nuclei documentation: https://docs.projectdiscovery.io/opensource/nuclei/overview
- Nuclei templates: https://docs.projectdiscovery.io/templates/introduction
- OWASP ZAP Automation Framework: https://www.zaproxy.org/docs/automate/automation-framework/
- OWASP ZAP Docker documentation: https://www.zaproxy.org/docs/docker/
- Metasploit documentation: https://docs.metasploit.com/
- Metasploit RPC documentation: https://docs.metasploit.com/docs/using-metasploit/advanced/RPC/
- Docker Compose documentation: https://docs.docker.com/compose/
- Nmap official documentation: https://nmap.org/docs.html

---

## 36. First Codex Prompt

Use the following as the first prompt after placing this file at the repository root:

```text
Read VULNA_CODEX_BUILD_PLAN.md completely.

Use the Vulna product-family names exactly as defined in Section 1.1.

Implement Phase 0 only. Do not begin later phases.

Create the monorepo structure, development Docker Compose stack, FastAPI backend
with a health endpoint, React TypeScript frontend with a health page, Go probe
module with a version and self-test command, linting and formatting configuration,
Makefile commands, and GitHub Actions CI.

Security requirements:
- Do not add arbitrary command execution.
- Do not hard-code secrets.
- Use environment-variable templates.
- Pin major dependency versions.
- Run services as non-root where practical.
- Add basic container health checks.

Before writing code, create docs/adr/0001-initial-architecture.md explaining the
technology choices and boundaries.

After implementation:
1. Run all available tests and linters.
2. List every file created or modified.
3. Provide exact development startup commands.
4. Document known limitations.
5. Stop. Do not implement Phase 1.
```

---

## 37. Suggested Project Taglines

> **Vulna: Self-hosted security assessment across every site.**

Component phrasing:

> **VulnaDash commands. VulnaScout assesses. VulnaWatch never stops watching.**

Alternative:

> **Deploy a VulnaScout. Authorize the scope. Know what is exposed.**
