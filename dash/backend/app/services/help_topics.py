"""Contextual help catalogue.

A single registry that maps a help *topic key* to a short explanation and a link
into the documentation. Errors, setup steps, findings, maintenance warnings, and
update screens reference these keys so a user is always one click from a relevant,
plain-language explanation instead of a generic log page.

Every ``doc`` here points at a file under ``docs/``; a test verifies they all
exist, so a renamed or deleted guide is caught in CI.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HelpTopic:
    key: str
    title: str
    summary: str
    doc: str


HELP_TOPICS: dict[str, HelpTopic] = {
    "getting-started": HelpTopic(
        "getting-started",
        "Quick start",
        "Install Vulna on one host and run a first safe scan.",
        "docs/quickstart.md",
    ),
    "install": HelpTopic(
        "install",
        "Single-host installation",
        "Install and run the whole stack on one machine.",
        "docs/installation/README.md",
    ),
    "add-scout": HelpTopic(
        "add-scout",
        "Add a remote Scout or Relay",
        "Choose and deploy an endpoint at another site or network segment.",
        "docs/deployment.md",
    ),
    "relay": HelpTopic(
        "relay",
        "VulnaRelay",
        "Understand, install, scope, stop, and revoke a scanner-free Relay.",
        "docs/relay.md",
    ),
    "choose-preset": HelpTopic(
        "choose-preset",
        "Choosing a scan preset",
        "Pick a safe preset for the outcome you want.",
        "docs/terminology.md",
    ),
    "understand-findings": HelpTopic(
        "understand-findings",
        "Understanding findings",
        "What a finding means and how priority is decided.",
        "docs/understanding-findings.md",
    ),
    "fix-verify": HelpTopic(
        "fix-verify",
        "Fixing and verifying a finding",
        "Assign, remediate, and re-check a finding.",
        "docs/understanding-findings.md",
    ),
    "reporting": HelpTopic(
        "reporting",
        "Reports and exports",
        "Generate permission-scoped PDF, CSV, and JSON artifacts.",
        "docs/reporting.md",
    ),
    "authenticated-inventory": HelpTopic(
        "authenticated-inventory",
        "Authenticated inventory",
        "Run read-only SSH or WinRM software collection through an opted-in Scout.",
        "docs/authenticated-inventory.md",
    ),
    "inventory-intelligence": HelpTopic(
        "inventory-intelligence",
        "Inventory intelligence",
        "Import, reconcile, analyze, and report on passive inventory sources.",
        "docs/passive-inventory.md",
    ),
    "updates": HelpTopic(
        "updates",
        "Updates and rollback",
        "Apply a signed update and roll back safely.",
        "docs/updates.md",
    ),
    "backups": HelpTopic(
        "backups",
        "Backup and restore",
        "Create, verify, and restore an encrypted backup.",
        "docs/backups.md",
    ),
    "networking": HelpTopic(
        "networking",
        "Changing the URL or certificate",
        "Access modes, TLS, and reverse-proxy setup.",
        "docs/networking.md",
    ),
    "maintenance": HelpTopic(
        "maintenance",
        "Maintenance and cleanup",
        "Health overview, storage, and safe retention cleanup.",
        "docs/maintenance.md",
    ),
    "notifications": HelpTopic(
        "notifications",
        "Notifications",
        "Email and signed-webhook alerts.",
        "docs/notifications.md",
    ),
    "sso": HelpTopic(
        "sso",
        "Single sign-on",
        "Configure, test, and safely enforce OIDC or SAML sign-in.",
        "docs/sso.md",
    ),
    "scim": HelpTopic(
        "scim",
        "SCIM provisioning",
        "Provision directory users and map groups to roles and sites.",
        "docs/scim.md",
    ),
    "authorization": HelpTopic(
        "authorization",
        "Roles, service accounts, and API tokens",
        "Configure permission-scoped human and automation access.",
        "docs/authorization.md",
    ),
    "diagnostics": HelpTopic(
        "diagnostics",
        "Diagnostics (Vulna Doctor)",
        "Find which component is failing.",
        "docs/diagnostics.md",
    ),
    "low-resource": HelpTopic(
        "low-resource",
        "Low-resource and offline operation",
        "Lite profile, budgets, and offline bundles.",
        "docs/low-resource.md",
    ),
    "troubleshooting": HelpTopic(
        "troubleshooting",
        "Troubleshooting",
        "Start from a symptom and narrow it down.",
        "docs/troubleshooting.md",
    ),
    "authorized-use": HelpTopic(
        "authorized-use",
        "Authorized use",
        "Only assess systems you own or are permitted to test.",
        "docs/authorized-use.md",
    ),
    "exposure": HelpTopic(
        "exposure",
        "Exposing Vulna beyond your LAN",
        "The checklist before making Vulna reachable from the internet.",
        "docs/administration/exposure-checklist.md",
    ),
    "demo": HelpTopic(
        "demo",
        "Demo mode",
        "Explore the interface with sample data and no scanning.",
        "docs/demo.md",
    ),
    "privacy": HelpTopic(
        "privacy",
        "Privacy and data ownership",
        "What leaves the deployment, secret inventory, and telemetry.",
        "docs/privacy.md",
    ),
    "portability": HelpTopic(
        "portability",
        "Export and moving to a new host",
        "Export your data and migrate Vulna to another machine.",
        "docs/portability.md",
    ),
}

# Contextual mappings so callers can look up help by the identifier they already
# have (a job error code, a maintenance domain, an update state).
ERROR_HELP: dict[str, str] = {
    "upload_failed": "troubleshooting",
    "queue_full": "low-resource",
    "verification_failed": "understand-findings",
    "storage_critical": "maintenance",
    "storage_low": "maintenance",
}

DOMAIN_HELP: dict[str, str] = {
    "updates": "updates",
    "backups": "backups",
    "feeds": "diagnostics",
    "storage": "maintenance",
    "retention": "maintenance",
    "certificate_ca": "networking",
    "certificate_scouts": "add-scout",
    "scan_jobs": "troubleshooting",
    "stuck_jobs": "troubleshooting",
}


def topic_for(key: str) -> HelpTopic | None:
    return HELP_TOPICS.get(key)


def help_for_error(error_code: str) -> HelpTopic | None:
    return HELP_TOPICS.get(ERROR_HELP.get(error_code, ""))


def help_for_domain(domain: str) -> HelpTopic | None:
    return HELP_TOPICS.get(DOMAIN_HELP.get(domain, ""))


# The administrator checklist shown before exposing Vulna beyond a private LAN.
# Text mirrors docs/administration/exposure-checklist.md.
EXPOSURE_CHECKLIST: list[str] = [
    "Put Vulna behind a reverse proxy that terminates TLS with a valid certificate.",
    "Keep the database and Redis ports bound to localhost; never expose them.",
    "Set strong, unique secrets (VULNA_SECRET_KEY, admin password); never defaults.",
    "Require mutual TLS for Scouts and keep VULNA_TRUSTED_PROXIES accurate.",
    "Enable a firewall allowing only 443 (and your reverse proxy) from outside.",
    "Configure notifications so you hear about failures and expiring certificates.",
    "Take a verified, encrypted, off-host backup before exposing the service.",
    "Review docs/security-review-checklist.md and docs/threat-model.md.",
]
