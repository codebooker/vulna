"""Code-defined permissions and compatibility-role defaults (Phase 39).

Permission keys are stable public identifiers. Database roles select from this
catalogue; they cannot invent permission strings, which keeps authorization
reviewable in source control and prevents a typo from becoming an accidental
allow rule.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import UserRole

ORGANIZATION_SCOPE = "organization"
SITE_SCOPE = "site"


@dataclass(frozen=True)
class PermissionDefinition:
    key: str
    label: str
    description: str
    scopes: tuple[str, ...] = (ORGANIZATION_SCOPE,)
    high_risk: bool = False


def _permission(
    key: str,
    label: str,
    description: str,
    *,
    site_scoped: bool = False,
    high_risk: bool = False,
) -> PermissionDefinition:
    scopes = (ORGANIZATION_SCOPE, SITE_SCOPE) if site_scoped else (ORGANIZATION_SCOPE,)
    return PermissionDefinition(key, label, description, scopes, high_risk)


PERMISSIONS: tuple[PermissionDefinition, ...] = (
    _permission(
        "system.admin",
        "Full administration",
        "Compatibility permission for administrator-only operations.",
        high_risk=True,
    ),
    _permission("system.read", "View system status", "View local health and support status."),
    _permission(
        "organization.manage",
        "Manage organization",
        "Change organization-wide settings and experience configuration.",
        high_risk=True,
    ),
    _permission("users.read", "View users", "View organization user lifecycle metadata."),
    _permission(
        "users.manage",
        "Manage users",
        "Invite, suspend, and grant access to users.",
        high_risk=True,
    ),
    _permission("roles.read", "View authorization", "View roles, grants, and permissions."),
    _permission(
        "roles.manage",
        "Manage authorization",
        "Create roles and change scoped grants.",
        high_risk=True,
    ),
    _permission("tokens.self", "Manage personal tokens", "Manage your own expiring API tokens."),
    _permission(
        "service_accounts.manage",
        "Manage service accounts",
        "Create service principals and their expiring API tokens.",
        high_risk=True,
    ),
    _permission("sessions.self", "Manage own sessions", "View and revoke your own sessions."),
    _permission(
        "sessions.manage",
        "Manage all sessions",
        "View and revoke organization sessions.",
        high_risk=True,
    ),
    _permission("identity.self", "Manage own MFA", "Manage your own authentication factors."),
    _permission(
        "identity.manage",
        "Manage identity",
        "Manage MFA policy, SSO providers, and break-glass access.",
        high_risk=True,
    ),
    _permission(
        "scim.manage",
        "Manage SCIM",
        "Manage SCIM tokens, group mappings, and logs.",
        high_risk=True,
    ),
    _permission("sites.read", "View sites", "View assigned sites.", site_scoped=True),
    _permission("sites.manage", "Manage sites", "Create and change sites.", high_risk=True),
    _permission("scopes.read", "View scopes", "View authorized network scopes.", site_scoped=True),
    _permission(
        "scopes.manage", "Manage scopes", "Approve and change scanning boundaries.", high_risk=True
    ),
    _permission("networks.read", "View networks", "View network inventory.", site_scoped=True),
    _permission(
        "networks.manage", "Manage networks", "Change network inventory.", site_scoped=True
    ),
    _permission(
        "scouts.read", "View Scouts", "View Scout enrollment and health.", site_scoped=True
    ),
    _permission(
        "scouts.manage",
        "Manage Scouts",
        "Enroll, approve, repair, or revoke Scouts.",
        high_risk=True,
    ),
    _permission(
        "relays.read", "View relays", "View relay configuration and health.", site_scoped=True
    ),
    _permission("relays.manage", "Manage relays", "Change relay configuration.", high_risk=True),
    _permission("schedules.read", "View schedules", "View scan schedules.", site_scoped=True),
    _permission(
        "schedules.manage",
        "Manage schedules",
        "Create and change scan schedules.",
        site_scoped=True,
    ),
    _permission("jobs.read", "View jobs", "View assessment jobs.", site_scoped=True),
    _permission(
        "jobs.create", "Create jobs", "Start authorized assessment jobs.", site_scoped=True
    ),
    _permission("jobs.manage", "Manage jobs", "Cancel and reap assessment jobs.", site_scoped=True),
    _permission(
        "credentials.read",
        "View credential metadata",
        "View vault metadata, assignments, tests, and usage without secret values.",
    ),
    _permission(
        "credentials.manage",
        "Manage credential vault",
        "Create, rotate, assign, test, and deactivate vault credentials.",
        high_risk=True,
    ),
    _permission(
        "credentials.use",
        "Run authenticated inventory",
        "Resolve and deliver a credential to an authorized Scout job.",
        site_scoped=True,
        high_risk=True,
    ),
    _permission("assets.read", "View assets", "View assessed assets.", site_scoped=True),
    _permission("assets.manage", "Manage assets", "Change asset records.", site_scoped=True),
    _permission(
        "software.read",
        "View software inventory",
        "View installed software and EOL state.",
        site_scoped=True,
    ),
    _permission(
        "software.manage",
        "Manage software inventory",
        "Create manual EOL overrides and administer software inventory.",
        site_scoped=True,
    ),
    _permission("findings.read", "View findings", "View findings and evidence.", site_scoped=True),
    _permission(
        "findings.manage", "Manage findings", "Change finding workflow state.", site_scoped=True
    ),
    _permission("remediation.read", "View remediation", "View remediation work.", site_scoped=True),
    _permission(
        "remediation.manage",
        "Manage remediation",
        "Change remediation workflow and notes.",
        site_scoped=True,
    ),
    _permission(
        "pentest.read", "View pentest", "View controlled pentest sessions.", site_scoped=True
    ),
    _permission(
        "pentest.request",
        "Request pentest",
        "Request controlled pentest actions.",
        site_scoped=True,
        high_risk=True,
    ),
    _permission(
        "pentest.approve",
        "Approve pentest",
        "Approve controlled pentest actions.",
        site_scoped=True,
        high_risk=True,
    ),
    _permission("workflows.read", "View workflows", "View assessment workflows.", site_scoped=True),
    _permission("workflows.run", "Run workflows", "Start assessment workflows.", site_scoped=True),
    _permission(
        "workflows.approve",
        "Approve workflows",
        "Approve gated workflow stages.",
        site_scoped=True,
        high_risk=True,
    ),
    _permission(
        "risk_acceptance.read",
        "View risk decisions",
        "View risk-acceptance decisions.",
        site_scoped=True,
    ),
    _permission(
        "risk_acceptance.approve",
        "Approve risk decisions",
        "Approve risk-acceptance decisions.",
        site_scoped=True,
        high_risk=True,
    ),
    _permission(
        "risk_acceptance.manage",
        "Manage risk decisions",
        "Expire and administer risk decisions.",
        high_risk=True,
    ),
    _permission(
        "reports.read", "View reports", "View and download authorized reports.", site_scoped=True
    ),
    _permission(
        "reports.create", "Create reports", "Generate authorized reports.", site_scoped=True
    ),
    _permission("audit.read", "View audit log", "View the organization audit log."),
    _permission("feeds.read", "View intelligence feeds", "View feed health and records."),
    _permission("feeds.manage", "Manage intelligence feeds", "Synchronize and configure feeds."),
    _permission("notifications.read", "View notifications", "View notification configuration."),
    _permission(
        "notifications.manage",
        "Manage notifications",
        "Change notification destinations.",
        high_risk=True,
    ),
    _permission("privacy.read", "View privacy", "View privacy and data ownership status."),
    _permission("privacy.manage", "Manage privacy", "Change privacy settings.", high_risk=True),
    _permission("maintenance.read", "View maintenance", "View retention and maintenance status."),
    _permission(
        "maintenance.manage",
        "Manage maintenance",
        "Run retention, repair, and hold operations.",
        high_risk=True,
    ),
    _permission("portability.read", "View portability", "View migration guidance."),
    _permission(
        "portability.manage",
        "Manage portability",
        "Export or validate organization data.",
        high_risk=True,
    ),
    _permission("diagnostics.read", "View diagnostics", "View diagnostic status."),
    _permission(
        "diagnostics.manage",
        "Manage diagnostics",
        "Generate support bundles and diagnostic actions.",
    ),
    _permission("presets.read", "View presets", "View assessment presets.", site_scoped=True),
    _permission("presets.manage", "Manage presets", "Change assessment presets.", site_scoped=True),
    _permission("resources.read", "View resources", "View resource and utilization information."),
    _permission("resources.manage", "Manage resources", "Change resource policy."),
    _permission("onboarding.read", "View onboarding", "View onboarding plans."),
    _permission("onboarding.manage", "Manage onboarding", "Change onboarding configuration."),
    _permission("demo.read", "View demo state", "View demo-mode configuration."),
    _permission("demo.manage", "Manage demo state", "Reset or seed demo state.", high_risk=True),
    _permission("tasks.read", "View background tasks", "View task and worker health."),
    _permission(
        "tasks.manage",
        "Manage background tasks",
        "Retry, cancel, or inspect failed tasks.",
        high_risk=True,
    ),
)

PERMISSION_BY_KEY = {permission.key: permission for permission in PERMISSIONS}
ALL_PERMISSION_KEYS = frozenset(PERMISSION_BY_KEY)

_READ_KEYS = frozenset(key for key in ALL_PERMISSION_KEYS if key.endswith(".read"))
# These surfaces exposed administrator-only data before Phase 39 or are reserved
# for the dedicated operations console. Keep them out of broad compatibility
# roles so migrating a Viewer/Auditor cannot silently widen access.
_PRIVILEGED_READ_KEYS = frozenset({"audit.read", "roles.read", "tasks.read", "users.read"})
_GENERAL_READ_KEYS = _READ_KEYS - _PRIVILEGED_READ_KEYS
_SELF_KEYS = frozenset({"tokens.self", "sessions.self", "identity.self"})

BUILTIN_ROLE_PERMISSIONS: dict[UserRole, frozenset[str]] = {
    UserRole.ADMINISTRATOR: ALL_PERMISSION_KEYS,
    UserRole.SECURITY_OPERATOR: _GENERAL_READ_KEYS
    | _SELF_KEYS
    | frozenset(
        {
            "networks.manage",
            "schedules.manage",
            "jobs.create",
            "jobs.manage",
            "credentials.use",
            "assets.manage",
            "findings.manage",
            "remediation.manage",
            "pentest.request",
            "workflows.run",
            "reports.create",
            "presets.manage",
        }
    ),
    UserRole.PENTEST_APPROVER: _GENERAL_READ_KEYS
    | _SELF_KEYS
    | frozenset(
        {
            "jobs.create",
            "pentest.request",
            "pentest.approve",
            "workflows.approve",
            "risk_acceptance.approve",
            "reports.create",
        }
    ),
    UserRole.REMEDIATION_OWNER: _GENERAL_READ_KEYS
    | _SELF_KEYS
    | frozenset({"remediation.manage", "reports.create"}),
    UserRole.AUDITOR: _GENERAL_READ_KEYS | _SELF_KEYS | frozenset({"audit.read"}),
    UserRole.VIEWER: _GENERAL_READ_KEYS | _SELF_KEYS,
}

ROLE_PRIORITY: dict[UserRole, int] = {
    UserRole.ADMINISTRATOR: 60,
    UserRole.SECURITY_OPERATOR: 50,
    UserRole.PENTEST_APPROVER: 40,
    UserRole.REMEDIATION_OWNER: 30,
    UserRole.AUDITOR: 20,
    UserRole.VIEWER: 10,
}


def validate_permission_keys(keys: set[str]) -> set[str]:
    unknown = keys - ALL_PERMISSION_KEYS
    if unknown:
        raise ValueError(f"Unknown permission keys: {', '.join(sorted(unknown))}")
    return keys
