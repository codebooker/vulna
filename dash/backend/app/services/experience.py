"""Experience-profile presentation and onboarding planning rules (Phase 33).

Profiles affect route discoverability and recommendations only. This module is
deliberately independent of API authorization and never changes policies,
credentials, schedules, background behavior, or stored feature configuration.
"""

from __future__ import annotations

from typing import Any

from app.models.enums import ExperienceProfile

CORE_ROUTES: tuple[str, ...] = (
    "overview",
    "assets",
    "findings",
    "scans",
    "sites",
    "reports",
    "appliances",
    "notifications",
    "users",
    "settings",
)

ADVANCED_ROUTES: tuple[str, ...] = (
    "changes",
    "remediation",
    "networks",
    "presets",
    "pentest",
    "feeds",
    "system_health",
)

ROUTE_KEYS = frozenset((*CORE_ROUTES, *ADVANCED_ROUTES))

# Public, truthful status matrix. Production-ready stays false until the release
# qualification gate proves it, independent of whether a route is visible.
CAPABILITIES: tuple[dict[str, Any], ...] = (
    {
        "key": "core_assessment",
        "name": "Core assessment workflow",
        "status": "available",
        "production_ready": False,
    },
    {
        "key": "reports",
        "name": "Reports and exports",
        "status": "available",
        "production_ready": False,
    },
    {
        "key": "notifications",
        "name": "Notifications",
        "status": "available",
        "production_ready": False,
    },
    {
        "key": "identity_lifecycle",
        "name": "User lifecycle administration",
        "status": "available",
        "production_ready": False,
    },
    {
        "key": "revocable_sessions",
        "name": "Revocable sessions",
        "status": "available",
        "production_ready": False,
    },
    {
        "key": "mfa_webauthn",
        "name": "MFA and WebAuthn",
        "status": "planned",
        "production_ready": False,
    },
    {
        "key": "enterprise_sso",
        "name": "OIDC and SAML SSO",
        "status": "planned",
        "production_ready": False,
    },
    {"key": "scim", "name": "SCIM provisioning", "status": "planned", "production_ready": False},
    {
        "key": "granular_rbac",
        "name": "Granular RBAC",
        "status": "planned",
        "production_ready": False,
    },
    {
        "key": "asset_groups",
        "name": "Asset groups and ownership",
        "status": "planned",
        "production_ready": False,
    },
    {
        "key": "authenticated_scanning",
        "name": "Authenticated scanning",
        "status": "planned",
        "production_ready": False,
    },
    {
        "key": "ticketing",
        "name": "Ticketing connectors",
        "status": "planned",
        "production_ready": False,
    },
    {
        "key": "passive_inventory",
        "name": "Passive inventory connectors",
        "status": "planned",
        "production_ready": False,
    },
)

QUESTIONS: dict[ExperienceProfile, tuple[dict[str, Any], ...]] = {
    ExperienceProfile.SMALL_BUSINESS: (
        {
            "key": "asset_count",
            "label": "About how many assets do you manage?",
            "kind": "number",
            "required": True,
        },
        {
            "key": "internet_facing",
            "label": "Do you operate internet-facing systems?",
            "kind": "boolean",
        },
        {
            "key": "compliance",
            "label": "Do you have a compliance framework to track?",
            "kind": "boolean",
        },
        {
            "key": "ticketing",
            "label": "Do you want findings synchronized to a ticket system?",
            "kind": "boolean",
        },
    ),
    ExperienceProfile.ENTERPRISE: (
        {
            "key": "asset_count",
            "label": "About how many assets do you manage?",
            "kind": "number",
            "required": True,
        },
        {
            "key": "site_count",
            "label": "How many sites or environments do you manage?",
            "kind": "number",
        },
        {
            "key": "identity_provider",
            "label": "Which identity provider do you use?",
            "kind": "select",
            "options": ["none", "oidc", "saml", "both"],
        },
        {"key": "scim", "label": "Do you need automated user provisioning?", "kind": "boolean"},
        {
            "key": "cloud_inventory",
            "label": "Do you need cloud inventory connectors?",
            "kind": "boolean",
        },
        {
            "key": "ticketing",
            "label": "Do you want findings synchronized to a ticket system?",
            "kind": "boolean",
        },
    ),
    ExperienceProfile.CUSTOM: (
        {
            "key": "priorities",
            "label": "What outcomes are most important?",
            "kind": "text",
            "required": True,
        },
        {
            "key": "identity_provider",
            "label": "Do you use an external identity provider?",
            "kind": "boolean",
        },
        {
            "key": "cloud_inventory",
            "label": "Do you need cloud inventory connectors?",
            "kind": "boolean",
        },
        {
            "key": "ticketing",
            "label": "Do you want findings synchronized to a ticket system?",
            "kind": "boolean",
        },
    ),
}


def validate_overrides(overrides: dict[str, bool]) -> dict[str, bool]:
    unknown = sorted(set(overrides) - ROUTE_KEYS)
    if unknown:
        raise ValueError(f"Unknown route override(s): {', '.join(unknown)}")
    if any(not isinstance(value, bool) for value in overrides.values()):
        raise ValueError("Route overrides must be boolean values")
    return dict(overrides)


def route_visibility(
    profile: ExperienceProfile, overrides: dict[str, bool] | None = None
) -> dict[str, bool]:
    """Return navigation visibility; callers must not use this for authorization."""
    if profile == ExperienceProfile.SMALL_BUSINESS:
        visible = {key: key in CORE_ROUTES for key in ROUTE_KEYS}
    else:
        visible = dict.fromkeys(ROUTE_KEYS, True)
    if profile == ExperienceProfile.CUSTOM:
        visible.update(validate_overrides(overrides or {}))
    return dict(sorted(visible.items()))


def experience_payload(
    profile: ExperienceProfile,
    overrides: dict[str, bool] | None = None,
    *,
    previous: tuple[ExperienceProfile, dict[str, bool]] | None = None,
) -> dict[str, Any]:
    clean_overrides = validate_overrides(overrides or {})
    visibility = route_visibility(profile, clean_overrides)
    previous_visibility = (
        route_visibility(previous[0], previous[1]) if previous is not None else visibility
    )
    return {
        "experience_profile": profile,
        "feature_overrides": clean_overrides,
        "route_visibility": visibility,
        "core_routes": list(CORE_ROUTES),
        "advanced_routes": list(ADVANCED_ROUTES),
        "capabilities": [dict(item) for item in CAPABILITIES],
        "changed_routes": sorted(
            key for key in ROUTE_KEYS if visibility[key] != previous_visibility[key]
        ),
        "note": (
            "Experience profiles change navigation and recommendations only. "
            "Authorized direct access, security controls, and background operation continue."
        ),
    }


def profile_questions(profile: ExperienceProfile) -> list[dict[str, Any]]:
    return [dict(question) for question in QUESTIONS[profile]]


def validate_plan_answers(profile: ExperienceProfile, answers: dict[str, Any]) -> dict[str, Any]:
    questions = {question["key"]: question for question in QUESTIONS[profile]}
    unknown = sorted(set(answers) - set(questions))
    if unknown:
        raise ValueError(f"Unknown planning answer(s): {', '.join(unknown)}")
    for key, value in answers.items():
        kind = questions[key]["kind"]
        if kind == "boolean" and not isinstance(value, bool):
            raise ValueError(f"Planning answer '{key}' must be a boolean")
        if kind == "number" and (
            not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0
        ):
            raise ValueError(f"Planning answer '{key}' must be a non-negative number")
        if kind == "text" and not isinstance(value, str):
            raise ValueError(f"Planning answer '{key}' must be text")
        if kind == "select" and value not in questions[key].get("options", []):
            raise ValueError(f"Planning answer '{key}' is not a valid option")
    return dict(answers)


def recommendations(profile: ExperienceProfile, answers: dict[str, Any]) -> list[dict[str, Any]]:
    """Build advisory recommendations without applying any setting or policy."""
    result: list[dict[str, Any]] = [
        {
            "capability": "Start with the standard assessment preset",
            "status": "available",
            "reason": "It provides a safe first inventory and vulnerability baseline.",
            "route": "/scans",
        }
    ]
    if answers.get("internet_facing"):
        result.append(
            {
                "capability": "Review scopes and controlled validation",
                "status": "available",
                "reason": "Internet-facing systems benefit from explicit scope review.",
                "route": "/pentest",
            }
        )
    if answers.get("identity_provider") not in (None, False, "none"):
        result.append(
            {
                "capability": "Configure enterprise SSO",
                "status": "planned",
                "reason": "The selected identity-provider integration arrives in Phase 37.",
                "route": None,
            }
        )
    if answers.get("scim"):
        result.append(
            {
                "capability": "Automate provisioning with SCIM",
                "status": "planned",
                "reason": "SCIM provisioning arrives in Phase 38.",
                "route": None,
            }
        )
    if answers.get("ticketing"):
        result.append(
            {
                "capability": "Synchronize remediation tickets",
                "status": "planned",
                "reason": "Ticket connectors arrive in Phase 43.",
                "route": None,
            }
        )
    if answers.get("cloud_inventory"):
        result.append(
            {
                "capability": "Import passive cloud inventory",
                "status": "planned",
                "reason": "Cloud inventory connectors arrive in Phase 44.",
                "route": None,
            }
        )
    asset_count = answers.get("asset_count")
    if isinstance(asset_count, (int, float)) and asset_count > 500:
        result.append(
            {
                "capability": "Plan distributed Scouts by site",
                "status": "available",
                "reason": "The stated estate size benefits from site-scoped collection.",
                "route": "/appliances",
            }
        )
    return result
