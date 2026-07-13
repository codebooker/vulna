# ADR 0033: Adaptive installation and experience profiles

- **Status:** Accepted
- **Date:** 2026-07-12
- **Phase:** 33

## Context

Vulna's Phase 0–32 capabilities serve both small installations and more complex
environments. A single flat navigation makes the safe first path hard to see,
while removing routes for smaller deployments would create security and support
forks.

## Decision

Store a typed organization experience profile plus allowlisted navigation
overrides. A centralized frontend catalogue combines profile visibility with the
current role. Small Business promotes core routes and groups all other implemented
routes under collapsed Advanced navigation; Enterprise exposes all; Custom uses
explicit overrides.

Profile visibility is never consulted by backend authorization. Hidden routes stay
directly addressable, background behavior continues, and profile updates touch no
policy or feature configuration. Changes require an administrator, support a
preview, and audit old/new values.

Installer answers move to schema v2 while v1 remains readable. The bootstrap value
seeds only a newly created organization. New onboarding stores advisory planning
answers in `OnboardingState.extra_json`; it labels future features `planned` and
never auto-applies a high-impact policy.

## Consequences

- One codebase and security boundary serve every profile.
- Existing organizations receive the neutral Small Business presentation without
  losing configuration.
- New phases must update the public capability matrix and shared catalogue.

## Migration and rollback

The additive migration backfills `small_business` and `{}`. Export and backup/
restore preserve both fields. Downgrade removes only presentation preferences;
all operational and security configuration remains intact.
