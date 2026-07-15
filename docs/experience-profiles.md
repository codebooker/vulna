# Experience profiles

Experience profiles organize Vulna for different operators. They are a
presentation layer—not a feature flag, license boundary, or authorization system.

## Profiles

- **Small Business** keeps Overview, Assets, Findings, Scans, Sites, Reports,
  Appliances, Integrations, Users, and Settings prominent. Every other implemented
  surface remains available under a collapsed **Advanced** section.
- **Enterprise** shows every implemented route in the main navigation.
- **Custom** applies administrator-selected route visibility overrides.

A route absent from navigation remains directly addressable when the signed-in
user has permission. Background work continues. Switching profiles preserves
sites, scopes, schedules, policies, credentials, retention, evidence, reports,
privacy settings, and every security control.

## Change a profile

An administrator opens **Settings → General**, chooses a profile, and previews
the affected navigation entries. The confirmation explicitly states what is
preserved. Applying a change records old/new profile values and overrides in the
audit log.

The API equivalents are:

- `GET /api/v1/organizations/current/experience`
- `POST /api/v1/organizations/current/experience/preview`
- `PATCH /api/v1/organizations/current/experience`

## Installation and onboarding

The installer writes `VULNA_DEPLOYMENT_PROFILE`. Bootstrap reads it only when it
creates a new organization; it never changes an existing one. The onboarding
profile plan stores answers and recommendations in the organization's onboarding
state. `available` means the capability exists in the installed version;
`planned` means the recommendation is recognized but is not yet usable.
Recommendations never apply a policy automatically.

See the [capability matrix](capabilities.md) for the current status.
