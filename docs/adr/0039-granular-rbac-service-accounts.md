# ADR 0039: Code-defined permissions with database roles and scoped principals

## Status

Accepted for Phase 39.

## Context

The original API used one compatibility role and Phase 34 added a separate site
assignment boundary. That model cannot express additive duties, site-specific
operator access, or non-interactive automation without either multiplying enum
roles or weakening endpoint checks.

## Decision

Keep permission definitions in source control and materialize organization roles,
role-permission mappings, and principal grants in the database. A grant binds a
role to a user or service account at organization or site scope. Query helpers join
the role permission and grant in one correlated predicate so permissions from
different scopes cannot combine.

Migrate every compatibility role and Phase 34 site assignment into built-in grants.
Continue deriving `User.role`, `is_active`, `site_access_mode`, and user-site
assignments for `/api/v1` compatibility. Runtime-created and upgraded users use
grants as the authority; a narrow legacy fallback remains only for direct ORM test
fixtures and integrations that have not run lifecycle helpers.

Represent automation with service accounts that cannot sign in interactively.
Personal and service API tokens are random, hashed, expiring, optionally IP-bound,
shown once, rotatable, and immediately revocable. Bind tokens to a principal
authorization version. Require an interactive session for step-up operations.

## Consequences

- Permission additions require a code review and capability/migration update.
- Custom roles are additive without changing public enum shapes.
- Authorization changes invalidate sessions and tokens immediately.
- Service actors use audit attribution even where legacy user foreign keys are null.
- Downgrade removes granular configuration and token records but retains the derived
  compatibility role/site fields; custom-role meaning cannot be represented before
  Phase 39, so an encrypted backup is mandatory before downgrade.
