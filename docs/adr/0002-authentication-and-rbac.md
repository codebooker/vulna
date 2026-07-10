# ADR 0002: Authentication, RBAC, and the Data Access Layer

- **Status:** Accepted
- **Date:** 2026-07-10
- **Phase:** 1 (Authentication and core inventory)

## Context

Phase 1 introduces the first authenticated, persistent surface of VulnaDash:
local authentication, role-based access control, organizations, sites, network
scopes, and an append-only audit log, backed by a real database and migrations.
These choices set patterns every later phase builds on, so they are recorded
here.

## Decisions

### 1. Async SQLAlchemy 2.0 + Alembic, portable across PostgreSQL and SQLite

Models use the SQLAlchemy 2.0 typed `Mapped[...]` style on a shared
`DeclarativeBase`. The engine is async (`asyncpg` in production). All column
types are dialect-portable — `sa.Uuid` (native `UUID` on PostgreSQL, `CHAR(32)`
on SQLite) and `sa.JSON` — so the test suite runs against in-memory SQLite with
no PostgreSQL dependency while production uses PostgreSQL unchanged.

`eager_defaults=True` on the base mapper makes the ORM fetch server-generated
`created_at`/`updated_at` values immediately after INSERT/UPDATE, avoiding lazy
reloads during synchronous response serialization.

The schema is owned by Alembic. `VULNA_AUTO_CREATE_TABLES` allows
`metadata.create_all` for local/dev and tests, but production runs
`alembic upgrade head`. CI asserts the migration matches the models
(`alembic upgrade head && alembic check`).

### 2. Password hashing with Argon2id

Passwords are stored only as Argon2id hashes via `argon2-cffi` (the
OWASP-recommended default), used directly so the algorithm and parameters are
explicit. Hashes are transparently upgraded on login when parameters change.

### 3. Stateless JWT access tokens (HS256)

Login returns a short-lived JWT signed with `VULNA_SECRET_KEY` (HS256). The
token carries the subject, role, and organization so most authorization checks
need no database round-trip, while the current user is still loaded per request
so deactivated or deleted users are rejected immediately. There is intentionally
**no default secret**: authentication refuses to operate unless
`VULNA_SECRET_KEY` is configured. Refresh tokens, API tokens with scopes, and
rotation are deferred to a later phase.

### 4. Single role per user, enforced with explicit dependencies

Each user carries one role from the Section 5 set (administrator,
security_operator, pentest_approver, remediation_owner, auditor, viewer).
Authorization is a `require_roles(...)` FastAPI dependency: unauthenticated
requests get 401, authenticated-but-unauthorized get 403. A single role keeps
checks explicit and easy to test; finer-grained or multi-role assignment can be
added later without changing the enum values.

### 5. Organization scoping from day one

Every query is filtered by the caller's `organization_id`, and cross-tenant
access returns 404 (never disclosing that another tenant's resource exists).
The MVP ships a single organization but the isolation is enforced and tested
now.

### 6. Append-only audit log, written in-transaction

`AuditEvent` is append-only (no update/delete API; only an immutable
`created_at`). Audit records are written in the same transaction as the action
they describe, so a change and its audit entry commit together. Security-
relevant failures that end in an error response (e.g. failed logins) explicitly
commit their audit record before raising, so the trail survives the rollback of
the failed request.

### 7. Network-scope safety rules live in pure, unit-tested functions

CIDR normalization, default-route rejection (`0.0.0.0/0`, `::/0`), public-range
denial (overridable per scope), and overlap detection are implemented as pure
functions with no database access, so these security-critical rules are covered
by fast unit tests independent of the API. Any scope change bumps a
`policy_version` that probes will use (Phase 3) to detect stale local policy.

## Consequences

- The test suite is hermetic (in-memory SQLite, dependency-overridden session),
  so it runs anywhere without external services, while production behavior on
  PostgreSQL is preserved by keeping all types dialect-portable.
- Bootstrapping requires operators to supply a real (deliverable) admin email;
  special-use TLDs such as `.local` are rejected by email validation.
- Stateless JWTs mean logout is client-side (token discard); server-side token
  revocation lists are a later concern tracked alongside API tokens.

## Alternatives considered

- **Sync SQLAlchemy:** rejected to match FastAPI's async model and the ADR 0001
  direction; portability to SQLite for tests is retained regardless.
- **Server-side sessions:** rejected for the MVP; stateless JWTs avoid shared
  session storage and suit the API-first design. Revocation is revisited later.
- **Passlib:** rejected in favor of `argon2-cffi` directly, which is actively
  maintained and keeps the hashing parameters explicit.
