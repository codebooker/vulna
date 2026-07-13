# VulnaDash Backend

FastAPI application for the Vulna central orchestrator (VulnaDash).

**Current scope (through Phase 1):** health/system endpoints plus local
authentication, role-based access control, organizations, sites, network scopes,
append-only audit logging, an async SQLAlchemy data layer, and Alembic
migrations. Probe enrollment, assessments, and reporting arrive in later phases.

## Development

```bash
# From dash/backend/  (requires Python 3.12+)
python -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements-dev.lock
pip install --no-build-isolation --no-deps -e .

# A signing secret is required for authentication.
export VULNA_SECRET_KEY="$(openssl rand -base64 48)"

# Point at a database. For a quick local run without PostgreSQL you can use
# SQLite and let the app create tables on startup:
export VULNA_DATABASE_URL="sqlite+aiosqlite:///./vulna.db"
export VULNA_AUTO_CREATE_TABLES=true

# Optionally seed a first administrator (use a real, deliverable email).
export VULNA_ADMIN_EMAIL="admin@example.com"
export VULNA_ADMIN_PASSWORD="a-strong-password"

# Run the API with autoreload
uvicorn app.main:app --reload --port 8000

# Health check
curl http://localhost:8000/health

# Tests, lint, types
pytest
ruff check .
mypy app
```

Against PostgreSQL, omit `VULNA_AUTO_CREATE_TABLES` and apply migrations:

```bash
alembic upgrade head          # or: make backend-migrate
vulna bootstrap-admin         # seed org + admin from the environment
```

## CLI

```bash
vulna version
vulna bootstrap-admin [--create-tables]
```

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | none | Liveness probe |
| GET | `/api/v1/system/health` | none | Structured health payload |
| GET | `/api/v1/system/info` | `system.read` | Service name, version, environment |
| POST | `/api/v1/auth/login` | none | Obtain a JWT access token |
| GET | `/api/v1/auth/me` | user | Current user profile |
| GET/PATCH | `/api/v1/organizations/{id}` | user / admin | Read / update organization |
| GET/POST/PATCH/DELETE | `/api/v1/users` | admin | Manage users |
| GET/POST/PATCH/DELETE | `/api/v1/sites` | read: user, write: admin | Manage sites |
| GET/POST/PATCH/DELETE | `/api/v1/scopes` | read: user, write: admin | Manage network scopes |
| POST | `/api/v1/scopes/{id}/approve` | admin | Record scope approval |
| GET | `/api/v1/audit` | admin / auditor | Read the append-only audit log |

## Layout

```
app/
  api/v1/     REST routers (auth, users, organizations, sites, scopes, audit, system)
  auth/       password hashing, JWT tokens, RBAC dependencies
  core/       settings
  db/         declarative base, mixins, async engine/session
  models/     ORM models
  schemas/    Pydantic request/response models
  services/   audit, scope validation, bootstrap
  cli.py      `vulna` console entry point
  main.py     app factory + lifespan
alembic/      migration environment and versions
```

When dependencies change, regenerate both reviewed lock files with Python 3.12
and pip-tools 7.5.2:

```bash
pip-compile pyproject.toml --all-build-deps --generate-hashes --strip-extras \
  --allow-unsafe -o requirements.lock
pip-compile pyproject.toml --extra dev --generate-hashes --strip-extras \
  --all-build-deps --allow-unsafe -o requirements-dev.lock
```
