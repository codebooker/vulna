# VulnaDash Backend

FastAPI application for the Vulna central orchestrator (VulnaDash).

**Phase 0 scope:** application skeleton with health and system-info endpoints,
configuration via environment variables, linting/type-checking, and tests. No
authentication, database, or assessment functionality yet — those arrive in
later phases.

## Development

```bash
# From dash/backend/
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run the API with autoreload
uvicorn app.main:app --reload --port 8000

# Health check
curl http://localhost:8000/health

# Tests, lint, types
pytest
ruff check .
mypy app
```

## Endpoints (Phase 0)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness probe (no auth) |
| GET | `/api/v1/system/health` | Structured health payload |
| GET | `/api/v1/system/info` | Service name, version, and environment |
