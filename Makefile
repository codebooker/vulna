# Vulna developer Makefile.
# Run `make help` for a list of targets.

BACKEND_DIR := dash/backend
FRONTEND_DIR := dash/frontend
SCOUT_DIR := scout

# Prefer a python3.12+ interpreter for the backend.
PYTHON ?= python3

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Dev stack
# ---------------------------------------------------------------------------

.PHONY: dev
dev: ## Start the development stack (Postgres, Redis, API, frontend)
	docker compose -f docker-compose.dev.yml up --build

.PHONY: dev-down
dev-down: ## Stop and remove the development stack
	docker compose -f docker-compose.dev.yml down

.PHONY: up
up: ## Start the production-oriented stack
	docker compose up -d --build

.PHONY: down
down: ## Stop the production-oriented stack
	docker compose down

# ---------------------------------------------------------------------------
# Backend (VulnaDash API)
# ---------------------------------------------------------------------------

.PHONY: backend-install
backend-install: ## Install backend dependencies into a local venv
	cd $(BACKEND_DIR) && $(PYTHON) -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"

.PHONY: backend-dev
backend-dev: ## Run the backend with autoreload on :8000
	cd $(BACKEND_DIR) && . .venv/bin/activate && uvicorn app.main:app --reload --port 8000

.PHONY: backend-test
backend-test: ## Run backend tests
	cd $(BACKEND_DIR) && . .venv/bin/activate && pytest

.PHONY: backend-lint
backend-lint: ## Lint and type-check the backend
	cd $(BACKEND_DIR) && . .venv/bin/activate && ruff check . && mypy app

.PHONY: backend-migrate
backend-migrate: ## Apply database migrations (alembic upgrade head)
	cd $(BACKEND_DIR) && . .venv/bin/activate && alembic upgrade head

.PHONY: backend-revision
backend-revision: ## Autogenerate a migration (usage: make backend-revision m="message")
	cd $(BACKEND_DIR) && . .venv/bin/activate && alembic revision --autogenerate -m "$(m)"

.PHONY: backend-bootstrap
backend-bootstrap: ## Seed the default org and first admin from the environment
	cd $(BACKEND_DIR) && . .venv/bin/activate && vulna bootstrap-admin

# ---------------------------------------------------------------------------
# Frontend (VulnaDash UI)
# ---------------------------------------------------------------------------

.PHONY: frontend-install
frontend-install: ## Install frontend dependencies
	cd $(FRONTEND_DIR) && npm install

.PHONY: frontend-dev
frontend-dev: ## Run the Vite dev server on :5173
	cd $(FRONTEND_DIR) && npm run dev

.PHONY: frontend-build
frontend-build: ## Type-check and build the frontend
	cd $(FRONTEND_DIR) && npm run build

.PHONY: frontend-test
frontend-test: ## Run frontend tests
	cd $(FRONTEND_DIR) && npm run test

.PHONY: frontend-lint
frontend-lint: ## Lint and format-check the frontend
	cd $(FRONTEND_DIR) && npm run lint && npm run format:check

# ---------------------------------------------------------------------------
# Probe (VulnaScout)
# ---------------------------------------------------------------------------

.PHONY: probe-build
probe-build: ## Build the VulnaScout binary into scout/bin
	cd $(SCOUT_DIR) && go build -o bin/vulnascout ./cmd/vulnascout

.PHONY: probe-build-all
probe-build-all: ## Cross-compile the probe for linux/amd64 and linux/arm64
	cd $(SCOUT_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/vulnascout-linux-amd64 ./cmd/vulnascout
	cd $(SCOUT_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/vulnascout-linux-arm64 ./cmd/vulnascout

.PHONY: probe-test
probe-test: ## Run probe tests and vet
	cd $(SCOUT_DIR) && go vet ./... && go test ./...

.PHONY: probe-lint
probe-lint: ## Check probe formatting
	cd $(SCOUT_DIR) && test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

.PHONY: test
test: backend-test frontend-test probe-test ## Run all tests

.PHONY: lint
lint: backend-lint frontend-lint probe-lint ## Run all linters / type checks

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(SCOUT_DIR)/bin $(FRONTEND_DIR)/dist
	find $(BACKEND_DIR) -type d -name __pycache__ -prune -exec rm -rf {} +
