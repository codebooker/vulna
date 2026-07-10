# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Phase 0: Repository foundation

- Monorepo directory structure for VulnaDash, VulnaScout, and supporting
  components (`watch/`, `verify/`, `forge/`, `pulse/`, `lab/`, `shared/`).
- VulnaDash backend: FastAPI application with `/health`, `/api/v1/system/info`,
  and `/api/v1/system/health` endpoints; pinned dependencies; Ruff + mypy
  configuration; pytest suite; non-root Dockerfile.
- VulnaDash frontend: Vite + React + TypeScript application with a health page
  that reports backend connectivity; ESLint + Prettier; Vitest test; non-root
  Dockerfile served by nginx with a `/health` route.
- VulnaScout probe: Go module with `version` and `self-test` subcommands,
  internal package skeleton, unit test, and multi-arch Dockerfile.
- Development stack: `docker-compose.dev.yml` (Postgres, Redis, API, frontend)
  and a production-oriented `docker-compose.yml` skeleton with health checks.
- Shared JSON Schemas for job, result, plugin, and policy documents (drafts).
- `Makefile` with `dev`, `test`, `lint`, and component targets.
- GitHub Actions CI for backend, frontend, and probe (including `amd64` and
  `arm64` cross-compilation), plus issue and pull-request templates.
- Documentation: architecture overview, threat-model skeleton, authorized-use
  and rules-of-engagement guides, and ADR 0001 (initial architecture).

[Unreleased]: https://github.com/codebooker/vulna/commits/main
