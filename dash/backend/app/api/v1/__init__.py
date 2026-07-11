"""Version 1 of the VulnaDash REST API."""

from fastapi import APIRouter

from app.api.v1 import (
    assets,
    audit,
    auth,
    changes,
    cve,
    dashboard,
    diagnostics,
    feeds,
    findings,
    jobs,
    maintenance,
    networking,
    notifications,
    onboarding,
    organizations,
    pentest,
    presets,
    probes,
    reports,
    resources,
    risk_acceptances,
    scopes,
    sites,
    system,
    users,
    workflows,
)

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(system.router)
api_router.include_router(auth.router)
api_router.include_router(organizations.router)
api_router.include_router(users.router)
api_router.include_router(sites.router)
api_router.include_router(scopes.router)
api_router.include_router(probes.router)
api_router.include_router(jobs.router)
api_router.include_router(dashboard.router)
api_router.include_router(diagnostics.router)
api_router.include_router(maintenance.router)
api_router.include_router(notifications.router)
api_router.include_router(dashboard.search_router)
api_router.include_router(networking.router)
api_router.include_router(onboarding.router)
api_router.include_router(presets.router)
api_router.include_router(resources.router)
api_router.include_router(assets.router)
api_router.include_router(changes.router)
api_router.include_router(findings.router)
api_router.include_router(risk_acceptances.router)
api_router.include_router(pentest.router)
api_router.include_router(workflows.router)
api_router.include_router(feeds.router)
api_router.include_router(cve.router)
api_router.include_router(reports.router)
api_router.include_router(audit.router)
