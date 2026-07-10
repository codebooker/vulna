"""Version 1 of the VulnaDash REST API."""

from fastapi import APIRouter

from app.api.v1 import (
    assets,
    audit,
    auth,
    changes,
    findings,
    jobs,
    organizations,
    probes,
    scopes,
    sites,
    system,
    users,
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
api_router.include_router(assets.router)
api_router.include_router(changes.router)
api_router.include_router(findings.router)
api_router.include_router(audit.router)
