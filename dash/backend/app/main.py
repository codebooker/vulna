"""VulnaDash FastAPI application entry point.

Phase 0: exposes health and system-info endpoints only. Authentication, the
database layer, workers, and assessment functionality are introduced in later
phases.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1 import api_router
from app.core.config import get_settings
from app.schemas.system import HealthResponse


def create_app() -> FastAPI:
    """Application factory: build and configure the FastAPI app."""
    settings = get_settings()

    app = FastAPI(
        title="VulnaDash API",
        version=__version__,
        summary="Central orchestrator API for the Vulna security-assessment platform.",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router)

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        """Liveness probe used by Docker/Compose health checks and the frontend."""
        return HealthResponse(status="ok", service=settings.app_name, version=__version__)

    return app


app = create_app()
