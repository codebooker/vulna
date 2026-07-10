"""VulnaDash FastAPI application entry point.

Phase 1 introduces local authentication, RBAC, organizations, sites, network
scopes, and append-only audit logging on top of the Phase 0 health/system
surface. The database and bootstrap seeding are wired here through the
application lifespan.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.v1 import api_router
from app.core.config import get_settings
from app.db.base import Base
from app.db.session import dispose_engine, get_engine, get_sessionmaker
from app.schemas.system import HealthResponse
from app.services.bootstrap import run_bootstrap


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize the database and seed bootstrap data on startup."""
    settings = get_settings()

    if settings.auto_create_tables:
        # Import models so every table is registered on the metadata, then
        # create any that are missing. Production relies on Alembic migrations
        # instead (auto_create_tables stays disabled there).
        from app import models as _models  # noqa: F401

        engine = get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    # Seed the default organization and, if configured, the first administrator.
    factory = get_sessionmaker()
    async with factory() as session:
        await run_bootstrap(session, settings)
        await session.commit()

    try:
        yield
    finally:
        await dispose_engine()


def create_app() -> FastAPI:
    """Application factory: build and configure the FastAPI app."""
    settings = get_settings()

    app = FastAPI(
        title="VulnaDash API",
        version=__version__,
        summary="Central orchestrator API for the Vulna security-assessment platform.",
        docs_url="/docs",
        openapi_url="/openapi.json",
        lifespan=lifespan,
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
