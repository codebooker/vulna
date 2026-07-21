"""VulnaDash FastAPI application entry point.

Phase 1 introduces local authentication, RBAC, organizations, sites, network
scopes, and append-only audit logging on top of the Phase 0 health/system
surface. The database and bootstrap seeding are wired here through the
application lifespan.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.api.scim import router as scim_router
from app.api.v1 import api_router
from app.core.config import Settings, get_settings
from app.db.base import Base
from app.db.session import (
    dispose_engine,
    get_engine,
    get_session,
    get_sessionmaker,
    set_maintenance_context,
)
from app.schemas.system import HealthResponse
from app.services.bootstrap import run_bootstrap
from app.services.metrics import render_metrics

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize the database and seed bootstrap data on startup."""
    settings = get_settings()
    settings.validate_for_startup()

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
        docs_url=("/docs" if settings.env != "production" or settings.expose_api_docs else None),
        openapi_url=(
            "/openapi.json" if settings.env != "production" or settings.expose_api_docs else None
        ),
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
    app.include_router(scim_router)

    from app.services.scim import ScimError, error_response, log_failed_request

    @app.exception_handler(ScimError)
    async def scim_error_handler(request: Request, error: ScimError) -> Response:
        await log_failed_request(request, error)
        return error_response(error)

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        """Liveness probe used by Docker/Compose health checks and the frontend."""
        return HealthResponse(status="ok", service=settings.app_name)

    @app.get("/metrics", response_class=PlainTextResponse, tags=["system"], include_in_schema=False)
    async def metrics(
        session: Annotated[AsyncSession, Depends(get_session)],
        settings_dep: Annotated[Settings, Depends(get_settings)],
    ) -> str:
        """Prometheus metrics (aggregate only; no sensitive labels). Scrape this
        on the internal network — do not expose it through the public proxy."""
        await set_maintenance_context(session)
        return await render_metrics(session, settings_dep, datetime.now(UTC))

    return app


app = create_app()
