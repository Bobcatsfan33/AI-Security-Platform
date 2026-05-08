"""FastAPI application factory.

Sprint 1 wires:
    - structured logging
    - correlation ID middleware
    - CORS
    - /v1 router with: /healthz, /readyz, /auth/oidc/..., /policies/..., /admin/idp-configs/...
    - shared Redis client lifecycle
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.middleware import CorrelationIdMiddleware
from app.api.v1 import auth as auth_routes
from app.api.v1 import health as health_routes
from app.api.v1 import idp_admin as idp_admin_routes
from app.api.v1 import policies as policies_routes
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.security.audit_log import AuditEventType, log_event
from app.security.secret_gate import assert_production_secrets
from app.services.redis_client import close_redis, get_redis


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings)
    log = get_logger("startup")
    log.info(
        "platform_starting",
        version=__version__,
        environment=settings.environment,
    )

    # Refuse to serve traffic with a known-weak secret in production.
    assert_production_secrets()

    # Eagerly open the Redis connection so a misconfiguration fails fast at boot.
    await get_redis()

    log_event(
        AuditEventType.STARTUP,
        resource="platform",
        detail={"version": __version__, "environment": settings.environment},
    )

    yield

    log.info("platform_stopping")
    log_event(AuditEventType.SHUTDOWN, resource="platform")
    await close_redis()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AI Security Platform",
        version=__version__,
        description="Control plane API — Sprint 1 (infrastructure + identity federation)",
        lifespan=lifespan,
        openapi_url=f"{settings.api_v1_prefix}/openapi.json",
        docs_url=f"{settings.api_v1_prefix}/docs",
        redoc_url=f"{settings.api_v1_prefix}/redoc",
    )

    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    prefix = settings.api_v1_prefix
    app.include_router(health_routes.router, prefix=prefix)
    app.include_router(auth_routes.router, prefix=f"{prefix}/auth")
    app.include_router(idp_admin_routes.router, prefix=f"{prefix}/admin/idp-configs")
    app.include_router(policies_routes.router, prefix=f"{prefix}/policies")

    return app


app = create_app()
