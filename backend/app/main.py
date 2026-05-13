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
from app.api.v1 import aibom as aibom_routes
from app.api.v1 import anomalies as anomalies_routes
from app.api.v1 import assets as assets_routes
from app.api.v1 import compliance as compliance_routes
from app.api.v1 import auth as auth_routes
from app.api.v1 import connectors as connectors_routes
from app.api.v1 import dashboards as dashboards_routes
from app.api.v1 import evaluations as evaluations_routes
from app.api.v1 import findings as findings_routes
from app.api.v1 import health as health_routes
from app.api.v1 import idp_admin as idp_admin_routes
from app.api.v1 import mcp as mcp_routes
from app.api.v1 import policies as policies_routes
from app.api.v1 import redteam as redteam_routes
from app.api.v1 import reports as reports_routes
from app.api.v1 import runtime as runtime_routes
from app.api.v1 import scim as scim_routes
from app.api.v1 import siem as siem_routes
from app.api.v1 import test_cases as test_cases_routes
from app.api.v1 import threat_intel as threat_intel_routes
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.security.audit_log import AuditEventType, log_event
from app.security.headers import RequestValidationMiddleware, SecurityHeadersMiddleware
from app.security.secret_gate import assert_production_secrets
from app.services.redis_client import close_redis, get_redis
from app.siem.forwarder import get_forwarder
from app.telemetry.clickhouse_writer import start_writer, stop_writer


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

    # Background telemetry writer (drains a queue to ClickHouse every 5s).
    await start_writer()

    # SIEM forwarder — fans audit/finding/runtime events to org SIEMs.
    await get_forwarder().start()

    log_event(
        AuditEventType.STARTUP,
        resource="platform",
        detail={"version": __version__, "environment": settings.environment},
    )

    yield

    log.info("platform_stopping")
    log_event(AuditEventType.SHUTDOWN, resource="platform")
    await get_forwarder().stop()
    await stop_writer()
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

    # Middleware execution order is the REVERSE of registration order in
    # Starlette. We register from outermost (first to see request) to
    # innermost. So:
    #   1. SecurityHeadersMiddleware (outermost — adds headers to every
    #      response, even errors emitted by other middlewares)
    #   2. CORSMiddleware
    #   3. CorrelationIdMiddleware
    #   4. RequestValidationMiddleware (innermost — runs just before routing,
    #      rejects malformed requests early)
    app.add_middleware(RequestValidationMiddleware)
    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(SecurityHeadersMiddleware)

    prefix = settings.api_v1_prefix
    app.include_router(health_routes.router, prefix=prefix)
    app.include_router(auth_routes.router, prefix=f"{prefix}/auth")
    app.include_router(idp_admin_routes.router, prefix=f"{prefix}/admin/idp-configs")
    app.include_router(policies_routes.router, prefix=f"{prefix}/policies")
    app.include_router(connectors_routes.router, prefix=f"{prefix}/connectors")
    app.include_router(assets_routes.router, prefix=f"{prefix}/assets")
    app.include_router(test_cases_routes.router, prefix=f"{prefix}/test-cases")
    app.include_router(evaluations_routes.router, prefix=f"{prefix}/evaluations")
    app.include_router(findings_routes.router, prefix=f"{prefix}/findings")
    app.include_router(redteam_routes.router, prefix=f"{prefix}/redteam")
    app.include_router(reports_routes.router, prefix=f"{prefix}/reports")
    app.include_router(runtime_routes.router, prefix=f"{prefix}/runtime")
    app.include_router(mcp_routes.router, prefix=f"{prefix}/mcp")
    app.include_router(aibom_routes.router, prefix=f"{prefix}/aibom")
    app.include_router(scim_routes.router, prefix=f"{prefix}/scim/v2")
    app.include_router(siem_routes.router, prefix=f"{prefix}/admin/siem")
    app.include_router(dashboards_routes.router, prefix=f"{prefix}/dashboards")
    app.include_router(anomalies_routes.router, prefix=f"{prefix}/anomalies")
    app.include_router(threat_intel_routes.router, prefix=f"{prefix}/threat-intel")
    app.include_router(compliance_routes.router, prefix=f"{prefix}/compliance")

    return app


app = create_app()
