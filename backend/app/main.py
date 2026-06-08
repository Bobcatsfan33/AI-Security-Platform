"""FastAPI application factory.

v2.0 pivot: this is the AI Asset Intelligence Platform — two product
wedges only.

  Track 1: Asset Inventory + Connectors (this sprint)
  Track 2: Runtime Monitoring (already wired, untouched by the pivot)

Governance modules (redteam, policy, evaluation, findings, test_cases,
scim, aibom, mcp, idp_admin) remain on disk for git history but are
NOT registered as routes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.middleware import CorrelationIdMiddleware
from app.api.v1 import aiguard as aiguard_routes
from app.api.v1 import assets as assets_routes
from app.api.v1 import auth as auth_routes
from app.api.v1 import benchmark as benchmark_routes
from app.api.v1 import connectors as connectors_routes
from app.api.v1 import dashboard as dashboard_routes
from app.api.v1 import discovery as discovery_routes
from app.api.v1 import health as health_routes
from app.api.v1 import narratives as narratives_routes
from app.api.v1 import redteam as redteam_routes
from app.api.v1 import remediation as remediation_routes
from app.api.v1 import risk_index as risk_index_routes
from app.api.v1 import runtime as runtime_routes
from app.api.v1 import suppressions as suppressions_routes
from app.api.v1 import validation as validation_routes
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.observability.metrics import render
from app.observability.middleware import MetricsMiddleware
from app.observability.tracing import setup_tracing
from app.security.audit_log import AuditEventType, log_event
from app.security.headers import RequestValidationMiddleware, SecurityHeadersMiddleware
from app.security.secret_gate import assert_production_secrets
from app.services.redis_client import close_redis, get_redis
from app.streaming.events import set_producer
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

    assert_production_secrets()
    await get_redis()
    await start_writer()

    # AI Guard → narrative bridge: install the process-wide publisher so a
    # block/detect verdict on /v1/aiguard/inspect lands as a Tier-3 narrative
    # in the same Redis store the EPA consumer writes and the workbench reads.
    from app.aiguard.publish import build_default_publisher, set_publisher

    set_publisher(await build_default_publisher())

    # Streaming spine — start the Redpanda producer when enabled. Best-effort:
    # a broker that's down must not block startup (telemetry is best-effort;
    # ClickHouse is the durable store).
    if settings.streaming_enabled:
        from app.streaming.kafka_backend import build_producer

        producer = build_producer(
            brokers=settings.redpanda_brokers,
            topic=settings.runtime_events_topic,
        )
        await producer.start()
        set_producer(producer)
        log.info("streaming_producer_enabled", topic=settings.runtime_events_topic)

    log_event(
        AuditEventType.STARTUP,
        resource="platform",
        detail={"version": __version__, "environment": settings.environment},
    )

    yield

    log.info("platform_stopping")
    log_event(AuditEventType.SHUTDOWN, resource="platform")
    await stop_writer()

    from app.streaming.events import get_producer

    producer = get_producer()
    if producer is not None:
        await producer.stop()
        set_producer(None)

    from app.aiguard.publish import set_publisher

    set_publisher(None)
    await close_redis()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AI Asset Intelligence Platform",
        version="2.0.0",
        description=(
            "Discover every AI system. Monitor every model. " "Know your risk before auditors ask."
        ),
        lifespan=lifespan,
        openapi_url=f"{settings.api_v1_prefix}/openapi.json",
        docs_url=f"{settings.api_v1_prefix}/docs",
        redoc_url=f"{settings.api_v1_prefix}/redoc",
    )

    # Middleware execution order is the REVERSE of registration order in
    # Starlette. Register from outermost (first to see request) to innermost.
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
    app.add_middleware(MetricsMiddleware)

    # Optional OpenTelemetry tracing (no-op unless OTEL endpoint + packages).
    setup_tracing(app)

    prefix = settings.api_v1_prefix
    app.include_router(health_routes.router, prefix=prefix)
    app.include_router(auth_routes.router, prefix=f"{prefix}/auth")
    app.include_router(connectors_routes.router, prefix=f"{prefix}/connectors")
    app.include_router(assets_routes.router, prefix=f"{prefix}/assets")
    app.include_router(discovery_routes.router, prefix=f"{prefix}/discovery")
    app.include_router(dashboard_routes.router, prefix=f"{prefix}/dashboard")
    app.include_router(runtime_routes.router, prefix=f"{prefix}/runtime")
    app.include_router(narratives_routes.router, prefix=f"{prefix}/narratives")
    app.include_router(suppressions_routes.router, prefix=f"{prefix}/suppressions")
    app.include_router(validation_routes.router, prefix=f"{prefix}/validation")
    app.include_router(aiguard_routes.router, prefix=f"{prefix}/aiguard")
    app.include_router(remediation_routes.router, prefix=f"{prefix}/remediation")
    app.include_router(risk_index_routes.router, prefix=f"{prefix}/risk-index")
    app.include_router(benchmark_routes.router, prefix=f"{prefix}/benchmark")
    app.include_router(redteam_routes.router, prefix=f"{prefix}/redteam")

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        body, content_type = render()
        return Response(content=body, media_type=content_type)

    return app


app = create_app()
