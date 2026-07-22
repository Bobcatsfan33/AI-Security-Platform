"""FastAPI application factory.

Every router mounts through :data:`app.core.tiers.ROUTER_TIERS`, which is the
single source of truth for the tiering map documented in ``docs/TIERS.md``:

* Tier A mounts always and is held to reference quality.
* Tier B mounts always, tagged ``preview`` in the OpenAPI schema.
* Tier C is frozen and deny-by-default — it mounts only when its
  ``PLATFORM_ENABLE_*`` flag is set, and is otherwise absent from the schema
  entirely (not a 403).

Mounting an unregistered prefix raises: a new router must be tiered first.

Known limit, stated so nobody mistakes this for airtight: enforcement is
convention plus a test, not structure. ``mount()`` is the only tiered path, but
nothing *prevents* a future caller from reaching past it to
``app.include_router`` directly. The backstop is
``test_every_mounted_route_belongs_to_a_registered_router``, which walks the
published schema — and it only checks paths under ``settings.api_v1_prefix``.
So a router mounted directly at, say, ``/internal`` would be untiered AND
invisible to the ratchet. Acceptable today (every surface is ``/v1``); if a
second prefix ever appears, that test needs to widen before the surface lands.

Still on disk but NOT mounted, by design (Tier C frozen — see docs/GAPS.md
for the promotion triggers): ``scim`` and ``idp_admin`` (enterprise
provisioning; OIDC login covers a design-partner POC). ``siem`` (Tier B) and
``aibom`` (Tier A, GAP-001) both mount here with full HTTP + tenant-isolation
tests; aibom's router was adapted to the v2 ``metadata_json`` model and its
function proven against a real asset row before this mount.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api.middleware import CorrelationIdMiddleware
from app.api.v1 import aibom as aibom_routes
from app.api.v1 import aiguard as aiguard_routes
from app.api.v1 import anomalies as anomalies_routes
from app.api.v1 import assets as assets_routes
from app.api.v1 import auth as auth_routes
from app.api.v1 import benchmark as benchmark_routes
from app.api.v1 import compliance as compliance_routes
from app.api.v1 import connectors as connectors_routes
from app.api.v1 import dashboard as dashboard_routes
from app.api.v1 import dashboards as dashboards_routes
from app.api.v1 import discovery as discovery_routes
from app.api.v1 import evaluations as evaluations_routes
from app.api.v1 import findings as findings_routes
from app.api.v1 import health as health_routes
from app.api.v1 import mcp as mcp_routes
from app.api.v1 import narratives as narratives_routes
from app.api.v1 import policies as policies_routes
from app.api.v1 import redteam as redteam_routes
from app.api.v1 import remediation as remediation_routes
from app.api.v1 import reports as reports_routes
from app.api.v1 import risk_index as risk_index_routes
from app.api.v1 import runtime as runtime_routes
from app.api.v1 import siem as siem_routes
from app.api.v1 import suppressions as suppressions_routes
from app.api.v1 import test_cases as test_cases_routes
from app.api.v1 import threat_intel as threat_intel_routes
from app.api.v1 import validation as validation_routes
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.core.tiers import PREVIEW_TAG, Tier, spec_for
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

    # Wall 1 of tenant isolation: arm the ORM guard before the first request so
    # every tenant-scoped ORM query is org-filtered automatically (see
    # app/db/tenancy.py). Wall 2 (Postgres RLS) is enforced by the DB.
    from app.db.tenancy import install_tenant_guard

    install_tenant_guard()

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
    log = get_logger("startup")
    app = FastAPI(
        title="AI Asset Intelligence Platform",
        version="2.0.0",
        description=(
            "Discover every AI system. Monitor every model. " "Know your risk before auditors ask."
        ),
        lifespan=lifespan,
        openapi_tags=[
            {
                "name": PREVIEW_TAG,
                "description": (
                    "**Preview.** Shipped and usable, but not held to the "
                    "hardening bar of the agent/MCP security surface: expect "
                    "thinner tests, unbenchmarked performance, and breaking "
                    "changes without a deprecation window. Not recommended as "
                    "the load-bearing surface of a production integration. "
                    "See docs/TIERS.md."
                ),
            }
        ],
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

    def mount(router: APIRouter, rel_prefix: str) -> None:
        """Mount one router at its registered tier, or not at all."""
        spec = spec_for(rel_prefix)
        if spec.flag is not None and not getattr(settings, spec.flag):
            log.info(
                "router_not_mounted_tier_c",
                prefix=rel_prefix,
                flag=spec.flag.upper(),
            )
            return
        app.include_router(
            router,
            prefix=f"{settings.api_v1_prefix}{rel_prefix}",
            # Appends to the router's own tags, so a Tier B surface is
            # self-describing in /v1/docs without touching 25 route decorators.
            tags=[PREVIEW_TAG] if spec.tier is Tier.B else None,
        )

    mount(health_routes.router, "")
    mount(auth_routes.router, "/auth")
    mount(connectors_routes.router, "/connectors")
    mount(assets_routes.router, "/assets")
    mount(discovery_routes.router, "/discovery")
    mount(anomalies_routes.router, "/anomalies")
    mount(dashboard_routes.router, "/dashboard")
    mount(dashboards_routes.router, "/dashboards")
    mount(runtime_routes.router, "/runtime")
    mount(narratives_routes.router, "/narratives")
    mount(policies_routes.router, "/policies")
    mount(suppressions_routes.router, "/suppressions")
    mount(validation_routes.router, "/validation")
    mount(aiguard_routes.router, "/aiguard")
    mount(remediation_routes.router, "/remediation")
    mount(risk_index_routes.router, "/risk-index")
    mount(benchmark_routes.router, "/benchmark")
    mount(redteam_routes.router, "/redteam")
    # Governance revival (WS1/WS2) — models + tables restored in 0008.
    mount(evaluations_routes.router, "/evaluations")
    mount(findings_routes.router, "/findings")
    mount(test_cases_routes.router, "/test-cases")
    mount(threat_intel_routes.router, "/threat-intel")
    mount(compliance_routes.router, "/compliance")
    mount(reports_routes.router, "/reports")
    mount(mcp_routes.router, "/mcp")
    # GAP-001: SIEM exporter config, now reachable. The Tier B pair
    # (Splunk/Elastic) is usable out of the box; the four Tier C exporter types
    # stay gated inside the exporter builder, not here.
    mount(siem_routes.router, "/siem")
    # GAP-001 part 2: AI-BOM (Tier A) — adapted to the v2 metadata_json model,
    # with the computed blast-radius endpoint. Function proven against a real
    # asset row before this mount.
    mount(aibom_routes.router, "/aibom")

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        body, content_type = render()
        return Response(content=body, media_type=content_type)

    return app


app = create_app()
