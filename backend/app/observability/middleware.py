"""HTTP metrics middleware — records golden-signal metrics per request.

Uses the matched ROUTE TEMPLATE (e.g. /v1/narratives/{narrative_id}) rather
than the raw path so label cardinality stays bounded under per-id traffic.
"""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.observability.metrics import HTTP_IN_PROGRESS, HTTP_LATENCY, HTTP_REQUESTS


def _route_template(request: Request) -> str:
    """The matched route path, or a coarse fallback. Resolved post-dispatch
    from the matched route; before matching we use the raw path's first two
    segments to avoid unbounded cardinality."""
    route = request.scope.get("route")
    if route is not None and getattr(route, "path", None):
        return route.path
    parts = request.url.path.strip("/").split("/")[:2]
    return "/" + "/".join(parts) if parts and parts[0] else "/"


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        method = request.method
        # The route isn't matched yet here; use a coarse in-progress label.
        coarse = _route_template(request)
        HTTP_IN_PROGRESS.labels(method=method, route=coarse).inc()
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            duration = time.perf_counter() - start
            route = _route_template(request)  # now matched
            status_class = f"{status // 100}xx"
            HTTP_REQUESTS.labels(method=method, route=route, status=status_class).inc()
            HTTP_LATENCY.labels(method=method, route=route).observe(duration)
            HTTP_IN_PROGRESS.labels(method=method, route=coarse).dec()
