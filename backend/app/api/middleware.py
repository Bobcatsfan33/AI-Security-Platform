"""Middleware: request correlation IDs + structured access logs."""

from __future__ import annotations

import time
import uuid
from typing import Awaitable, Callable

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from structlog.contextvars import bind_contextvars, clear_contextvars

logger = structlog.get_logger("http")

CORRELATION_ID_HEADER = "X-Correlation-Id"


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Bind a correlation ID to every request so all logs in the request scope share it.

    If the client supplies an X-Correlation-Id header, we honor it (useful when a CI/CD
    pipeline or upstream service is tracing a flow). Otherwise we generate a uuid4.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        correlation_id = request.headers.get(CORRELATION_ID_HEADER) or str(uuid.uuid4())
        clear_contextvars()
        bind_contextvars(
            correlation_id=correlation_id,
            method=request.method,
            path=request.url.path,
        )
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("request_failed")
            raise
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        response.headers[CORRELATION_ID_HEADER] = correlation_id
        logger.info(
            "request_completed",
            status=response.status_code,
            duration_ms=duration_ms,
        )
        return response
