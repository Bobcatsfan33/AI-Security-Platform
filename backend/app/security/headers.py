"""Security headers + request hygiene middleware.

NIST 800-53 Rev5: SC-8 (transmission integrity), SC-28 (protection at rest),
SI-10 (input validation).

Origin: ported from TokenDNA ``modules/security/headers.py``. Adapted to
the platform's path conventions (``/v1/`` instead of ``/api/`` + ``/admin/``)
and to coexist with the existing :class:`CorrelationIdMiddleware`.

Two middlewares:

:class:`SecurityHeadersMiddleware`
    Adds HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy, Cross-Origin-* headers to every response. Scrubs
    the Server fingerprint.

:class:`RequestValidationMiddleware`
    SI-10 surface: rejects null-byte URLs, oversized headers, oversized
    bodies, and non-JSON content types on mutation endpoints.

Both are wired in :func:`app.main.create_app`. Order matters — validation
runs first (rejects bad input before anything else processes it), then
correlation-ID, then security-headers (so headers are added on every
response, including error responses).
"""

from __future__ import annotations

import os
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp


# ─────────────────────────────────────────────── Security headers


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add the full defensive HTTP header set to every response."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        csp_report_uri: str = "",
        server_header: str = "Platform",
        allowed_script_origins: tuple[str, ...] = (),
        allowed_style_origins: tuple[str, ...] = (),
    ) -> None:
        super().__init__(app)
        self.csp_report_uri = csp_report_uri
        self.server_header = server_header
        self.allowed_script_origins = allowed_script_origins
        self.allowed_style_origins = allowed_style_origins

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response: Response = await call_next(request)

        # HSTS: 2 years, includeSubDomains, preload-eligible
        response.headers["Strict-Transport-Security"] = (
            "max-age=63072000; includeSubDomains; preload"
        )

        # CSP — strict default. Frontend (Next.js, Sprint 11) may extend via
        # constructor args. 'unsafe-inline' is included for now to keep the
        # FastAPI auto-generated /v1/docs Swagger UI working in dev; the
        # production deployment should override this constructor.
        script_src = ["'self'", "'unsafe-inline'", *self.allowed_script_origins]
        style_src = ["'self'", "'unsafe-inline'", *self.allowed_style_origins]
        csp_parts = [
            "default-src 'self'",
            f"script-src {' '.join(script_src)}",
            f"style-src {' '.join(style_src)}",
            "font-src 'self' data:",
            "img-src 'self' data:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "object-src 'none'",
        ]
        if self.csp_report_uri:
            csp_parts.append(f"report-uri {self.csp_report_uri}")
        response.headers["Content-Security-Policy"] = "; ".join(csp_parts)

        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), bluetooth=()"
        )

        # Cross-Origin isolation
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        # COEP=require-corp would block cross-origin images served without
        # CORP=cross-origin; not required for an API. Leave off by default.

        # Cache-Control for API responses (paths under /v1/)
        if request.url.path.startswith("/v1/"):
            response.headers["Cache-Control"] = (
                "no-store, no-cache, must-revalidate, private"
            )
            response.headers["Pragma"] = "no-cache"

        # Scrub server fingerprint
        response.headers["Server"] = self.server_header
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]

        return response


# ─────────────────────────────────────────────── Request validation


# Hard limit on request body. Configurable via env. Default 1 MB — well above
# any reasonable JSON API call but small enough that an attacker cannot
# stream a gigabyte of payload to exhaust resources before the JSON parser
# even runs.
MAX_REQUEST_BODY_BYTES_DEFAULT: int = 1 * 1024 * 1024


def _max_body_bytes() -> int:
    raw = os.getenv("MAX_REQUEST_BODY_BYTES", "")
    if raw.isdigit():
        return int(raw)
    return MAX_REQUEST_BODY_BYTES_DEFAULT


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """SI-10 input validation surface — runs before any route handler."""

    _MAX_HEADER_VALUE_LEN = 8192
    _MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    # Paths where we enforce JSON content-type on mutations. SCIM uses
    # ``application/scim+json`` and is allowed via the substring check below.
    _PROTECTED_PREFIXES = ("/v1/",)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Null byte in URL — injection precursor
        if "\x00" in str(request.url):
            return Response(
                content='{"detail":"invalid_request"}',
                status_code=400,
                media_type="application/json",
            )

        # Oversized headers — defense against header smuggling and resource
        # exhaustion
        for _, header_value in request.headers.items():
            if len(header_value) > self._MAX_HEADER_VALUE_LEN:
                return Response(
                    content='{"detail":"header_too_large"}',
                    status_code=431,
                    media_type="application/json",
                )

        # Body size enforcement when client honestly declares Content-Length
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > _max_body_bytes():
            return Response(
                content='{"detail":"request_body_too_large"}',
                status_code=413,
                media_type="application/json",
            )

        # Content-Type enforcement on mutation endpoints
        if (
            request.method in self._MUTATION_METHODS
            and any(request.url.path.startswith(p) for p in self._PROTECTED_PREFIXES)
            and "content-type" in request.headers
        ):
            ctype = request.headers["content-type"].lower()
            allowed = (
                "application/json" in ctype
                or "application/scim+json" in ctype
                or "multipart/" in ctype
                or "application/x-www-form-urlencoded" in ctype
            )
            if not allowed:
                return Response(
                    content='{"detail":"unsupported_content_type"}',
                    status_code=415,
                    media_type="application/json",
                )

        return await call_next(request)
