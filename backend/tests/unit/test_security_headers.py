"""Tests for SecurityHeadersMiddleware and RequestValidationMiddleware.

Uses Starlette's TestClient against a minimal app so we don't pull in the
full FastAPI lifespan (which requires Redis).
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.security.headers import (
    RequestValidationMiddleware,
    SecurityHeadersMiddleware,
)


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/v1/anything")
    def _anything() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/v1/echo")
    async def _echo(payload: dict) -> dict:  # type: ignore[type-arg]
        return payload

    app.add_middleware(RequestValidationMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    return app


@pytest.fixture
def client() -> TestClient:
    return TestClient(_build_app())


@pytest.mark.unit
class TestSecurityHeaders:
    def test_hsts_present(self, client: TestClient) -> None:
        resp = client.get("/v1/anything")
        assert resp.status_code == 200
        hsts = resp.headers["strict-transport-security"]
        assert "max-age=" in hsts
        assert "includeSubDomains" in hsts

    def test_csp_default_is_strict(self, client: TestClient) -> None:
        resp = client.get("/v1/anything")
        csp = resp.headers["content-security-policy"]
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp

    def test_x_frame_options_deny(self, client: TestClient) -> None:
        assert client.get("/v1/anything").headers["x-frame-options"] == "DENY"

    def test_nosniff(self, client: TestClient) -> None:
        assert client.get("/v1/anything").headers["x-content-type-options"] == "nosniff"

    def test_referrer_policy(self, client: TestClient) -> None:
        assert (
            client.get("/v1/anything").headers["referrer-policy"]
            == "strict-origin-when-cross-origin"
        )

    def test_permissions_policy_locks_browser_apis(self, client: TestClient) -> None:
        pp = client.get("/v1/anything").headers["permissions-policy"]
        for feature in ("camera=()", "microphone=()", "geolocation=()"):
            assert feature in pp

    def test_server_header_scrubbed(self, client: TestClient) -> None:
        assert client.get("/v1/anything").headers["server"] == "Platform"

    def test_cache_control_on_v1_paths(self, client: TestClient) -> None:
        resp = client.get("/v1/anything")
        assert "no-store" in resp.headers["cache-control"]


@pytest.mark.unit
class TestRequestValidation:
    def test_rejects_oversized_body(self, client: TestClient) -> None:
        # Manually claim a huge content-length
        big = "x" * 100
        resp = client.post(
            "/v1/echo",
            content=big,
            headers={"Content-Length": "99999999", "Content-Type": "application/json"},
        )
        assert resp.status_code == 413

    def test_rejects_oversized_header(self, client: TestClient) -> None:
        # 9000-byte header value > 8192 limit
        resp = client.get("/v1/anything", headers={"X-Long": "y" * 9000})
        assert resp.status_code == 431

    def test_rejects_non_json_content_type_on_post(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/echo", content="<xml/>", headers={"Content-Type": "application/xml"}
        )
        assert resp.status_code == 415

    def test_accepts_application_json(self, client: TestClient) -> None:
        resp = client.post("/v1/echo", json={"hello": "world"})
        assert resp.status_code == 200

    def test_accepts_scim_json(self, client: TestClient) -> None:
        resp = client.post(
            "/v1/echo",
            content='{"hello":"world"}',
            headers={"Content-Type": "application/scim+json"},
        )
        assert resp.status_code == 200

    def test_does_not_break_get_with_no_body(self, client: TestClient) -> None:
        assert client.get("/v1/anything").status_code == 200


@pytest.mark.unit
class TestCustomCspOrigins:
    def test_constructor_accepts_extra_script_origins(self) -> None:
        app = FastAPI()

        @app.get("/v1/x")
        def _x() -> dict[str, bool]:
            return {"ok": True}

        app.add_middleware(
            SecurityHeadersMiddleware,
            allowed_script_origins=("https://cdn.example.com",),
        )
        client = TestClient(app)
        csp = client.get("/v1/x").headers["content-security-policy"]
        assert "https://cdn.example.com" in csp
