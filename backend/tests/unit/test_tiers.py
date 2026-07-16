"""Tier registry and the Tier C feature-flag mechanism.

The tiering map in ``docs/TIERS.md`` is a claim, so it points at something
mechanically checked — these tests are that something. They assert the three
properties the map promises:

1. Tier C is deny-by-default and *absent*, not merely forbidden.
2. Tier B is self-describing as preview in the OpenAPI schema.
3. The registry cannot silently disagree with what actually mounts.
"""

from __future__ import annotations

import pathlib
from collections.abc import Callable, Iterator

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute

from app.core.config import get_settings
from app.core.tiers import (
    PREVIEW_TAG,
    ROUTER_TIERS,
    RouterSpec,
    Tier,
    prefixes_for_tier,
    spec_for,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def build_app(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., FastAPI]]:
    """Build a fresh app with the given PLATFORM_ENABLE_* env, bypassing the
    settings cache on the way in and out."""

    def _build(**env: str) -> FastAPI:
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        get_settings.cache_clear()
        from app.main import create_app

        return create_app()

    yield _build
    get_settings.cache_clear()


def _paths(app: FastAPI) -> list[str]:
    return [r.path for r in app.routes if isinstance(r, APIRoute)]


def _routes_under(app: FastAPI, prefix: str) -> list[APIRoute]:
    full = f"/v1{prefix}"
    return [
        r
        for r in app.routes
        if isinstance(r, APIRoute) and (r.path == full or r.path.startswith(f"{full}/"))
    ]


# ─────────────────────────────────────────── registry integrity


def test_tier_c_router_must_be_flag_gated() -> None:
    """Deny-by-default is structural: a Tier C spec without a flag cannot be
    constructed, so it cannot be forgotten."""
    with pytest.raises(ValueError, match="deny-by-default"):
        RouterSpec("/oops", Tier.C, "no flag")


def test_only_tier_c_is_flag_gated() -> None:
    """A flag on Tier A/B would mean a shipped surface can vanish by config —
    that is a tiering mistake, not a feature."""
    with pytest.raises(ValueError, match="only Tier C"):
        RouterSpec("/oops", Tier.A, "flagged", flag="platform_enable_threat_intel")


def test_every_tier_c_flag_is_a_real_setting() -> None:
    settings = get_settings()
    for prefix in prefixes_for_tier(Tier.C):
        flag = ROUTER_TIERS[prefix].flag
        assert flag is not None
        assert hasattr(settings, flag), f"{prefix}: flag {flag!r} is not a Settings field"


def test_tier_c_flags_default_to_off() -> None:
    """The whole point of frozen: a deployment that sets nothing gets nothing."""
    from app.core.config import Settings

    settings = Settings(jwt_secret="x" * 40)
    for prefix in prefixes_for_tier(Tier.C):
        flag = ROUTER_TIERS[prefix].flag
        assert getattr(settings, flag) is False, f"{prefix}: {flag} must default off"


def test_unregistered_prefix_cannot_mount() -> None:
    with pytest.raises(KeyError, match="no tier assignment"):
        spec_for("/not-a-real-router")


# ─────────────────────────────────────────── Tier C: absent, not forbidden


def test_threat_intel_is_absent_by_default(build_app: Callable[..., FastAPI]) -> None:
    app = build_app()
    assert not _routes_under(
        app, "/threat-intel"
    ), "cross-tenant clustering is Tier C and must not mount by default"


def test_threat_intel_mounts_when_pulled_forward(build_app: Callable[..., FastAPI]) -> None:
    app = build_app(PLATFORM_ENABLE_THREAT_INTEL="true")
    assert _routes_under(app, "/threat-intel"), "flag on must mount the router"


def test_dark_tier_c_is_not_in_the_openapi_schema(build_app: Callable[..., FastAPI]) -> None:
    """A frozen capability is invisible, not a documented 403. An evaluator
    reading /v1/openapi.json must not find a surface we do not stand behind."""
    schema = build_app().openapi()
    assert not [p for p in schema["paths"] if p.startswith("/v1/threat-intel")]


# ─────────────────────────────────────────── Tier B: labelled preview


def test_tier_b_routes_are_tagged_preview(build_app: Callable[..., FastAPI]) -> None:
    app = build_app()
    for prefix in prefixes_for_tier(Tier.B):
        routes = _routes_under(app, prefix)
        assert routes, f"{prefix} is Tier B but mounted no routes"
        for route in routes:
            assert PREVIEW_TAG in route.tags, f"{route.path} is Tier B but not tagged preview"


def test_tier_a_routes_are_not_tagged_preview(build_app: Callable[..., FastAPI]) -> None:
    """The preview label has to mean something — if Tier A carried it too, it
    would carry no information."""
    app = build_app()
    for prefix in prefixes_for_tier(Tier.A):
        for route in _routes_under(app, prefix):
            assert PREVIEW_TAG not in route.tags, f"{route.path} is Tier A but tagged preview"


def test_preview_tag_is_described_in_the_schema(build_app: Callable[..., FastAPI]) -> None:
    schema = build_app().openapi()
    tags = {t["name"]: t.get("description", "") for t in schema.get("tags", [])}
    assert PREVIEW_TAG in tags, "the preview tag must carry a description in the schema"
    assert "TIERS.md" in tags[PREVIEW_TAG]


# ─────────────────────────────────────────── registry ↔ reality


def test_every_mounted_route_belongs_to_a_registered_router(
    build_app: Callable[..., FastAPI],
) -> None:
    """No route may exist outside the tiering map. This is what keeps
    docs/TIERS.md true as routers come and go.

    Matched on the first path segment rather than by prefix: the health router
    registers at ``""``, so a prefix match against ``/v1`` would accept every
    path and quietly assert nothing.
    """
    from app.api.v1 import health as health_routes

    app = build_app(PLATFORM_ENABLE_THREAT_INTEL="true")
    health_paths = {f"/v1{r.path}" for r in health_routes.router.routes if isinstance(r, APIRoute)}

    unmapped: list[str] = []
    for path in _paths(app):
        if not path.startswith("/v1/") or path in health_paths:
            continue
        segment = "/" + path[len("/v1/") :].split("/", 1)[0]
        if segment not in ROUTER_TIERS:
            unmapped.append(path)
    assert not unmapped, f"routes with no tier assignment: {unmapped}"


def test_every_registered_router_actually_mounts(build_app: Callable[..., FastAPI]) -> None:
    """The inverse: a registry entry for a router nobody mounts is a claim with
    nothing behind it."""
    app = build_app(PLATFORM_ENABLE_THREAT_INTEL="true")
    missing = [p for p in ROUTER_TIERS if not _routes_under(app, p)]
    assert not missing, f"registered but not mounted: {missing}"


# ─────────────────────────────────────────── backend ↔ frontend parity


def _frontend_tier_b_routes() -> list[str]:
    """Parse TIER_B_ROUTES out of the PreviewBadge component.

    Deliberately a regex over the source rather than a build step: the parity
    that matters is between two hand-maintained lists, and a test that needs
    npm to run is a test that stops running.
    """
    import re

    source = _PREVIEW_BADGE_TSX.read_text(encoding="utf-8")
    block = re.search(r"TIER_B_ROUTES[^=]*=\s*\[(.*?)\]", source, re.DOTALL)
    assert block, "could not find TIER_B_ROUTES in PreviewBadge.tsx"
    return re.findall(r'"([^"]+)"', block.group(1))


_PREVIEW_BADGE_TSX = (
    pathlib.Path(__file__).resolve().parents[3]
    / "frontend"
    / "src"
    / "components"
    / "PreviewBadge.tsx"
)


@pytest.mark.skipif(not _PREVIEW_BADGE_TSX.exists(), reason="frontend not checked out")
def test_frontend_preview_routes_match_backend_tier_b() -> None:
    """The badge a user sees and the tag the API reports are the same claim, so
    they must not drift. Backed by PreviewBadge.tsx's own docstring pointing
    here."""
    backend = set(prefixes_for_tier(Tier.B))
    frontend = set(_frontend_tier_b_routes())

    assert frontend == backend, (
        "frontend TIER_B_ROUTES has drifted from the backend tier registry.\n"
        f"  badged in UI but not Tier B: {sorted(frontend - backend)}\n"
        f"  Tier B but unbadged in UI:   {sorted(backend - frontend)}"
    )
