"""Router coverage ratchet — every mounted router earns HTTP tests.

Background: the Phase 0 audit found that 4 of 25 mounted routers had any test
that goes through the HTTP layer, and only one router had a tenant-isolation
test. Service-level unit tests sit *beneath* the router, so they exercise
neither the request/response contract nor — the part that matters — the auth
and org-scoping dependencies that are declared in the route signature. A
service can be perfectly tenant-safe while the route above it leaks.

Rather than chase that ad hoc, this is a ratchet in the style of
``test_no_broken_imports``: the exemption list is allowed to shrink and never
grow. Two tests hold the door open one way:

* :func:`test_no_unexempted_router_lacks_http_tests` fails for any *new* router
  mounted without tests.
* :func:`test_exemptions_are_not_stale` fails once an exempt router *gains*
  tests, forcing it off the list. An exemption cannot outlive its excuse.

Detection is deliberately coarse — it greps the test sources for calls against
the router's prefix. It proves a request was made, not that it was made well.
That is the right bar for a ratchet: cheap, no false failures, and it makes
"there are no HTTP tests here" a fact the suite knows rather than a fact an
audit rediscovers.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from app.core.tiers import ROUTER_TIERS

pytestmark = pytest.mark.unit

_TESTS_ROOT = pathlib.Path(__file__).resolve().parent.parent
_API_PREFIX = "/v1"

# Test files that specifically assert cross-org isolation.
_TENANT_ISOLATION_FILES = ("test_tenant_isolation.py", "test_tenant_guard.py")


# ──────────────────────────────────────────────────────────────────
# The exemption list. THIS LIST MAY ONLY SHRINK.
#
# Phase 1 retires the Tier A rows (/mcp, /anomalies, /aiguard, /policies,
# /runtime) — those are the spearhead and a design partner will probe them
# first. Tier B and substrate rows follow as their phases land. Do not add a
# row here to make a new router pass; write the test instead.
# ──────────────────────────────────────────────────────────────────
NEEDS_HTTP_TESTS: dict[str, str] = {
    "/auth": "Phase 4 — service-level tests only (SAML/OIDC/JWT); no HTTP-layer test.",
    "/anomalies": "Phase 1 — attack graph + anomaly efficacy suite lands here.",
    "/dashboards": "Phase 4 — operability phase covers the runtime views.",
    "/runtime": "Phase 2 — covered by the agent failure-mode matrix.",
    "/narratives": "Phase 4 — service tests only (test_narratives, test_narrative_store).",
    "/policies": "Phase 2 — policy cache behaviour is tested from the agent side first.",
    "/suppressions": "Phase 4 — no tests at any layer.",
    "/validation": "Phase 3 — detection efficacy phase covers the scorecard surface.",
    "/aiguard": "Phase 1 — Stage-2/Stage-3 backends; detector suite tested at service level.",
    "/remediation": "Phase 4 — no tests at any layer.",
    "/risk-index": "Phase 4 — service tests only (test_risk_index_model).",
    "/benchmark": "Phase 3 — offline evaluation runner supersedes this surface.",
    "/redteam": "Phase 3 — auto-promotion loop test covers campaigns.",
    "/evaluations": "Phase 4 — Tier B preview; no tests at any layer.",
    "/findings": "Phase 4 — Tier B preview; no tests at any layer.",
    "/test-cases": "Phase 4 — Tier B preview; no tests at any layer.",
    "/threat-intel": "Tier C frozen — dark by default; retire the row or the router.",
    "/compliance": "Phase 5 — service tests only (test_compliance_matrix).",
    "/reports": "Phase 5 — Tier B preview; no tests at any layer.",
    "/mcp": "Phase 1 — the spearhead. First row to retire.",
}

# Tenant isolation is a separate, stricter claim: guardrail 2 says every
# tenant-scoped surface proves a sibling org cannot read it. Today exactly one
# integration test covers 4 routers.
NEEDS_TENANT_ISOLATION_TESTS: dict[str, str] = dict(NEEDS_HTTP_TESTS)


_SELF = pathlib.Path(__file__).resolve()


def _test_sources() -> dict[pathlib.Path, str]:
    """Every test source except this file — its docstrings quote example calls
    like ``client.get("/v1/mcp/tools")``, and scanning itself would credit a
    router with coverage that is only prose."""
    return {
        path: path.read_text(encoding="utf-8")
        for path in _TESTS_ROOT.rglob("test_*.py")
        if "__pycache__" not in path.parts and path.resolve() != _SELF
    }


def _calls_prefix(source: str, prefix: str) -> bool:
    """Whether the source drives a request against this router's prefix.

    Matches the call itself (``client.get("/v1/mcp/tools")``) rather than
    looking for an ``AsyncClient`` import plus a bare path string: the client
    arrives as a conftest fixture, so the import never appears in the test file
    that actually makes the request.

    The path must terminate at a quote or a ``/`` so that ``/v1/assets`` is not
    credited by a call to ``/v1/assets-something``.
    """
    full = re.escape(f"{_API_PREFIX}{prefix}")
    pattern = rf'client\.(?:get|post|put|patch|delete|request)\(\s*f?"{full}(?:["/?])'
    return re.search(pattern, source) is not None


def _routers_with_http_tests() -> set[str]:
    found: set[str] = set()
    for source in _test_sources().values():
        for prefix in ROUTER_TIERS:
            if prefix and _calls_prefix(source, prefix):
                found.add(prefix)
    return found


def _routers_with_tenant_isolation_tests() -> set[str]:
    found: set[str] = set()
    for path, source in _test_sources().items():
        if path.name not in _TENANT_ISOLATION_FILES:
            continue
        for prefix in ROUTER_TIERS:
            if prefix and _calls_prefix(source, prefix):
                found.add(prefix)
    return found


def _gated_prefixes() -> set[str]:
    """Routers subject to the ratchet: everything registered except the bare
    health router, which has no prefix to grep for."""
    return {p for p in ROUTER_TIERS if p}


# ─────────────────────────────────────────── the ratchet


def test_no_unexempted_router_lacks_http_tests() -> None:
    """A newly mounted router must arrive with an HTTP test."""
    covered = _routers_with_http_tests()
    missing = sorted(_gated_prefixes() - covered - set(NEEDS_HTTP_TESTS))
    assert not missing, (
        "These mounted routers have no HTTP-layer test. Write one — do not add "
        f"them to NEEDS_HTTP_TESTS: {missing}"
    )


def test_no_unexempted_router_lacks_tenant_isolation_tests() -> None:
    """Guardrail 2: every tenant-scoped surface proves a sibling org sees
    nothing."""
    covered = _routers_with_tenant_isolation_tests()
    missing = sorted(_gated_prefixes() - covered - set(NEEDS_TENANT_ISOLATION_TESTS))
    assert not missing, "These mounted routers have no cross-org isolation test: " f"{missing}"


# ─────────────────────────────────────────── the one-way door


def test_exemptions_are_not_stale() -> None:
    """Once a router gains HTTP tests, its exemption must go. This is what makes
    the list shrink-only: coverage you add is coverage you keep."""
    covered = _routers_with_http_tests()
    stale = sorted(covered & set(NEEDS_HTTP_TESTS))
    assert not stale, (
        "These routers now have HTTP tests — remove them from NEEDS_HTTP_TESTS "
        f"so the ratchet holds the ground you took: {stale}"
    )


def test_tenant_isolation_exemptions_are_not_stale() -> None:
    covered = _routers_with_tenant_isolation_tests()
    stale = sorted(covered & set(NEEDS_TENANT_ISOLATION_TESTS))
    assert not stale, (
        "These routers now have tenant-isolation tests — remove them from "
        f"NEEDS_TENANT_ISOLATION_TESTS: {stale}"
    )


def test_exemptions_reference_real_routers() -> None:
    """An exemption for a router that no longer mounts is dead weight that
    makes the list look worse than reality."""
    gated = _gated_prefixes()
    for name, listing in (
        ("NEEDS_HTTP_TESTS", NEEDS_HTTP_TESTS),
        ("NEEDS_TENANT_ISOLATION_TESTS", NEEDS_TENANT_ISOLATION_TESTS),
    ):
        unknown = sorted(set(listing) - gated)
        assert not unknown, f"{name} lists unregistered routers: {unknown}"


def test_every_exemption_carries_a_reason() -> None:
    """A reason with a phase is a plan. A bare TODO is a hope."""
    for prefix, reason in NEEDS_HTTP_TESTS.items():
        assert len(reason) > 20, f"{prefix}: exemption needs a real reason"
        assert (
            "Phase" in reason or "Tier C" in reason
        ), f"{prefix}: exemption must name the phase that retires it"
