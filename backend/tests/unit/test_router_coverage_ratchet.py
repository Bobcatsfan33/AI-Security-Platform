"""Router coverage ratchet — every mounted router earns HTTP tests.

Background: the Phase 0 audit found that only 4 routers — /connectors, /assets,
/discovery, /dashboard — had any test that goes through the HTTP layer, out of
the 24 that mount by default (25 registered, minus /threat-intel, which is Tier
C and dark). The same 4 are the only ones with a cross-org isolation test.
Service-level unit tests sit *beneath* the router, so they exercise
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

# Test files that specifically assert cross-org isolation.
_TENANT_ISOLATION_FILES = ("test_tenant_isolation.py", "test_tenant_guard.py")


def _api_prefix() -> str:
    """The mount prefix actually in force. Read at call time rather than
    hardcoded, matching test_tiers.py — an assumed "/v1" silently credits
    nothing when the prefix is configured differently, and a ratchet that
    quietly measures zero is worse than no ratchet."""
    from app.core.config import get_settings

    return get_settings().api_v1_prefix


# ──────────────────────────────────────────────────────────────────
# The exemption lists. THEY MAY ONLY SHRINK.
#
# There are TWO lists, written out in full, and they are deliberately NOT
# derived from one another. HTTP coverage and tenant-isolation coverage are
# different claims that get satisfied at different times: the first HTTP test
# for a router usually lands before its cross-org test does.
#
# An earlier version had NEEDS_TENANT_ISOLATION_TESTS = dict(NEEDS_HTTP_TESTS),
# which coupled them at import: retiring a row from the HTTP list (as
# test_exemptions_are_not_stale forces the moment an HTTP test lands) also
# silently retired it from the tenant-isolation list, breaking that ratchet
# unless BOTH test types landed in the same commit. That is an accidental
# policy, and not one we want — so the duplication here is the point. Keep them
# separate even when their contents happen to match.
#
# Phase 1 retires the Tier A rows (/mcp, /anomalies, /aiguard, /policies,
# /runtime) — the spearhead, which a design partner probes first. Tier B and
# substrate rows follow as their phases land. Do not add a row to make a new
# router pass; write the test instead.
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
    # /mcp retired here: test_mcp_api.py drives all 8 endpoints over HTTP. Its
    # tenant-isolation row below stays until the cross-org test lands (the two
    # ratchets shrink separately, by design — see this module's header).
}

# Guardrail 2: every tenant-scoped surface proves a sibling org cannot read it.
# A stricter claim than "an HTTP test exists", and tracked separately.
NEEDS_TENANT_ISOLATION_TESTS: dict[str, str] = {
    "/auth": "Phase 4 — org-scoping is asserted at the service layer only.",
    "/anomalies": "Phase 1 — lands with the attack graph HTTP tests.",
    "/dashboards": "Phase 4 — operability phase.",
    "/runtime": "Phase 2 — telemetry ingest is org-scoped by agent credential.",
    "/narratives": "Phase 4 — no cross-org test at any layer.",
    "/policies": "Phase 2 — a policy leak across orgs is a Tier A concern; tested with the mounts.",
    "/suppressions": "Phase 4 — no tests at any layer.",
    "/validation": "Phase 3 — detection efficacy phase.",
    "/aiguard": "Phase 1 — lands with the Tier A HTTP tests.",
    "/remediation": "Phase 4 — no tests at any layer.",
    "/risk-index": "Phase 4 — service tests only.",
    "/benchmark": "Phase 3 — superseded by the offline evaluation runner.",
    "/redteam": "Phase 3 — campaigns are org-scoped; untested across orgs.",
    "/evaluations": "Phase 4 — Tier B preview.",
    "/findings": "Phase 4 — Tier B preview.",
    "/test-cases": "Phase 4 — Tier B preview.",
    "/threat-intel": "Tier C frozen — dark by default. Cross-TENANT by design; see docs/TIERS.md.",
    "/compliance": "Phase 5 — evidence packs are org-scoped; untested across orgs.",
    "/reports": "Phase 5 — Tier B preview.",
    "/mcp": "Phase 1 — the spearhead. First row to retire.",
}


_SELF = pathlib.Path(__file__).resolve()


def _strip_comments(source: str) -> str:
    """Drop comment lines before matching.

    A commented-out call — ``# client.get("/v1/auth/login")`` — would otherwise
    credit /auth with coverage and, worse, force-retire its exemption via the
    staleness test while no test exists. The ratchet would then have talked
    itself into believing in a test nobody wrote.

    Line-level rather than a real tokenizer: it removes whole-line comments and
    trailing ones, which is the shape this actually occurs in. A ``#`` inside a
    string literal on a line that also makes a client call would truncate that
    line — the failure mode is UNDER-crediting, which the ratchet treats as
    "write a test", not as a false pass.

    KNOWN LIMIT — docstrings are not stripped. A test file that quotes
    ``client.get("/v1/mcp/tools")`` inside a docstring still credits /mcp and
    force-retires its exemption, exactly as a comment used to. This module
    dodges its own trap by excluding itself (see :func:`_test_sources`), which
    is not a general fix. Stripping docstrings needs an ``ast`` walk rather than
    a line filter; deferred because the remaining hole requires someone to
    document a call they did not write, whereas commenting out a call you *did*
    write is a normal thing to do while debugging. If this bites, the fix is
    ``ast.parse`` + drop every ``Expr(Constant(str))``.
    """
    out: list[str] = []
    for line in source.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(line.split("#", 1)[0] if "#" in line else line)
    return "\n".join(out)


def _test_sources() -> dict[pathlib.Path, str]:
    """Every test source except this file, comments stripped.

    This file is excluded because its docstrings quote example calls like
    ``client.get("/v1/mcp/tools")``; scanning itself would credit a router with
    coverage that is only prose.
    """
    return {
        path: _strip_comments(path.read_text(encoding="utf-8"))
        for path in _TESTS_ROOT.rglob("test_*.py")
        if "__pycache__" not in path.parts and path.resolve() != _SELF
    }


def _calls_prefix(source: str, prefix: str) -> bool:
    """Whether the source drives a request against this router's prefix.

    Matches the call itself (``client.get("/v1/mcp/tools")``) rather than
    looking for an ``AsyncClient`` import plus a bare path string: the client
    arrives as a conftest fixture, so the import never appears in the test file
    that actually makes the request.

    The path must terminate at a quote, ``/`` or ``?`` so that ``/v1/assets`` is
    not credited by a call to ``/v1/assets-something``.
    """
    full = re.escape(f"{_api_prefix()}{prefix}")
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


def test_a_commented_out_call_does_not_count_as_coverage() -> None:
    """The ratchet must not be talked into believing in a test nobody wrote.

    Without comment stripping, `# client.get("/v1/auth/login")` credits /auth
    with coverage AND force-retires its exemption via the staleness test — the
    ratchet would then demand you delete the exemption for a test that does not
    exist.
    """
    real = 'await client.get("/v1/auth/login")'
    commented = '# await client.get("/v1/auth/login")'
    trailing = 'x = 1  # await client.get("/v1/auth/login")'

    assert _calls_prefix(_strip_comments(real), "/auth") is True
    assert _calls_prefix(_strip_comments(commented), "/auth") is False
    assert _calls_prefix(_strip_comments(trailing), "/auth") is False


def test_the_two_exemption_lists_are_independent() -> None:
    """HTTP and tenant-isolation coverage are different claims satisfied at
    different times, so their lists must be able to shrink independently.

    Guards the specific regression: `NEEDS_TENANT_ISOLATION_TESTS =
    dict(NEEDS_HTTP_TESTS)` made one a copy of the other, so retiring an HTTP
    row silently retired the isolation row too — coupling that would only
    surface as a confusing ratchet failure months later.

    Asserted on VALUES, not identity: `dict(NEEDS_HTTP_TESTS)` produces a
    distinct object, so an `is not` check would sail straight past the bug. The
    lists happen to share keys today (both exempt the same 20 routers), so what
    distinguishes "written independently" from "copied" is that each row's
    reason is about ITS OWN claim.
    """
    assert NEEDS_TENANT_ISOLATION_TESTS != NEEDS_HTTP_TESTS, (
        "the exemption lists are value-identical, which means one was derived "
        "from the other. They must be independent literals so the two ratchets "
        "can shrink separately — see this module's header."
    )


def test_every_exemption_carries_a_reason() -> None:
    """A reason with a phase is a plan. A bare TODO is a hope."""
    for prefix, reason in NEEDS_HTTP_TESTS.items():
        assert len(reason) > 20, f"{prefix}: exemption needs a real reason"
        assert (
            "Phase" in reason or "Tier C" in reason
        ), f"{prefix}: exemption must name the phase that retires it"
