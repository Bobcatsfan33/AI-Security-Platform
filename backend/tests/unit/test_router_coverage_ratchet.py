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

HTTP detection is deliberately coarse — it greps the test sources for calls
against the router's prefix. It proves a request was made, not that it was made
well. That is the right bar for *that* ratchet: cheap, no false failures, and it
makes "there are no HTTP tests here" a fact the suite knows rather than a fact
an audit rediscovers.

**Tenant-isolation detection is not coarse, because it cannot afford to be
(P12.1).** It used to be: a module-level allowlist of files, and any prefix a
listed file *touched* was credited with proving cross-org isolation for that
router. Contact is not proof. In P12 that nearly credited ``/auth`` on the
strength of ``test_me_reflects_the_presented_identity`` — a single-org test that
asserts the presented token describes itself, which says nothing whatsoever
about what a *sibling* org can see. The credit was caught by hand and earned
with a real test instead, but "caught by hand" is exactly the property a ratchet
is supposed to remove.

The rule now has three conjuncts, all mechanical, and a claim must satisfy every
one of them:

1. **Declared** — the test carries ``@pytest.mark.tenant_isolation`` (on the
   function or on its class). Isolation coverage is now an explicit claim rather
   than a side effect of which file a request happened to live in.
2. **Real** — the marked test actually drives a request against the prefix it
   credits. A marker cannot conjure coverage for a router the test never calls.
3. **Cross-org** — the marked test takes at least two org identities (a pair
   fixture like ``two_orgs``, or two singles like ``org`` + ``other_org``). One
   org cannot demonstrate that a second org is excluded; the claim is not merely
   unproven in that case, it is unprovable.

Conjuncts 2 and 3 are enforced *against the marker itself* by
:func:`test_a_tenant_isolation_marker_must_be_earned`: a marked test that drives
nothing, or that holds only one org, is a hard failure rather than a silent
non-credit. Otherwise the marker would decay into decoration — someone marks a
test, the detector quietly declines to credit it, and the exemption row survives
while everyone believes it did not. Loud is the point.

What this deliberately does NOT do is judge the assertions. A test can satisfy
all three conjuncts and still assert something weak. That is a code-review
question, and pretending a regex can answer it would be the same overreach the
old detector made in the other direction. What the ratchet now guarantees is
narrower and actually true: every credited router has a test that was *declared*
to prove isolation, *does* call that router, and *has two tenants to compare*.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

from app.core.tiers import ROUTER_TIERS

pytestmark = pytest.mark.unit

_TESTS_ROOT = pathlib.Path(__file__).resolve().parent.parent

# The marker that declares a cross-org isolation claim. Registered in
# pyproject.toml because the suite runs --strict-markers, so a typo here is a
# collection error rather than a test that silently stops counting.
_ISOLATION_MARKER = "tenant_isolation"

# Fixtures that supply MORE THAN ONE org in a single parameter. A test taking
# one of these has two tenants to compare even though it names one fixture.
_ORG_PAIR_FIXTURES = frozenset({"two_orgs", "org_pair"})

# Fixtures that supply exactly one org. Two DISTINCT names from this set means
# two tenants.
#
# An explicit registry rather than a regex on purpose: a regex like `.*org.*`
# would count `org_slug`, `org_name`, or `reorganize` as tenants and hand back
# the false credit this whole mechanism exists to prevent. A new org fixture
# has to be added here, which is a one-line, reviewable act — and forgetting to
# add it fails loudly (the marker check reports "0 org fixtures") instead of
# silently dropping the credit.
_ORG_FIXTURES = frozenset({"org", "other_org", "org_a", "org_b", "foreign_org"})


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
    "/anomalies": "Phase 1 — attack graph + anomaly efficacy suite lands here.",
    "/dashboards": "Phase 4 — operability phase covers the runtime views.",
    "/runtime": "Phase 2 — covered by the agent failure-mode matrix.",
    "/narratives": "Phase 4 — service tests only (test_narratives, test_narrative_store).",
    "/suppressions": "Phase 4 — no tests at any layer.",
    "/validation": "Phase 3 — detection efficacy phase covers the scorecard surface.",
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
    #
    # /policies retired in P12: test_api_authorization.py drives the router over
    # HTTP for authn, role authorization, malformed input, and cross-org access.
    # Its tenant-isolation row went at the same time — unusually, both ratchets
    # shrank in one commit because the same file carries both classes of test.
}

# Guardrail 2: every tenant-scoped surface proves a sibling org cannot read it.
# A stricter claim than "an HTTP test exists", and tracked separately.
NEEDS_TENANT_ISOLATION_TESTS: dict[str, str] = {
    "/anomalies": "Phase 1 — lands with the attack graph HTTP tests.",
    "/dashboards": "Phase 4 — operability phase.",
    "/runtime": "Phase 2 — telemetry ingest is org-scoped by agent credential.",
    "/narratives": "Phase 4 — no cross-org test at any layer.",
    "/suppressions": "Phase 4 — no tests at any layer.",
    "/validation": "Phase 3 — detection efficacy phase.",
    "/aiguard": "Phase 1 — HTTP contract covered; cross-org behavior still needs an isolation test.",
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
    # /mcp retired: test_tenant_isolation.py::test_mcp_is_org_scoped proves a
    # sibling org sees none of A's profiles/calls/violations (404-not-403).
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

    KNOWN LIMIT — docstrings are not stripped *here*. A test file that quotes
    ``client.get("/v1/mcp/tools")`` inside a docstring still credits /mcp for
    HTTP coverage, exactly as a comment used to. This module dodges its own trap
    by excluding itself (see :func:`_test_sources`), which is not a general fix.
    :func:`_scannable` closes the hole with the ``ast`` walk this docstring used
    to defer, but only on the tenant-isolation path, where a false credit is a
    false security claim. The HTTP ratchet keeps the cheaper line filter: over-
    crediting there costs an exemption row someone must justify in review, not a
    silent assertion that a tenant boundary was tested.

    LINE-PRESERVING: a stripped line becomes empty rather than disappearing, so
    line numbers still line up with an ``ast`` parse of the ORIGINAL source.
    :func:`_scannable` slices functions out by ``lineno``, and dropping lines
    here would shift every function below the first comment.
    """
    out: list[str] = []
    for line in source.splitlines():
        if line.lstrip().startswith("#"):
            out.append("")
            continue
        out.append(line.split("#", 1)[0] if "#" in line else line)
    return "\n".join(out)


def _scannable(source: str) -> list[str]:
    """``source`` as lines, with comments AND string-literal statements blanked.

    Blanking bare string expressions removes every docstring — module, class,
    and function — so a call quoted in prose cannot be mistaken for a call the
    test makes. Line numbering is preserved throughout so the result can be
    sliced by the line numbers of an ``ast`` parse of the original text.
    """
    lines = _strip_comments(source).splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:  # pragma: no cover - a test file that does not parse
        return lines
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            for index in range(node.lineno - 1, (node.end_lineno or node.lineno)):
                if 0 <= index < len(lines):
                    lines[index] = ""
    return lines


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


def _has_isolation_marker(node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether ``@pytest.mark.tenant_isolation`` decorates this node.

    Accepts the bare form and the called form, since ``pytest.mark.x`` and
    ``pytest.mark.x()`` are both legal and mean the same thing.
    """
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if (
            isinstance(target, ast.Attribute)
            and target.attr == _ISOLATION_MARKER
            and isinstance(target.value, ast.Attribute)
            and target.value.attr == "mark"
        ):
            return True
    return False


def _org_fixture_count(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """How many distinct org identities this test can compare.

    A pair fixture counts as two on its own; otherwise distinct names from
    :data:`_ORG_FIXTURES` are counted. ``self`` is ignored so class-based tests
    are measured the same way as bare functions.
    """
    params = [arg.arg for arg in (*node.args.args, *node.args.kwonlyargs) if arg.arg != "self"]
    if any(param in _ORG_PAIR_FIXTURES for param in params):
        return 2
    return len({param for param in params if param in _ORG_FIXTURES})


def _iter_test_functions(
    tree: ast.Module,
) -> list[tuple[bool, ast.FunctionDef | ast.AsyncFunctionDef]]:
    """Every test function, paired with whether its enclosing class is marked.

    Explicit descent rather than :func:`ast.walk` because the class/method
    relationship is exactly what matters here and ``walk`` discards it.
    """
    found: list[tuple[bool, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith(
            "test_"
        ):
            found.append((False, node))
        elif isinstance(node, ast.ClassDef):
            class_marked = _has_isolation_marker(node)
            for member in node.body:
                if isinstance(
                    member, ast.FunctionDef | ast.AsyncFunctionDef
                ) and member.name.startswith("test_"):
                    found.append((class_marked, member))
    return found


def _isolation_analysis(source: str) -> tuple[set[str], list[str]]:
    """Prefixes this module legitimately credits, and any unearned markers.

    Returns ``(credited, violations)``. A marked test that drives no gated
    prefix, or that holds fewer than two orgs, contributes a violation and
    credits nothing — see the module docstring for why that is loud rather than
    silent.
    """
    credited: set[str] = set()
    violations: list[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:  # pragma: no cover - a test file that does not parse
        return credited, violations

    lines = _scannable(source)
    gated = _gated_prefixes()

    for class_marked, node in _iter_test_functions(tree):
        if not (class_marked or _has_isolation_marker(node)):
            continue
        body = "\n".join(lines[node.lineno - 1 : node.end_lineno])
        driven = {prefix for prefix in gated if _calls_prefix(body, prefix)}
        orgs = _org_fixture_count(node)

        if not driven:
            violations.append(
                f"{node.name}: marked {_ISOLATION_MARKER} but drives no mounted router "
                "prefix. The marker cannot credit a router the test never calls."
            )
            continue
        if orgs < 2:
            violations.append(
                f"{node.name}: marked {_ISOLATION_MARKER} but takes {orgs} org fixture(s). "
                "Cross-org isolation needs two tenants to compare — use a pair fixture "
                f"{sorted(_ORG_PAIR_FIXTURES)} or two of {sorted(_ORG_FIXTURES)}. "
                "If the fixture is new, register it in this module."
            )
            continue
        credited |= driven
    return credited, violations


def _routers_with_tenant_isolation_tests() -> set[str]:
    found: set[str] = set()
    for source in _test_sources().values():
        found |= _isolation_analysis(source)[0]
    return found


def _unearned_isolation_markers() -> list[str]:
    found: list[str] = []
    for path, source in _test_sources().items():
        found.extend(f"{path.name}::{note}" for note in _isolation_analysis(source)[1])
    return sorted(found)


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
    assert not missing, f"These mounted routers have no cross-org isolation test: {missing}"


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


def test_a_tenant_isolation_marker_must_be_earned() -> None:
    """A marker that credits nothing must fail, not go quiet.

    If an unearned marker were merely ignored, the failure mode would be a test
    that looks like it proves isolation, an exemption row that stays, and nobody
    the wiser. The marker is a claim; this is the thing the claim points at.
    """
    unearned = _unearned_isolation_markers()
    assert not unearned, "these tenant_isolation markers are not earned:\n  " + "\n  ".join(
        unearned
    )


# The pre-P12 /auth shape, verbatim in structure: a single-org test that asserts
# the presented token describes itself. Under the old file-allowlist detector
# this credited /auth with proving cross-org isolation. It proves no such thing
# — there is no second tenant anywhere in it.
_TOUCH_ONLY_AUTH_TEST = '''
import pytest


class TestUnauthenticatedAuthSurfaces:
    async def test_me_reflects_the_presented_identity(self, app_client, org):
        """A call to client.get("/v1/auth/me") quoted in prose, for good measure."""
        headers = {"Authorization": f"Bearer {_token(org, 'analyst')}"}
        async with app_client as client:
            response = await client.get("/v1/auth/me", headers=headers)
        assert response.json()["org_id"] == str(org)
'''

# The same surface, done properly: two orgs, and the assertion compares them.
_EARNED_AUTH_TEST = """
import pytest


@pytest.mark.tenant_isolation
class TestAuthIsOrgScopedAcrossTenants:
    async def test_me_never_reports_a_foreign_org(self, app_client, org, other_org):
        async with app_client as client:
            mine = await client.get("/v1/auth/me", headers=_headers(org))
            theirs = await client.get("/v1/auth/me", headers=_headers(other_org))
        assert mine.json()["org_id"] != theirs.json()["org_id"]
"""


def test_touching_a_prefix_does_not_earn_isolation_credit() -> None:
    """The regression this detector was tightened to close.

    The old rule credited any prefix an allowlisted FILE touched. This test
    fixes the boundary in place: contact is not proof, and single-org contact is
    not even capable of being proof.
    """
    credited, violations = _isolation_analysis(_TOUCH_ONLY_AUTH_TEST)

    assert credited == set(), "a single-org test that merely calls /auth must credit nothing"
    assert violations == [], "an UNMARKED test is not a violation — it is simply not a claim"


def test_a_marked_two_org_test_does_earn_isolation_credit() -> None:
    """The positive control. A detector that credits nothing is not strict, it
    is broken, and every exemption row would survive forever on a false pass."""
    credited, violations = _isolation_analysis(_EARNED_AUTH_TEST)

    assert credited == {"/auth"}
    assert violations == []


def test_marking_the_touch_only_test_fails_loudly_instead_of_crediting() -> None:
    """Marking does not launder the claim.

    The tempting fix for a router the ratchet refuses to credit is to slap the
    marker on whatever test already exists. That must fail, and name the reason
    — otherwise the marker is a way to buy credit rather than earn it.
    """
    marked = _TOUCH_ONLY_AUTH_TEST.replace(
        "class TestUnauthenticatedAuthSurfaces:",
        "@pytest.mark.tenant_isolation\nclass TestUnauthenticatedAuthSurfaces:",
    )
    credited, violations = _isolation_analysis(marked)

    assert credited == set(), "one org cannot demonstrate that a second org is excluded"
    assert len(violations) == 1
    assert "1 org fixture" in violations[0]


def test_a_marker_cannot_credit_a_router_the_test_never_calls() -> None:
    """Conjunct 2. Otherwise a marker on an unrelated test would credit whatever
    router someone hoped it covered."""
    source = """
import pytest


@pytest.mark.tenant_isolation
async def test_proves_nothing_over_http(org, other_org):
    assert org != other_org
"""
    credited, violations = _isolation_analysis(source)

    assert credited == set()
    assert len(violations) == 1
    assert "drives no mounted router prefix" in violations[0]


def test_a_call_quoted_in_a_docstring_does_not_earn_isolation_credit() -> None:
    """Prose is not a request. The old line filter stripped comments but not
    docstrings, so a documented call still counted; on the isolation path that
    would be a security claim made by a sentence."""
    source = '''
import pytest


@pytest.mark.tenant_isolation
async def test_documents_a_call_it_never_makes(app_client, org, other_org):
    """Fetches client.get("/v1/policies") for both orgs."""
    assert org != other_org
'''
    credited, violations = _isolation_analysis(source)

    assert credited == set(), "a call quoted in a docstring is not a call"
    assert len(violations) == 1
    assert "drives no mounted router prefix" in violations[0]


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
