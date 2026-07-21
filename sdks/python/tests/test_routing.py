"""The fail-closed branch (GAP-005).

This is the product's core promise: LLM traffic is protected, or it does not
flow. Everything else in this SDK is a convenience wrapper; this one decision
is the security control. It shipped with zero tests in either language, which
made "deny-by-default in production" a claim resting on a branch nobody had
ever executed.

The contract under test:

* ``PLATFORM_FALLBACK_DIRECT`` is explicit and always wins.
* Otherwise ``PLATFORM_ENV`` decides, and ONLY a recognised non-production
  environment falls back. Unset, empty and unrecognised all fail **closed** —
  matching the runtime agent, so the platform has one convention.
* Falling back is never silent — an unprotected call warns loudly.

The decision table lives in ``sdks/routing-cases.json`` and is iterated by both
this suite and the Node one. Transport-level behaviour (what counts as "down")
is legitimately language-specific and tested separately below.
"""

from __future__ import annotations

import json
import pathlib
import warnings

import pytest

from platform_sdk import _routing

PROXY_PATH = "/proxy/v1"
DIRECT = "https://api.openai.com/v1"

# The environment variables under test. Cleared before every test so a
# developer's real shell config can never make a security test pass.
_ENV_VARS = ("PLATFORM_ENV", "PLATFORM_FALLBACK_DIRECT", "PLATFORM_AGENT_URL")

# The decision table is SHARED with the Node suite (sdks/routing-cases.json).
# Both SDKs make the same promise, so the table that decides it is one artifact
# rather than two hand-maintained lists that drift — which they already had.
_CASES_FILE = pathlib.Path(__file__).resolve().parents[2] / "routing-cases.json"


def _shared_cases() -> list[dict]:
    assert _CASES_FILE.exists(), (
        f"{_CASES_FILE} is missing — the shared decision table is what keeps the "
        "Python and Node suites honest about being the same contract."
    )
    return json.loads(_CASES_FILE.read_text())["cases"]


SHARED_CASES = _shared_cases()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def agent_down(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_routing, "agent_reachable", lambda: False)


@pytest.fixture
def agent_up(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_routing, "agent_reachable", lambda: True)


def _resolve() -> str:
    return _routing.resolve_base_url(proxy_path=PROXY_PATH, direct_default=DIRECT)


# ─────────────────────────────────── the shared decision table


@pytest.mark.parametrize(
    "case", SHARED_CASES, ids=[c["name"] for c in SHARED_CASES]
)
def test_shared_decision_table(case: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every case in sdks/routing-cases.json, driven against the Python SDK.

    The Node suite iterates the same file. Neither language owns the contract;
    a case added for one is automatically demanded of the other, which is the
    only way two implementations of one promise stay honest.
    """
    for key, value in case["env"].items():
        monkeypatch.setenv(key, value)

    assert _routing.fallback_direct() is case["fallback"], case.get("why", case["name"])


def test_the_shared_table_has_no_duplicate_cases() -> None:
    """Two cases asserting the same env COMBINATION are noise, not coverage.

    Deliberately mechanical: it compares env dicts, not intent. The pair this
    guard commemorates ("explicit false overrides a dev environment" vs
    "…in a dev environment still fails closed") was duplicate in BEHAVIOUR but
    not in env — one used PLATFORM_ENV=development, the other =dev — so this
    test would not have caught it, and removing it cost the `dev` shorthand its
    direct coverage. That case is back.

    Which is the honest scope: a mechanical guard catches mechanical
    duplication. Judging whether two different inputs are "really" the same
    behaviour is a review question, and a test that tried would either be wrong
    or be a second implementation of the SDK.
    """
    seen: dict[str, str] = {}
    duplicates: list[str] = []
    for case in SHARED_CASES:
        key = json.dumps(case["env"], sort_keys=True)
        if key in seen:
            duplicates.append(f"{seen[key]!r} and {case['name']!r} both assert env {key}")
        seen[key] = case["name"]

    assert not duplicates, "\n".join(duplicates)


def test_the_shared_table_covers_the_dangerous_default() -> None:
    """A guard on the table itself: the case that matters most must be in it.

    The first cut of this SDK defaulted to FALLBACK on unset PLATFORM_ENV, so a
    production deployment that forgot the variable shipped unprotected traffic
    behind a warning. If that case ever falls out of the table, this suite would
    go quiet about the exact regression that motivated it.
    """
    unset_cases = [c for c in SHARED_CASES if not c["env"]]

    assert unset_cases, "the table must cover a completely unset environment"
    assert all(c["fallback"] is False for c in unset_cases), (
        "an unset environment must fail CLOSED — absence of information is not "
        "evidence of a dev box"
    )


# ─────────────────────────────────── resolve_base_url: the decision


def test_reachable_agent_is_always_used(agent_up: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """Even with fallback enabled, a reachable agent wins — fallback is for
    when the agent is down, not a preference."""
    monkeypatch.setenv("PLATFORM_FALLBACK_DIRECT", "true")
    assert _resolve() == f"http://localhost:8400{PROXY_PATH}"


def test_agent_url_override_is_honoured(agent_up: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PLATFORM_AGENT_URL", "http://agent.internal:9000/")
    assert _resolve() == f"http://agent.internal:9000{PROXY_PATH}"


def test_prod_with_agent_down_refuses_to_send(
    agent_down: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE test. Production, agent unreachable, nothing explicitly set: the SDK
    must raise rather than send a single unprotected token."""
    monkeypatch.setenv("PLATFORM_ENV", "production")

    with pytest.raises(RuntimeError, match="[Rr]efusing to send LLM traffic"):
        _resolve()


def test_the_refusal_names_exactly_which_variable_to_set(
    agent_down: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This error WILL trip first-run developers — that is the accepted cost of
    failing closed on unset. So it has to be the most useful error in the
    codebase: an error that stops someone and does not tell them how to proceed
    deliberately is an error they route around with a worse workaround."""
    monkeypatch.setenv("PLATFORM_ENV", "production")

    with pytest.raises(RuntimeError) as exc:
        _resolve()

    message = str(exc.value)
    assert "PLATFORM_ENV=development" in message, "must name the dev fix verbatim"
    assert "PLATFORM_FALLBACK_DIRECT" in message, "must name the deliberate opt-out"
    assert "PLATFORM_AGENT_URL" in message, "must name how to point at a real agent"


def test_an_unset_environment_refuses_and_explains(agent_down: None) -> None:
    """The behaviour change, asserted head-on: no PLATFORM_ENV at all used to
    mean "fall back, unprotected, with a warning". It now refuses."""
    with pytest.raises(RuntimeError) as exc:
        _resolve()

    assert "not a recognised non-production environment" in str(exc.value)


def test_a_typo_environment_refuses_rather_than_falling_back(
    agent_down: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """'porduction' is not production, and under the old rule that made it a
    dev box. The allowlist means a typo fails closed."""
    monkeypatch.setenv("PLATFORM_ENV", "porduction")

    with pytest.raises(RuntimeError):
        _resolve()


def test_dev_with_agent_down_falls_back_to_direct(
    agent_down: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PLATFORM_ENV", "development")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        assert _resolve() == DIRECT


def test_falling_back_is_loud(agent_down: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """warnings.warn, not just logging: the bypass has to surface even when the
    host app never configured a logger. An unprotected call that looks
    identical to a protected one is how this fails in the field."""
    monkeypatch.setenv("PLATFORM_ENV", "development")
    with pytest.warns(RuntimeWarning, match="NOT protected"):
        _resolve()


def test_routing_via_agent_is_quiet(agent_up: None) -> None:
    """No warning on the happy path — an alarm that always fires is ignored."""
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _resolve()


# ─────────────────────────────────── agent_reachable: what counts as up


def test_unreachable_agent_is_not_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing is listening on this port. This exercises the real urllib path
    rather than a mock, so a refactor that swallows the wrong exception type
    (and returns True on error) fails here."""
    monkeypatch.setenv("PLATFORM_AGENT_URL", "http://127.0.0.1:1")
    assert _routing.agent_reachable() is False


@pytest.mark.parametrize(
    "exc",
    [OSError("connection refused"), TimeoutError("slow"), ConnectionResetError("reset")],
    ids=["refused", "timeout", "reset"],
)
def test_transport_failures_all_mean_down(exc: Exception, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every transport failure resolves to "down" rather than propagating.
    Fail-closed depends on this returning False: an uncaught error would crash
    the caller instead of producing the documented refusal."""

    def _raise(*_args: object, **_kwargs: object) -> None:
        raise exc

    monkeypatch.setattr(_routing.urllib.request, "urlopen", _raise)

    assert _routing.agent_reachable() is False


def test_non_200_health_response_means_down(monkeypatch: pytest.MonkeyPatch) -> None:
    """A listening-but-unhealthy agent is not protection. 503 means down."""

    class _Resp:
        status = 503

        def __enter__(self) -> "_Resp":
            return self

        def __exit__(self, *_: object) -> None:
            return None

    monkeypatch.setattr(_routing.urllib.request, "urlopen", lambda *a, **k: _Resp())

    assert _routing.agent_reachable() is False


def test_a_malformed_agent_url_never_yields_unprotected_traffic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typo'd PLATFORM_AGENT_URL must not become a silent bypass.

    urllib raises ValueError("unknown url type") for a scheme-less URL, and
    agent_reachable only catches (URLError, TimeoutError, OSError) — so this
    propagates rather than returning False. That is ugly but SAFE: the call
    dies instead of shipping unprotected tokens. Asserted so that a future
    refactor which "helpfully" broadens the except clause to bare Exception
    cannot quietly convert a config typo into a direct, unprotected call.
    """
    monkeypatch.setenv("PLATFORM_ENV", "production")
    monkeypatch.setenv("PLATFORM_AGENT_URL", "localhost:8400")  # no scheme

    with pytest.raises((ValueError, RuntimeError)):
        _resolve()
