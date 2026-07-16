"""The fail-closed branch (GAP-005).

This is the product's core promise: LLM traffic is protected, or it does not
flow. Everything else in this SDK is a convenience wrapper; this one decision
is the security control. It shipped with zero tests in either language, which
made "deny-by-default in production" a claim resting on a branch nobody had
ever executed.

The contract under test:

* ``PLATFORM_FALLBACK_DIRECT`` is explicit and always wins.
* Unset, it resolves by environment: prod/production → fail **closed**;
  anything else → fail **open** (a laptop with no agent running must not be
  bricked).
* Falling back is never silent — an unprotected call warns loudly.
"""

from __future__ import annotations

import warnings

import pytest

from platform_sdk import _routing

PROXY_PATH = "/proxy/v1"
DIRECT = "https://api.openai.com/v1"

# The environment variables under test. Cleared before every test so a
# developer's real shell config can never make a security test pass.
_ENV_VARS = ("PLATFORM_ENV", "PLATFORM_FALLBACK_DIRECT", "PLATFORM_AGENT_URL")


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


# ─────────────────────────────────── the environment default


@pytest.mark.parametrize("env", ["prod", "production", "PROD", "Production", "PrOdUcTiOn"])
def test_production_fails_closed_by_default(env: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Case-insensitively: production means closed. A deployment that sets
    PLATFORM_ENV and nothing else is protected."""
    monkeypatch.setenv("PLATFORM_ENV", env)
    assert _routing.fallback_direct() is False


@pytest.mark.parametrize("env", ["dev", "development", "staging", "test", "", "anything-else"])
def test_non_production_falls_back_by_default(env: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A laptop with no agent running must still work, or nobody adopts this."""
    monkeypatch.setenv("PLATFORM_ENV", env)
    assert _routing.fallback_direct() is True


def test_unset_environment_falls_back_by_default() -> None:
    assert _routing.fallback_direct() is True


# ─────────────────────────────────── explicit always wins


def test_explicit_false_overrides_dev_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PLATFORM_ENV", "dev")
    monkeypatch.setenv("PLATFORM_FALLBACK_DIRECT", "false")
    assert _routing.fallback_direct() is False


def test_explicit_true_overrides_prod_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """An operator who explicitly opts out of protection in prod gets what they
    asked for. Documented, deliberate, and their call — but it must be
    explicit, never a default."""
    monkeypatch.setenv("PLATFORM_ENV", "production")
    monkeypatch.setenv("PLATFORM_FALLBACK_DIRECT", "true")
    assert _routing.fallback_direct() is True


@pytest.mark.parametrize("value", ["TRUE", "True", "tRuE"])
def test_explicit_true_is_case_insensitive(value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PLATFORM_FALLBACK_DIRECT", value)
    assert _routing.fallback_direct() is True


@pytest.mark.parametrize("value", ["yes", "1", "on", "", "  ", "truthy", "0", "no"])
def test_only_the_literal_true_enables_fallback(
    value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Anything that is not exactly "true" fails closed. A typo like
    PLATFORM_FALLBACK_DIRECT=1 must not silently unprotect traffic — the safe
    reading of an ambiguous value is the protected one."""
    monkeypatch.setenv("PLATFORM_ENV", "production")
    monkeypatch.setenv("PLATFORM_FALLBACK_DIRECT", value)
    assert _routing.fallback_direct() is False


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

    with pytest.raises(RuntimeError, match="refusing to send LLM traffic"):
        _resolve()


def test_the_refusal_names_the_escape_hatch(
    agent_down: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An error that stops a deploy must say how to proceed deliberately, or
    someone will reach for a worse workaround."""
    monkeypatch.setenv("PLATFORM_ENV", "production")

    with pytest.raises(RuntimeError) as exc:
        _resolve()

    assert "PLATFORM_FALLBACK_DIRECT" in str(exc.value)


def test_dev_with_agent_down_falls_back_to_direct(agent_down: None) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        assert _resolve() == DIRECT


def test_falling_back_is_loud(agent_down: None) -> None:
    """warnings.warn, not just logging: the bypass has to surface even when the
    host app never configured a logger. An unprotected call that looks
    identical to a protected one is how this fails in the field."""
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
