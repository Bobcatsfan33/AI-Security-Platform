"""Shared logic for routing through the local runtime agent.

Both the OpenAI and Anthropic wrappers reuse this — the only difference
between them is which upstream base path the agent expects.
"""

from __future__ import annotations

import logging
import os
import urllib.request
import warnings
from urllib.error import URLError

logger = logging.getLogger("platform_sdk")

DEFAULT_AGENT_URL = "http://localhost:8400"
DEFAULT_AGENT_HEALTH_TIMEOUT_S = 1.0


def agent_url() -> str:
    """Return the runtime agent's base URL. ``PLATFORM_AGENT_URL`` env
    var overrides; defaults to ``http://localhost:8400``."""
    return os.environ.get("PLATFORM_AGENT_URL", DEFAULT_AGENT_URL).rstrip("/")


# Environments that are a deliberate statement of "not production", and so buy
# a direct fallback when the agent is down. An ALLOWLIST, not "anything that
# isn't production": the else-branch of a negative test is where typos land, and
# `PLATFORM_ENV=porduction` resolving to "fall back, unprotected" is the single
# worst outcome this module can produce.
#
# Keep in sync with sdks/node/src/routing.ts — the shared decision table in
# sdks/routing-cases.json is what actually holds them together.
_NON_PRODUCTION_ENVS = frozenset(
    {"dev", "development", "staging", "stage", "test", "testing", "ci", "local", "sandbox"}
)


def fallback_direct() -> bool:
    """Whether to fall back to a direct API call when the agent is unreachable.

    The rule, matching the runtime agent's AGENT_NO_POLICY_BEHAVIOR exactly so
    the platform has one convention rather than two:

    * ``PLATFORM_FALLBACK_DIRECT`` is explicit and always wins (only the literal
      ``"true"`` enables fallback — the safe reading of an ambiguous value is
      the protected one);
    * otherwise ``PLATFORM_ENV`` decides, and only a RECOGNISED non-production
      environment falls back.

    Unset, empty and unrecognised all fail CLOSED. This is deliberately stricter
    than the first cut, which defaulted to fallback unless PLATFORM_ENV said
    prod — meaning a production deployment that simply forgot to set
    PLATFORM_ENV shipped unprotected traffic behind a warning. That is the most
    dangerous possible place to be permissive, and it made the "one convention"
    claim false at its worst edge: the agent already resolved unset to closed.

    The cost is real and accepted: a first-run developer with no PLATFORM_ENV
    now hits an error instead of silently-unprotected calls. That is one line of
    setup friction, once, against unprotected production traffic nobody notices.
    The error says exactly which variable to set.
    """
    explicit = os.environ.get("PLATFORM_FALLBACK_DIRECT")
    if explicit is not None:
        return explicit.strip().lower() == "true"
    return os.environ.get("PLATFORM_ENV", "").strip().lower() in _NON_PRODUCTION_ENVS


def agent_reachable() -> bool:
    """Lightweight ping to the agent's /healthz endpoint. Returns False
    on any error (timeout, connection refused, non-200)."""
    try:
        url = agent_url() + "/healthz"
        # urllib so we don't add an httpx/requests dependency to the SDK
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=DEFAULT_AGENT_HEALTH_TIMEOUT_S) as resp:
            return resp.status == 200
    except (URLError, TimeoutError, OSError):
        return False


def resolve_base_url(
    *,
    proxy_path: str,
    direct_default: str,
) -> str:
    """Decide whether to route via the agent or directly to the provider.

    ``proxy_path`` is the path component the agent expects (e.g.
    ``/proxy/v1`` for OpenAI). ``direct_default`` is the upstream URL
    to fall back to.
    """
    if agent_reachable():
        return agent_url() + proxy_path
    if fallback_direct():
        # warnings.warn so the bypass is loud even when the host app never
        # configures logging — falling back means LLM traffic is UNPROTECTED.
        warnings.warn(
            f"platform_sdk: runtime agent at {agent_url()!r} is unreachable — "
            f"falling back to direct calls ({direct_default}). LLM traffic is "
            "NOT protected. Set PLATFORM_FALLBACK_DIRECT=false to fail closed.",
            RuntimeWarning,
            stacklevel=3,
        )
        logger.warning(
            "platform_sdk_agent_unreachable_falling_back_direct",
            extra={"agent_url": agent_url(), "direct": direct_default},
        )
        return direct_default
    env = os.environ.get("PLATFORM_ENV", "")
    raise RuntimeError(
        f"platform_sdk: the runtime agent at {agent_url()!r} is unreachable, and "
        f"fallback is off (PLATFORM_ENV={env!r} is not a recognised non-production "
        "environment). Refusing to send LLM traffic unprotected.\n"
        "\n"
        "  Developing locally?  export PLATFORM_ENV=development\n"
        f"                       (recognised: {', '.join(sorted(_NON_PRODUCTION_ENVS))})\n"
        "  Running for real?    start the runtime agent, or point the SDK at it with\n"
        "                       PLATFORM_AGENT_URL=http://<host>:8400\n"
        "  Deliberately opting out of protection?  PLATFORM_FALLBACK_DIRECT=true\n"
    )
