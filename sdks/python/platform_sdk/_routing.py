"""Shared logic for routing through the local runtime agent.

Both the OpenAI and Anthropic wrappers reuse this — the only difference
between them is which upstream base path the agent expects.
"""

from __future__ import annotations

import logging
import os
import urllib.request
from urllib.error import URLError

logger = logging.getLogger("platform_sdk")

DEFAULT_AGENT_URL = "http://localhost:8400"
DEFAULT_AGENT_HEALTH_TIMEOUT_S = 1.0


def agent_url() -> str:
    """Return the runtime agent's base URL. ``PLATFORM_AGENT_URL`` env
    var overrides; defaults to ``http://localhost:8400``."""
    return os.environ.get("PLATFORM_AGENT_URL", DEFAULT_AGENT_URL).rstrip("/")


def fallback_direct() -> bool:
    """Whether to fall back to a direct API call when the agent is
    unreachable. ``PLATFORM_FALLBACK_DIRECT=false`` makes the SDK
    fail-closed."""
    return os.environ.get("PLATFORM_FALLBACK_DIRECT", "true").lower() == "true"


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
        logger.warning(
            "platform_sdk_agent_unreachable_falling_back_direct",
            extra={"agent_url": agent_url(), "direct": direct_default},
        )
        return direct_default
    raise RuntimeError(
        f"platform_sdk: runtime agent at {agent_url()!r} is unreachable "
        "and PLATFORM_FALLBACK_DIRECT=false — refusing to send LLM traffic "
        "unprotected."
    )
