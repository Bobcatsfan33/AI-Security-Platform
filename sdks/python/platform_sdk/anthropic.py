"""Drop-in Anthropic client wrapper.

Same pattern as :mod:`platform_sdk.openai`: the upstream ``anthropic``
package accepts a ``base_url`` arg, we point it at the agent's proxy.
"""

from __future__ import annotations

import os
from typing import Any

from platform_sdk._routing import resolve_base_url

ANTHROPIC_DIRECT_BASE_URL = os.environ.get(
    "ANTHROPIC_BASE_URL", "https://api.anthropic.com"
)


class Anthropic:
    """Drop-in replacement for ``anthropic.Anthropic``.

    Routes through the local runtime agent when available; falls back
    to a direct upstream call (with a warning log) when not.
    """

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        try:
            from anthropic import Anthropic as _UpstreamAnthropic
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "anthropic package not installed. Run: pip install anthropic"
            ) from exc

        # Anthropic's `base_url` is the host root; the SDK appends
        # /v1/messages itself. Our agent expects /proxy/v1/messages, so
        # we set base_url to the agent's /proxy prefix and let the SDK
        # append /v1/messages.
        base_url = resolve_base_url(
            proxy_path="/proxy",
            direct_default=ANTHROPIC_DIRECT_BASE_URL,
        )
        kwargs.setdefault("base_url", base_url)
        return _UpstreamAnthropic(*args, **kwargs)


class AsyncAnthropic:
    """Async variant."""

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        try:
            from anthropic import AsyncAnthropic as _UpstreamAsyncAnthropic
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "anthropic package not installed. Run: pip install anthropic"
            ) from exc

        base_url = resolve_base_url(
            proxy_path="/proxy",
            direct_default=ANTHROPIC_DIRECT_BASE_URL,
        )
        kwargs.setdefault("base_url", base_url)
        return _UpstreamAsyncAnthropic(*args, **kwargs)
