"""Drop-in OpenAI client wrapper.

The official ``openai`` package's ``OpenAI`` class accepts a ``base_url``
constructor arg that overrides where it sends requests. We just set
that base_url to our runtime agent's proxy path; everything else (auth,
streaming, tool calls, error types) is the original SDK.

This means you can use every feature of the upstream OpenAI SDK
(``.chat.completions.create``, ``.embeddings.create``, ``.images``,
``.batches``, etc.) without modification — only the import line changes.
"""

from __future__ import annotations

import os
from typing import Any

from platform_sdk._routing import resolve_base_url

OPENAI_DIRECT_BASE_URL = os.environ.get(
    "OPENAI_BASE_URL", "https://api.openai.com/v1"
)


class OpenAI:
    """Drop-in replacement for ``openai.OpenAI``.

    Routes through the local runtime agent when available; falls back
    to a direct upstream call (with a warning log) when not.
    """

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        try:
            from openai import OpenAI as _UpstreamOpenAI
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            ) from exc

        base_url = resolve_base_url(
            proxy_path="/proxy/v1",
            direct_default=OPENAI_DIRECT_BASE_URL,
        )
        kwargs.setdefault("base_url", base_url)
        return _UpstreamOpenAI(*args, **kwargs)


class AsyncOpenAI:
    """Async variant — same behavior, async surface."""

    def __new__(cls, *args: Any, **kwargs: Any) -> Any:
        try:
            from openai import AsyncOpenAI as _UpstreamAsyncOpenAI
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "openai package not installed. Run: pip install openai"
            ) from exc

        base_url = resolve_base_url(
            proxy_path="/proxy/v1",
            direct_default=OPENAI_DIRECT_BASE_URL,
        )
        kwargs.setdefault("base_url", base_url)
        return _UpstreamAsyncOpenAI(*args, **kwargs)
