"""platform_sdk — drop-in wrappers that route LLM traffic through the
local runtime agent.

Usage
-----
Replace::

    from openai import OpenAI

with::

    from platform_sdk.openai import OpenAI

Every call goes to ``http://localhost:8400/proxy/v1/chat/completions``
(or whatever ``PLATFORM_AGENT_URL`` is set to). If the agent isn't
running, the SDK falls back to a direct API call AND logs a warning
unless ``PLATFORM_FALLBACK_DIRECT=false`` is set, in which case it
raises ``RuntimeError``.

Same pattern for Anthropic::

    from platform_sdk.anthropic import Anthropic

The SDK preserves the upstream provider's exact API surface — your
existing code keeps working with a one-line import change.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
