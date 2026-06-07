"""LiteLLM integration — a CustomLogger that enforces AI Guard inline.

LiteLLM proxies calls to 100+ LLM providers and exposes pre/post-call hooks.
This adapter inspects the inbound prompt and the outbound completion through
the AI Guard detector suite and blocks (raises) on a ``block`` verdict.

Usage (in a LiteLLM config or proxy):

    from app.integrations.litellm_callback import AIGuardLiteLLMLogger
    import litellm
    litellm.callbacks = [AIGuardLiteLLMLogger(config=my_detector_config)]

The class deliberately does **not** import ``litellm`` at module load so the
platform has no hard dependency on it; it only needs to be installed where
the callback is actually wired in. Method signatures follow LiteLLM's
``CustomLogger`` contract.
"""

from __future__ import annotations

from typing import Any

from app.aiguard.service import AIGuardService
from app.detectors.base import DetectorContext, Direction


class AIGuardBlocked(Exception):
    """Raised to reject a request/response that AI Guard blocked."""

    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        super().__init__(f"AI Guard blocked: {response.get('reason')}")


def _extract_prompt(messages: list[dict[str, Any]]) -> str:
    parts = [m.get("content", "") for m in messages if isinstance(m.get("content"), str)]
    return "\n".join(p for p in parts if p)


class AIGuardLiteLLMLogger:
    """Implements the subset of LiteLLM's CustomLogger hooks we need."""

    def __init__(
        self,
        service: AIGuardService | None = None,
        config: dict[str, dict[str, Any]] | None = None,
        context: DetectorContext | None = None,
        block_on_input: bool = True,
        block_on_output: bool = True,
    ) -> None:
        self._svc = service or AIGuardService()
        self._config = config or {}
        self._ctx = context
        self._block_in = block_on_input
        self._block_out = block_on_output

    # --- LiteLLM pre-call hook -------------------------------------------
    async def async_pre_call_hook(
        self, user_api_key_dict: Any, cache: Any, data: dict[str, Any], call_type: str
    ) -> dict[str, Any]:
        prompt = _extract_prompt(data.get("messages", []))
        verdict = self.inspect(prompt, Direction.INBOUND)
        data.setdefault("metadata", {})["ai_guard"] = verdict
        if self._block_in and verdict["action"] == "block":
            raise AIGuardBlocked(verdict)
        return data

    # --- LiteLLM post-call success hook ----------------------------------
    async def async_post_call_success_hook(
        self, data: dict[str, Any], user_api_key_dict: Any, response: Any
    ) -> Any:
        text = self._completion_text(response)
        verdict = self.inspect(text, Direction.OUTBOUND)
        if self._block_out and verdict["action"] == "block":
            raise AIGuardBlocked(verdict)
        return response

    # --- helpers ---------------------------------------------------------
    def inspect(self, text: str, direction: Direction) -> dict[str, Any]:
        return self._svc.inspect(
            text=text or "", direction=direction, config=self._config, context=self._ctx
        ).to_dict()

    @staticmethod
    def _completion_text(response: Any) -> str:
        try:
            return response["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            choices = getattr(response, "choices", None)
            if choices:
                msg = getattr(choices[0], "message", None)
                return getattr(msg, "content", "") or ""
            return ""
