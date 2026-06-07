"""Portkey integration — a guardrail check callable.

Portkey guardrails are functions that receive the text under inspection and
return a verdict object ``{"verdict": bool, "data": {...}}``. ``verdict=True``
means the content passed. This adapter maps AI Guard's Allow|Block|Detect to
that contract (``block`` -> verdict False).
"""

from __future__ import annotations

from typing import Any

from app.aiguard.service import AIGuardService
from app.detectors.base import DetectorContext, Direction


class PortkeyAIGuardrail:
    def __init__(
        self,
        service: AIGuardService | None = None,
        config: dict[str, dict[str, Any]] | None = None,
        context: DetectorContext | None = None,
        fail_on_detect: bool = False,
    ) -> None:
        self._svc = service or AIGuardService()
        self._config = config or {}
        self._ctx = context
        self._fail_on_detect = fail_on_detect

    def check(self, text: str, direction: str = "inbound") -> dict[str, Any]:
        d = Direction.OUTBOUND if direction == "outbound" else Direction.INBOUND
        resp = self._svc.inspect(
            text=text or "", direction=d, config=self._config, context=self._ctx
        )
        passed = resp.action == "allow" or (resp.action == "detect" and not self._fail_on_detect)
        return {
            "verdict": passed,
            "data": {
                "action": resp.action,
                "triggered": list(resp.triggered),
                "reason": resp.reason,
                "latency_ms": round(resp.latency_ms, 3),
            },
        }

    # Allow the instance to be used directly as a callable guardrail.
    def __call__(self, text: str, direction: str = "inbound") -> dict[str, Any]:
        return self.check(text, direction)
