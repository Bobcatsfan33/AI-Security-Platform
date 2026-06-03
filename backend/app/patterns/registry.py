"""PatternRegistry — the live set of compiled patterns, hot-reloadable.

Mirrors the policy cache + pub/sub model: patterns compile once and are held in
an atomically-swapped tuple, so the evaluator never sees a half-updated set.
``apply_specs`` recompiles from raw specs (e.g. on a pattern:reload pub/sub
message), validating each — a bad spec is rejected and logged without taking
down the good ones.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from app.patterns.compiled import CompiledPattern, PatternValidationError, compile_pattern

logger = logging.getLogger("platform.patterns.registry")

PATTERN_RELOAD_CHANNEL = "pattern:reload"


class PatternRegistry:
    def __init__(self) -> None:
        self._patterns: tuple[CompiledPattern, ...] = ()

    @property
    def patterns(self) -> tuple[CompiledPattern, ...]:
        return self._patterns

    def apply_specs(self, specs: list[dict[str, Any]]) -> tuple[int, list[str]]:
        """Recompile from raw specs and atomically swap. Returns (loaded_count,
        errors). Invalid specs are skipped, not fatal."""
        compiled: list[CompiledPattern] = []
        errors: list[str] = []
        for spec in specs:
            try:
                compiled.append(compile_pattern(spec))
            except PatternValidationError as exc:
                name = spec.get("name", "?") if isinstance(spec, dict) else "?"
                errors.append(f"{name}: {exc}")
                logger.warning(
                    "pattern_compile_failed",
                    extra={"pattern_name": name, "error": str(exc)},
                )
        self._patterns = tuple(compiled)  # atomic swap
        return len(compiled), errors


# Process-wide registry (the running web/consumer process holds one).
_registry: Optional[PatternRegistry] = None


def get_registry() -> PatternRegistry:
    global _registry
    if _registry is None:
        _registry = PatternRegistry()
    return _registry


def reset_for_tests() -> None:
    global _registry
    _registry = None


async def publish_pattern_reload(specs: list[dict[str, Any]]) -> None:
    """Publish a reload so every consumer process refreshes its registry."""
    from app.services.redis_client import get_redis

    redis = await get_redis()
    await redis.publish(PATTERN_RELOAD_CHANNEL, json.dumps({"specs": specs}, separators=(",", ":")))
