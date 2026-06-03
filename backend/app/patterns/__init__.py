"""Complex Event Pattern DSL — detection-as-code.

Patterns are declarative, multi-condition rules over a flow of events
(causal/temporal/absence logic flat SIEM rules can't express). They compile
once (compile_pattern) and run per flow (evaluate). The PatternRegistry holds
the live, hot-reloadable set. This makes detection *content* — versionable,
customer-tunable, shippable separately from code — the platform's moat.
"""

from app.patterns.compiled import (
    CompiledPattern,
    PatternValidationError,
    compile_pattern,
)
from app.patterns.evaluator import PatternMatch, evaluate
from app.patterns.registry import (
    PATTERN_RELOAD_CHANNEL,
    PatternRegistry,
    get_registry,
    publish_pattern_reload,
    reset_for_tests,
)

__all__ = [
    "CompiledPattern",
    "PatternValidationError",
    "compile_pattern",
    "PatternMatch",
    "evaluate",
    "PatternRegistry",
    "PATTERN_RELOAD_CHANNEL",
    "get_registry",
    "publish_pattern_reload",
    "reset_for_tests",
]
