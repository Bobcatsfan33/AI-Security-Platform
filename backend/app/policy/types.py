"""Policy pipeline types — shared by all stages.

The three-stage policy pipeline (binding decision in the engineering
blueprint) classifies inputs through up to three stages before reaching
a final decision:

  Stage 1 (regex / deterministic) — sub-1ms latency
  Stage 2 (ONNX classifier)       — 5-10ms latency  [Sprint 3]
  Stage 3 (LLM judge)             — 500-3000ms latency  [Sprint 7]

Each stage returns a :class:`StageResult`. The pipeline orchestrator
combines stage results, applies confidence routing, and emits one final
:class:`PolicyDecision`.

Sprint 2 implements Stage 1 only. The Protocol shapes for Stage 2 and
Stage 3 are defined now so adding them later is a no-op interface
addition rather than an architectural change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Protocol, runtime_checkable

EnforcementLevel = Literal["fast", "balanced", "comprehensive"]
ActionTaken = Literal["allowed", "blocked", "modified", "flagged", "escalated"]
PipelineExitStage = Literal["stage1_regex", "stage2_ml", "stage3_judge", "no_match"]
RuleType = Literal[
    "regex",
    "keyword",
    "tool_firewall",
    "rate_limit",
    "pii_pattern",
    "custom",
]
Severity = Literal["info", "low", "medium", "high", "critical"]


class Direction(str, Enum):  # noqa: UP042 - (str, Enum) kept for .value/str() wire-compat
    """Whether the inspected payload is going INTO the model (inbound) or
    coming OUT of the model (outbound). Different rules apply to each."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"


@dataclass(frozen=True)
class PolicyInput:
    """The thing being inspected — either a prompt or a model response.

    Fields are intentionally minimal: a stage shouldn't need to know
    where the text came from. The orchestrator passes whatever metadata
    it has via ``context`` for stages that want it (e.g. tool firewall
    needs to know which tools are being called).
    """

    text: str
    direction: Direction
    asset_id: str | None = None
    session_id: str | None = None
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StageResult:
    """One stage's verdict on a single :class:`PolicyInput`.

    A stage can:
      - Return matched=False  (no rule fired; pass to next stage or allow)
      - Return matched=True with an action  (definitive verdict)
      - Return matched=True with low confidence (uncertain — escalate)

    ``confidence`` semantics by stage:
      Stage 1 (regex):     always 1.0 on match (deterministic)
      Stage 2 (ML/ONNX):   0.0-1.0 model output
      Stage 3 (LLM judge): 0.0-1.0 derived from judge response
    """

    stage: PipelineExitStage
    matched: bool
    action: ActionTaken = "allowed"
    severity: Severity = "info"
    category: str = ""
    rule_id: str | None = None
    confidence: float = 0.0
    reason: str = ""
    latency_us: int = 0  # microseconds — Stage 1 budgets are sub-1ms
    evidence: dict[str, Any] = field(default_factory=dict)
    # How this verdict was ACTUALLY computed — the honesty field. One of:
    # "stage1_regex", "stage2_heuristic", "stage2_onnx", "stage2_detectors",
    # "stage2_http", "stage3_deterministic", "stage3_llm_judge", "stage3_http",
    # or "disabled" (stage has no real backend — it did NOT compute a verdict).
    # Never let `stage` (pipeline position) imply a capability `mode` denies.
    mode: str = ""


@dataclass(frozen=True)
class PolicyDecision:
    """The pipeline's final decision after all relevant stages have run.

    This is what the runtime agent (Sprint 7) acts on, what gets recorded
    to ClickHouse runtime_events, and what shows up in finding evidence.
    """

    action: ActionTaken
    severity: Severity
    pipeline_exit_stage: PipelineExitStage
    enforcement_level: EnforcementLevel
    matched_rules: tuple[str, ...] = field(default_factory=tuple)
    stage_results: tuple[StageResult, ...] = field(default_factory=tuple)
    total_latency_us: int = 0
    block_reason: str | None = None

    @property
    def allowed(self) -> bool:
        return self.action == "allowed"

    @property
    def blocked(self) -> bool:
        return self.action == "blocked"


# ─────────────────────────────────────────────── Stage Protocols


@runtime_checkable
class Stage1Engine(Protocol):
    """Stage 1 — regex + deterministic rules. Sub-millisecond budget.

    Implementations must be allocation-free in the hot path: pre-compile
    patterns at construction time, never compile per-call.
    """

    async def evaluate(self, *, input_: PolicyInput, policy: CompiledPolicy) -> StageResult: ...


@runtime_checkable
class Stage2Engine(Protocol):
    """Stage 2 — ML classifier (ONNX). Sprint 3."""

    async def classify(self, *, input_: PolicyInput, policy: CompiledPolicy) -> StageResult: ...


@runtime_checkable
class Stage3Engine(Protocol):
    """Stage 3 — LLM judge. Sprint 7."""

    async def judge(self, *, input_: PolicyInput, policy: CompiledPolicy) -> StageResult: ...


# Forward-declared placeholder; the concrete CompiledPolicy lives in
# app.policy.compiled. Stages take CompiledPolicy not the raw DB row so
# pattern compilation cost is amortized across many requests.
class CompiledPolicy(Protocol):
    """A policy after rule compilation. Stages read from this read-only
    snapshot; the Redis pub/sub subscriber swaps it atomically."""

    policy_id: str
    version: int
    enforcement_level: EnforcementLevel
    fail_behavior: Literal["open", "closed"]
    ml_confidence_threshold_high: float
    ml_confidence_threshold_low: float
