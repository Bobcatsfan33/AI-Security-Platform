"""Three-stage policy pipeline orchestrator.

The orchestrator is what callers (the runtime agent in Sprint 7, the
evaluation engine in Sprint 4+, the simulation endpoint) invoke. It:

1. Picks which stages to run based on the policy's enforcement_level.
2. Runs Stage 1 first. If matched and high-confidence, return.
3. If enforcement_level is "balanced" or "comprehensive" AND Stage 1
   didn't already block, run Stage 2 (Sprint 3 — currently a no-op
   stub that returns matched=False).
4. If enforcement_level is "comprehensive" AND Stage 2's confidence is
   in the uncertain band, run Stage 3 (Sprint 7 — also a no-op stub).
5. Combine stage results into one :class:`PolicyDecision`.

Sprint 2 ships only Stage 1; Stages 2 and 3 are no-op stubs that return
matched=False so the pipeline behaves as Stage-1-only regardless of
configured enforcement_level. When Sprint 3 / Sprint 7 ship, swapping
in real engines is a one-line dependency injection.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from app.policy.compiled import CompiledPolicy
from app.policy.stage1 import Stage1RegexEngine
from app.policy.stage2_heuristic import HeuristicStage2
from app.policy.stage3_judge import LlmJudgeStage3
from app.policy.types import (
    PolicyDecision,
    PolicyInput,
    Stage1Engine,
    Stage2Engine,
    Stage3Engine,
    StageResult,
)

# ─────────────────────────────────────────────── No-op stubs for Stages 2 & 3


class _NoopStage2:
    """Explicitly-disabled Stage 2 — computes nothing, reports it honestly."""

    async def classify(self, *, input_: PolicyInput, policy: CompiledPolicy) -> StageResult:
        return StageResult(stage="stage2_ml", matched=False, action="allowed", mode="disabled")


class _NoopStage3:
    """Explicitly-disabled Stage 3 — computes nothing, reports it honestly."""

    async def judge(self, *, input_: PolicyInput, policy: CompiledPolicy) -> StageResult:
        return StageResult(stage="stage3_judge", matched=False, action="allowed", mode="disabled")


# ─────────────────────────────────────────────── Pipeline


@dataclass
class PolicyPipeline:
    """Orchestrates the three-stage pipeline.

    Construct once per process; share across requests. Stages should be
    stateless / thread-safe.
    """

    stage1: Stage1Engine
    stage2: Stage2Engine
    stage3: Stage3Engine

    @classmethod
    def default(cls) -> PolicyPipeline:
        """Default wiring: real Stage 1 + functional Stage 2 + Stage 3 judge.

        Stage 2 is the zero-config :class:`HeuristicStage2` — swap in
        ``OnnxClassifierStage2`` (built from a policy's classifier specs)
        when a trained model is provisioned. Stage 3 is :class:`LlmJudgeStage3`
        with the deterministic default judge — pass ``make_connector_judge``
        to back it with a real model. Tests construct PolicyPipeline directly
        with custom stages (e.g. _NoopStage2 for Stage-1-only behaviour).
        """
        return cls(
            stage1=Stage1RegexEngine(),
            stage2=HeuristicStage2(),
            stage3=LlmJudgeStage3(),
        )

    async def evaluate(
        self,
        *,
        input_: PolicyInput,
        policy: CompiledPolicy,
        environment: str | None = None,
    ) -> PolicyDecision:
        """Run the pipeline against one input. Returns a final decision."""
        start_ns = time.perf_counter_ns()
        results: list[StageResult] = []

        # Stage 1 always runs (unless we lack a policy entirely)
        s1 = await self._stage1_with_signature(
            input_=input_, policy=policy, environment=environment
        )
        results.append(s1)
        if s1.matched and s1.action == "blocked":
            return self._decide(
                results=results,
                policy=policy,
                exit_stage="stage1_regex",
                start_ns=start_ns,
            )

        # Stage 2 runs for balanced + comprehensive
        if policy.enforcement_level in ("balanced", "comprehensive"):
            s2 = await self.stage2.classify(input_=input_, policy=policy)
            results.append(s2)

            # Confidence routing
            if s2.matched and s2.confidence >= policy.ml_confidence_threshold_high:
                return self._decide(
                    results=results,
                    policy=policy,
                    exit_stage="stage2_ml",
                    start_ns=start_ns,
                )
            uncertain = (
                s2.matched
                and s2.confidence >= policy.ml_confidence_threshold_low
                and s2.confidence < policy.ml_confidence_threshold_high
            )

            # Stage 3 runs only for comprehensive AND uncertain Stage 2 results
            if uncertain and policy.enforcement_level == "comprehensive":
                s3 = await self.stage3.judge(input_=input_, policy=policy)
                results.append(s3)
                if s3.matched:
                    return self._decide(
                        results=results,
                        policy=policy,
                        exit_stage="stage3_judge",
                        start_ns=start_ns,
                    )

        # No stage produced a definitive verdict — combine results
        return self._decide(
            results=results,
            policy=policy,
            exit_stage=_exit_stage_for_no_match(results),
            start_ns=start_ns,
        )

    async def _stage1_with_signature(
        self,
        *,
        input_: PolicyInput,
        policy: CompiledPolicy,
        environment: str | None,
    ) -> StageResult:
        # Stage1RegexEngine.evaluate accepts an environment kwarg; the
        # protocol does not (since environment is a Stage 1 concept). Bridge
        # via concrete-class duck typing — Stage 1 implementations that
        # don't support environments simply ignore the kwarg.
        try:
            return await self.stage1.evaluate(  # type: ignore[call-arg]
                input_=input_, policy=policy, environment=environment
            )
        except TypeError:
            return await self.stage1.evaluate(input_=input_, policy=policy)

    def _decide(
        self,
        *,
        results: list[StageResult],
        policy: CompiledPolicy,
        exit_stage: str,
        start_ns: int,
    ) -> PolicyDecision:
        # Pick the most severe matched result for the final action
        matched = [r for r in results if r.matched]
        if matched:
            chosen = max(matched, key=lambda r: _action_severity_rank(r.action))
            action = chosen.action
            severity = chosen.severity
            block_reason = chosen.reason if action == "blocked" else None
        else:
            chosen_action: Any = "allowed"
            action = chosen_action
            severity = "info"
            block_reason = None

        rule_ids = tuple(r.rule_id for r in matched if r.rule_id)
        total_us = (time.perf_counter_ns() - start_ns) // 1000

        return PolicyDecision(
            action=action,
            severity=severity,
            pipeline_exit_stage=exit_stage,  # type: ignore[arg-type]
            enforcement_level=policy.enforcement_level,
            matched_rules=rule_ids,
            stage_results=tuple(results),
            total_latency_us=int(total_us),
            block_reason=block_reason,
        )


# ─────────────────────────────────────────────── helpers


def _action_severity_rank(action: str) -> int:
    return {
        "blocked": 4,
        "escalated": 3,
        "modified": 2,
        "flagged": 1,
        "allowed": 0,
    }.get(action, 0)


def _exit_stage_for_no_match(results: list[StageResult]) -> str:
    """If we ran multiple stages and none matched, the exit stage is
    'no_match'. If only Stage 1 ran, exit stage is also 'no_match' (the
    decision is "no rule fired").
    """
    if not results:
        return "no_match"
    return "no_match"


# Re-exported for convenience
from typing import Any  # noqa: E402
