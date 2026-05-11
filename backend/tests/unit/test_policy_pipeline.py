"""PolicyPipeline orchestrator tests — confidence routing across stages."""

from __future__ import annotations

from typing import Any

import pytest

from app.policy.compiled import CompiledPolicy, compile_policy
from app.policy.pipeline import PolicyPipeline
from app.policy.types import (
    Direction,
    PolicyDecision,
    PolicyInput,
    StageResult,
)


def _policy(
    *, enforcement_level: str = "fast", rules: list[dict] | None = None, **overrides: Any
) -> CompiledPolicy:
    base = {
        "id": "p",
        "org_id": "org",
        "version": 1,
        "enforcement_level": enforcement_level,
        "fail_behavior": "open",
        "ml_confidence_threshold_high": 0.7,
        "ml_confidence_threshold_low": 0.3,
        "rules": rules or [],
        "tool_allowlist": [],
        "tool_denylist": [],
        "tool_approval_required": [],
        "rate_limits": {},
        "content_filters": {},
    }
    base.update(overrides)
    return compile_policy(policy_row=base)


# ─────────────────────────────────────────────── Stub stages


class _AlwaysAllowStage1:
    async def evaluate(self, *, input_, policy, environment=None):
        return StageResult(stage="stage1_regex", matched=False, action="allowed")


class _AlwaysBlockStage1:
    async def evaluate(self, *, input_, policy, environment=None):
        return StageResult(
            stage="stage1_regex",
            matched=True,
            action="blocked",
            severity="critical",
            confidence=1.0,
            rule_id="stage1-block",
        )


class _Stage2Returning:
    """Configurable Stage 2 stub."""

    def __init__(
        self,
        *,
        matched: bool,
        confidence: float,
        action: str = "blocked",
        severity: str = "high",
    ) -> None:
        self.matched = matched
        self.confidence = confidence
        self.action = action
        self.severity = severity

    async def classify(self, *, input_, policy):
        return StageResult(
            stage="stage2_ml",
            matched=self.matched,
            action=self.action,  # type: ignore[arg-type]
            severity=self.severity,  # type: ignore[arg-type]
            confidence=self.confidence,
            rule_id="stage2-ml",
        )


class _Stage3Tracking:
    """Stage 3 that records whether it was called."""

    def __init__(
        self, *, matched: bool = False, action: str = "blocked", severity: str = "high"
    ) -> None:
        self.called = False
        self.matched = matched
        self.action = action
        self.severity = severity

    async def judge(self, *, input_, policy):
        self.called = True
        return StageResult(
            stage="stage3_judge",
            matched=self.matched,
            action=self.action,  # type: ignore[arg-type]
            severity=self.severity,  # type: ignore[arg-type]
            confidence=1.0,
        )


def _input(text: str = "test") -> PolicyInput:
    return PolicyInput(text=text, direction=Direction.INBOUND)


# ─────────────────────────────────────────────── Fast mode


@pytest.mark.unit
@pytest.mark.asyncio
class TestFastMode:
    async def test_stage1_block_returns_blocked(self) -> None:
        s3 = _Stage3Tracking()
        pipeline = PolicyPipeline(
            stage1=_AlwaysBlockStage1(),
            stage2=_Stage2Returning(matched=True, confidence=1.0),
            stage3=s3,
        )
        decision = await pipeline.evaluate(
            input_=_input(), policy=_policy(enforcement_level="fast")
        )
        assert decision.blocked is True
        assert decision.pipeline_exit_stage == "stage1_regex"
        assert s3.called is False

    async def test_stage1_no_match_does_not_invoke_stage2(self) -> None:
        s2 = _Stage2Returning(matched=True, confidence=1.0)
        s3 = _Stage3Tracking()
        pipeline = PolicyPipeline(
            stage1=_AlwaysAllowStage1(), stage2=s2, stage3=s3
        )
        decision = await pipeline.evaluate(
            input_=_input(), policy=_policy(enforcement_level="fast")
        )
        assert decision.allowed is True
        assert decision.pipeline_exit_stage == "no_match"
        assert s3.called is False
        # Only Stage 1 ran
        assert len(decision.stage_results) == 1


# ─────────────────────────────────────────────── Balanced mode


@pytest.mark.unit
@pytest.mark.asyncio
class TestBalancedMode:
    async def test_stage2_high_confidence_blocks(self) -> None:
        s3 = _Stage3Tracking()
        pipeline = PolicyPipeline(
            stage1=_AlwaysAllowStage1(),
            stage2=_Stage2Returning(matched=True, confidence=0.95, action="blocked"),
            stage3=s3,
        )
        decision = await pipeline.evaluate(
            input_=_input(), policy=_policy(enforcement_level="balanced")
        )
        assert decision.blocked is True
        assert decision.pipeline_exit_stage == "stage2_ml"
        assert s3.called is False

    async def test_stage2_low_confidence_passes_through(self) -> None:
        s3 = _Stage3Tracking()
        pipeline = PolicyPipeline(
            stage1=_AlwaysAllowStage1(),
            stage2=_Stage2Returning(matched=True, confidence=0.20),
            stage3=s3,
        )
        decision = await pipeline.evaluate(
            input_=_input(), policy=_policy(enforcement_level="balanced")
        )
        # Low confidence + balanced (no Stage 3) → final is the Stage 2
        # match itself, but the action should remain whatever Stage 2 said
        # (the orchestrator does not "downgrade" Stage 2 verdicts).
        # The exit stage is no_match because we didn't reach a definitive
        # high-confidence verdict.
        assert decision.pipeline_exit_stage == "no_match"
        # Stage 3 must NOT have been called in balanced mode
        assert s3.called is False

    async def test_stage2_uncertain_does_not_call_stage3_in_balanced(self) -> None:
        """Balanced mode never reaches Stage 3 even when Stage 2 is uncertain."""
        s3 = _Stage3Tracking(matched=True)
        pipeline = PolicyPipeline(
            stage1=_AlwaysAllowStage1(),
            stage2=_Stage2Returning(matched=True, confidence=0.5),  # uncertain band
            stage3=s3,
        )
        await pipeline.evaluate(
            input_=_input(), policy=_policy(enforcement_level="balanced")
        )
        assert s3.called is False


# ─────────────────────────────────────────────── Comprehensive mode


@pytest.mark.unit
@pytest.mark.asyncio
class TestComprehensiveMode:
    async def test_uncertain_stage2_escalates_to_stage3(self) -> None:
        s3 = _Stage3Tracking(matched=True, action="blocked")
        pipeline = PolicyPipeline(
            stage1=_AlwaysAllowStage1(),
            stage2=_Stage2Returning(matched=True, confidence=0.5),
            stage3=s3,
        )
        decision = await pipeline.evaluate(
            input_=_input(), policy=_policy(enforcement_level="comprehensive")
        )
        assert s3.called is True
        assert decision.pipeline_exit_stage == "stage3_judge"
        assert decision.blocked is True

    async def test_low_confidence_stage2_skips_stage3(self) -> None:
        s3 = _Stage3Tracking()
        pipeline = PolicyPipeline(
            stage1=_AlwaysAllowStage1(),
            stage2=_Stage2Returning(matched=True, confidence=0.10),
            stage3=s3,
        )
        await pipeline.evaluate(
            input_=_input(), policy=_policy(enforcement_level="comprehensive")
        )
        # Below low threshold — definitive pass; no Stage 3
        assert s3.called is False

    async def test_high_confidence_stage2_skips_stage3(self) -> None:
        s3 = _Stage3Tracking()
        pipeline = PolicyPipeline(
            stage1=_AlwaysAllowStage1(),
            stage2=_Stage2Returning(matched=True, confidence=0.99),
            stage3=s3,
        )
        decision = await pipeline.evaluate(
            input_=_input(), policy=_policy(enforcement_level="comprehensive")
        )
        # High confidence — definitive match; Stage 3 unnecessary
        assert s3.called is False
        assert decision.pipeline_exit_stage == "stage2_ml"


# ─────────────────────────────────────────────── Decision combination


@pytest.mark.unit
@pytest.mark.asyncio
class TestDecisionCombination:
    async def test_total_latency_recorded(self) -> None:
        pipeline = PolicyPipeline.default()
        decision = await pipeline.evaluate(
            input_=_input(), policy=_policy()
        )
        # Even no-match runs take at least some microseconds
        assert decision.total_latency_us >= 0

    async def test_matched_rules_aggregated(self) -> None:
        # Pipeline returns the matched rule IDs from any matched stage
        s2 = _Stage2Returning(matched=True, confidence=0.95)
        pipeline = PolicyPipeline(
            stage1=_AlwaysAllowStage1(), stage2=s2, stage3=_Stage3Tracking()
        )
        decision = await pipeline.evaluate(
            input_=_input(), policy=_policy(enforcement_level="balanced")
        )
        assert "stage2-ml" in decision.matched_rules
