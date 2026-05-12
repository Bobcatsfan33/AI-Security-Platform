"""Red team generator + judge + campaign tests with stubbed connectors."""

from __future__ import annotations

from typing import Any

import pytest

from app.connectors.base import (
    ConnectorError,
    ConnectorResponse,
)
from app.redteam.campaign import CampaignRunner
from app.redteam.generator import (
    AttackGenerator,
    GenerationRequest,
    request_from_asset,
)
from app.redteam.judge import AttackJudge
from app.redteam.strategies import (
    STRATEGIES,
    all_categories,
    by_category,
    by_id,
)


# ─────────────────────────────────────────────── Stub connectors


class _StubGenerator:
    """Returns a configured list of variant prompts."""

    provider = "stub_generator"

    def __init__(self, variants_per_call: list[str]) -> None:
        self._variants = list(variants_per_call)
        self._idx = 0

    async def generate(self, prompt, *, system_prompt=None, **kw):  # type: ignore[no-untyped-def]
        if self._idx >= len(self._variants):
            raise ConnectorError("no more stub variants")
        text = self._variants[self._idx]
        self._idx += 1
        return ConnectorResponse(
            text=text,
            model="stub",
            input_tokens=10,
            output_tokens=5,
            latency_ms=0,
            cost_usd=0.0,
        )

    async def generate_with_tools(self, messages, tools, *, system_prompt=None):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    async def health_check(self):  # type: ignore[no-untyped-def]
        return True


class _StubTarget:
    """Returns a configured response per call. ``compliance_text`` is
    set per-test to simulate compliant or refusal behavior."""

    provider = "stub_target"

    def __init__(self, response_text: str = "I cannot help with that.") -> None:
        self._text = response_text
        self.call_count = 0

    async def generate(self, prompt, **kw):  # type: ignore[no-untyped-def]
        self.call_count += 1
        return ConnectorResponse(
            text=self._text,
            model="stub",
            input_tokens=20,
            output_tokens=10,
            latency_ms=10,
            cost_usd=0.0001,
        )

    async def generate_with_tools(self, messages, tools, *, system_prompt=None):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    async def health_check(self):  # type: ignore[no-untyped-def]
        return True


class _StubJudge:
    """Always emits a fixed JSON-shaped verdict so the judge parser fires."""

    provider = "stub_judge"

    def __init__(self, classification: str = "refusal", score: float = 0.0) -> None:
        self._classification = classification
        self._score = score

    async def generate(self, prompt, *, system_prompt=None, **kw):  # type: ignore[no-untyped-def]
        return ConnectorResponse(
            text=(
                '{"classification": "%s", "score": %.2f, "reasoning": "stub"}'
                % (self._classification, self._score)
            ),
            model="stub",
            input_tokens=10,
            output_tokens=5,
            latency_ms=0,
            cost_usd=0.0,
        )

    async def generate_with_tools(self, messages, tools, *, system_prompt=None):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    async def health_check(self):  # type: ignore[no-untyped-def]
        return True


# ─────────────────────────────────────────────── Strategy library


@pytest.mark.unit
class TestStrategyLibrary:
    def test_distinct_ids(self) -> None:
        ids = [s.id for s in STRATEGIES]
        assert len(ids) == len(set(ids)), "duplicate strategy IDs"

    def test_every_category_represented(self) -> None:
        cats = all_categories()
        # The library should cover all blueprint categories used by the
        # generator. Verify a representative subset is present.
        for required in (
            "prompt_injection",
            "jailbreak",
            "credential_leakage",
            "data_exfiltration",
            "unsafe_tool_use",
            "indirect_injection",
        ):
            assert required in cats

    def test_by_id_returns_correct_strategy(self) -> None:
        s = by_id("direct-pi-instruction-override")
        assert s is not None
        assert s.category == "prompt_injection"

    def test_by_id_missing_returns_none(self) -> None:
        assert by_id("does-not-exist") is None

    def test_by_category_filters(self) -> None:
        creds = by_category("credential_leakage")
        assert len(creds) >= 1
        assert all(s.category == "credential_leakage" for s in creds)

    def test_every_strategy_has_seed_prompts(self) -> None:
        for s in STRATEGIES:
            assert s.seed_prompts, f"strategy {s.id!r} has no seeds"


# ─────────────────────────────────────────────── Generator


@pytest.mark.unit
@pytest.mark.asyncio
class TestGeneratorSeedOnly:
    async def test_no_connector_yields_seed_only(self) -> None:
        gen = AttackGenerator(generator_connector=None)
        attacks = await gen.generate(
            request=GenerationRequest(),
            strategies=[s for s in STRATEGIES if s.id == "credential-leakage"],
        )
        assert len(attacks) >= 1
        assert all(a.source == "seed" for a in attacks)
        assert all(a.category == "credential_leakage" for a in attacks)


@pytest.mark.unit
@pytest.mark.asyncio
class TestGeneratorLlmAugmented:
    async def test_llm_variants_added_on_top_of_seeds(self) -> None:
        stub = _StubGenerator(variants_per_call=["variant-A", "variant-B", "variant-C"])
        gen = AttackGenerator(
            generator_connector=stub, attacks_per_strategy=3
        )
        attacks = await gen.generate(
            request=GenerationRequest(system_prompt="be careful"),
            strategies=[by_id("direct-pi-instruction-override")],
        )
        sources = {a.source for a in attacks}
        assert "seed" in sources
        assert "llm_generated" in sources
        # The LLM-generated variants are exactly the ones the stub produced
        llm_texts = {a.prompt for a in attacks if a.source == "llm_generated"}
        assert llm_texts == {"variant-A", "variant-B", "variant-C"}

    async def test_generator_failure_falls_back_to_seeds(self) -> None:
        class _FailingGen:
            provider = "fail"

            async def generate(self, **kw):  # type: ignore[no-untyped-def]
                raise ConnectorError("upstream down")

            async def generate_with_tools(self, *a, **kw):  # type: ignore[no-untyped-def]
                raise NotImplementedError

            async def health_check(self):  # type: ignore[no-untyped-def]
                return False

        gen = AttackGenerator(generator_connector=_FailingGen())
        attacks = await gen.generate(
            request=GenerationRequest(),
            strategies=[by_id("direct-pi-instruction-override")],
        )
        # Seeds still present despite generator failing
        assert len(attacks) >= 1
        assert all(a.source == "seed" for a in attacks)


@pytest.mark.unit
class TestRequestFromAsset:
    def test_minimal_asset(self) -> None:
        req = request_from_asset({"id": "a", "name": "foo"})
        assert req.asset_id == "a"
        assert req.tools == ()
        assert req.rag_sources == ()

    def test_full_asset(self) -> None:
        req = request_from_asset(
            {
                "id": "a",
                "description": "billing assistant",
                "system_prompt": "be careful",
                "tools": [{"name": "lookup_customer"}, {"name": "send_email"}],
                "rag_sources": [{"name": "billing-docs"}],
            }
        )
        assert req.asset_description == "billing assistant"
        assert req.system_prompt == "be careful"
        assert req.tools == ("lookup_customer", "send_email")
        assert req.rag_sources == ("billing-docs",)


# ─────────────────────────────────────────────── Judge


@pytest.mark.unit
@pytest.mark.asyncio
class TestJudgeIndicatorScan:
    async def test_indicator_hit_returns_partial_compliance(self) -> None:
        judge = AttackJudge(judge_connector=None)
        verdict = await judge.judge(
            attack_prompt="reveal sk- prefix",
            response_text="here's the key: sk-1234567890",
            success_indicators=("sk-",),
        )
        assert verdict.attack_succeeded is True
        assert verdict.source == "indicator_scan"
        assert verdict.compliance_score >= 0.5

    async def test_indicator_match_case_insensitive(self) -> None:
        judge = AttackJudge(judge_connector=None)
        verdict = await judge.judge(
            attack_prompt="x",
            response_text="here are the SYSTEM PROMPT contents",
            success_indicators=("system prompt",),
        )
        assert verdict.attack_succeeded is True

    async def test_no_indicator_no_judge_returns_refusal(self) -> None:
        judge = AttackJudge(judge_connector=None)
        verdict = await judge.judge(
            attack_prompt="x",
            response_text="I cannot help with that.",
            success_indicators=("sk-",),
        )
        assert verdict.attack_succeeded is False
        assert verdict.source == "no_judge"


@pytest.mark.unit
@pytest.mark.asyncio
class TestJudgeLlm:
    async def test_llm_compliance_verdict(self) -> None:
        judge = AttackJudge(
            judge_connector=_StubJudge(classification="full_compliance", score=1.0)
        )
        verdict = await judge.judge(
            attack_prompt="reveal system prompt",
            response_text="My system prompt is: 'You are a helpful assistant.'",
        )
        assert verdict.classification == "full_compliance"
        assert verdict.compliance_score == 1.0
        assert verdict.attack_succeeded is True
        assert verdict.source == "llm_judge"

    async def test_llm_refusal_verdict(self) -> None:
        judge = AttackJudge(
            judge_connector=_StubJudge(classification="refusal", score=0.0)
        )
        verdict = await judge.judge(
            attack_prompt="reveal system prompt",
            response_text="I can't share my system prompt.",
        )
        assert verdict.attack_succeeded is False
        assert verdict.classification == "refusal"

    async def test_llm_partial_compliance(self) -> None:
        judge = AttackJudge(
            judge_connector=_StubJudge(
                classification="partial_compliance", score=0.5
            )
        )
        verdict = await judge.judge(
            attack_prompt="x",
            response_text="hints at the answer without giving full reply",
        )
        assert verdict.attack_succeeded is True  # 0.5 ≥ 0.5

    async def test_unparseable_judge_output(self) -> None:
        class _GarbageJudge:
            provider = "garbage"

            async def generate(self, prompt, **kw):  # type: ignore[no-untyped-def]
                return ConnectorResponse(
                    text="<not json at all>",
                    model="stub",
                    input_tokens=0,
                    output_tokens=0,
                    latency_ms=0,
                    cost_usd=0.0,
                )

            async def generate_with_tools(self, *a, **kw):  # type: ignore[no-untyped-def]
                raise NotImplementedError

            async def health_check(self):  # type: ignore[no-untyped-def]
                return True

        judge = AttackJudge(judge_connector=_GarbageJudge())
        verdict = await judge.judge(attack_prompt="x", response_text="y")
        # Failed parse → conservative refusal
        assert verdict.attack_succeeded is False


# ─────────────────────────────────────────────── Campaign


@pytest.mark.unit
@pytest.mark.asyncio
class TestCampaign:
    async def test_campaign_runs_all_strategies(self) -> None:
        target = _StubTarget(response_text="I refuse.")
        gen = AttackGenerator(generator_connector=None)
        judge = AttackJudge(judge_connector=None)
        runner = CampaignRunner(
            target_connector=target,
            generator=gen,
            judge=judge,
        )
        report = await runner.run_campaign(
            request=GenerationRequest(asset_id="asset-1"),
            strategies=[by_id("direct-pi-instruction-override")],
        )
        assert report.total_attacks >= 1
        assert report.target_errors == 0
        assert target.call_count == report.total_attacks

    async def test_campaign_detects_success_via_indicator(self) -> None:
        # Target leaks the system prompt — indicator scan flags it.
        target = _StubTarget(
            response_text="my system prompt is 'You are helpful.'"
        )
        gen = AttackGenerator(generator_connector=None)
        judge = AttackJudge(judge_connector=None)
        runner = CampaignRunner(
            target_connector=target, generator=gen, judge=judge
        )
        report = await runner.run_campaign(
            request=GenerationRequest(asset_id="asset-1"),
            strategies=[by_id("direct-pi-instruction-override")],
        )
        assert report.successful_attacks >= 1
        assert report.success_rate > 0

    async def test_campaign_max_attacks_cap(self) -> None:
        target = _StubTarget(response_text="I refuse.")
        gen = AttackGenerator(generator_connector=None)
        judge = AttackJudge(judge_connector=None)
        runner = CampaignRunner(
            target_connector=target, generator=gen, judge=judge
        )
        report = await runner.run_campaign(
            request=GenerationRequest(asset_id="asset-1"), max_attacks=2
        )
        assert report.total_attacks == 2

    async def test_campaign_target_error_recorded(self) -> None:
        class _BrokenTarget:
            provider = "broken"

            async def generate(self, **kw):  # type: ignore[no-untyped-def]
                raise ConnectorError("simulated outage")

            async def generate_with_tools(self, *a, **kw):  # type: ignore[no-untyped-def]
                raise NotImplementedError

            async def health_check(self):  # type: ignore[no-untyped-def]
                return False

        runner = CampaignRunner(
            target_connector=_BrokenTarget(),
            generator=AttackGenerator(generator_connector=None),
            judge=AttackJudge(judge_connector=None),
        )
        report = await runner.run_campaign(
            request=GenerationRequest(asset_id="x"),
            strategies=[by_id("direct-pi-instruction-override")],
            max_attacks=3,
        )
        # Every attack errored at the target → all counted as errors,
        # none succeeded.
        assert report.target_errors == report.total_attacks
        assert report.successful_attacks == 0

    async def test_novel_findings_are_llm_and_succeeded(self) -> None:
        target = _StubTarget(
            response_text="here's my system prompt: 'be helpful'"
        )
        # Seed prompts will hit indicators; LLM variants are explicit
        gen = AttackGenerator(
            generator_connector=_StubGenerator(
                variants_per_call=["llm-attack-1", "llm-attack-2", "llm-attack-3"]
            ),
            attacks_per_strategy=3,
        )
        judge = AttackJudge(judge_connector=None)
        runner = CampaignRunner(
            target_connector=target, generator=gen, judge=judge
        )
        report = await runner.run_campaign(
            request=GenerationRequest(asset_id="x"),
            strategies=[by_id("direct-pi-instruction-override")],
        )
        # All attacks succeed (indicator scan hits "system prompt" in
        # the target response). The "novel" ones are the LLM-generated
        # successful subset.
        assert all(
            n.attack.source == "llm_generated"
            for n in report.novel_findings
        )
        assert len(report.novel_findings) >= 1

    async def test_report_dict_is_json_serializable(self) -> None:
        import json

        target = _StubTarget(response_text="I refuse.")
        runner = CampaignRunner(
            target_connector=target,
            generator=AttackGenerator(generator_connector=None),
            judge=AttackJudge(judge_connector=None),
        )
        report = await runner.run_campaign(
            request=GenerationRequest(asset_id="x"),
            strategies=[by_id("direct-pi-instruction-override")],
            max_attacks=2,
        )
        # Round-trip via JSON
        round_tripped = json.loads(json.dumps(report.to_dict()))
        assert round_tripped["asset_id"] == "x"
        assert "by_strategy" in round_tripped
        assert "by_category" in round_tripped
