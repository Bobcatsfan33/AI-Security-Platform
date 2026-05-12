"""Red team campaign orchestrator.

Drives the full evaluate loop:

  1. Generate attacks via :class:`AttackGenerator` against the asset
  2. Execute each attack against the target connector
  3. Judge the response via :class:`AttackJudge`
  4. Aggregate into a :class:`CampaignReport` — per-strategy success rate,
     novel attacks (LLM-generated and successful), category breakdown,
     and total cost

The orchestrator is intentionally a coroutine that yields results so
callers (the evaluation engine, a CLI runner, an admin endpoint) can
stream progress without buffering the entire campaign. For a synchronous
report, ``CampaignRunner.run_campaign`` returns the aggregated dict
directly.

Adaptive generation (feed failures back into the generator for a
second pass) is deferred to a follow-on — current campaigns are a
single fan-out.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

from app.connectors.base import ConnectorError, ConnectorResponse, ModelConnector
from app.redteam.generator import AttackGenerator, GenerationRequest, GeneratedAttack
from app.redteam.judge import AttackJudge, JudgeVerdict
from app.redteam.strategies import STRATEGIES, AttackStrategy

logger = logging.getLogger("platform.redteam.campaign")


@dataclass(frozen=True)
class AttackResult:
    """One executed attack + its judgment."""

    attack: GeneratedAttack
    response_text: str
    response_input_tokens: int
    response_output_tokens: int
    response_cost_usd: float
    response_latency_ms: int
    verdict: JudgeVerdict
    error: str | None = None  # populated when the target connector errored

    @property
    def succeeded(self) -> bool:
        return self.verdict.attack_succeeded


@dataclass(frozen=True)
class CampaignReport:
    """Aggregate report for one campaign run."""

    asset_id: str
    total_attacks: int
    successful_attacks: int
    success_rate: float
    by_strategy: dict[str, dict[str, Any]]
    by_category: dict[str, dict[str, Any]]
    novel_findings: tuple[AttackResult, ...]   # LLM-generated AND successful
    total_cost_usd: float
    total_target_calls: int
    target_errors: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "total_attacks": self.total_attacks,
            "successful_attacks": self.successful_attacks,
            "success_rate": self.success_rate,
            "by_strategy": self.by_strategy,
            "by_category": self.by_category,
            "novel_findings": [
                {
                    "strategy_id": r.attack.strategy_id,
                    "category": r.attack.category,
                    "severity": r.attack.severity,
                    "prompt": r.attack.prompt,
                    "response_text": r.response_text,
                    "verdict": asdict(r.verdict),
                }
                for r in self.novel_findings
            ],
            "total_cost_usd": self.total_cost_usd,
            "total_target_calls": self.total_target_calls,
            "target_errors": self.target_errors,
        }


# ─────────────────────────────────────────────── Runner


class CampaignRunner:
    """Single-pass campaign orchestrator."""

    def __init__(
        self,
        *,
        target_connector: ModelConnector,
        generator: AttackGenerator,
        judge: AttackJudge,
        target_temperature: float = 0.0,
        target_max_tokens: int = 1024,
    ) -> None:
        self._target = target_connector
        self._generator = generator
        self._judge = judge
        self._temp = target_temperature
        self._max_tokens = target_max_tokens

    async def run_campaign(
        self,
        *,
        request: GenerationRequest,
        strategies: list[AttackStrategy] | None = None,
        max_attacks: int | None = None,
    ) -> CampaignReport:
        attacks = await self._generator.generate(
            request=request, strategies=strategies
        )
        if max_attacks is not None:
            attacks = attacks[:max_attacks]

        results: list[AttackResult] = []
        for attack in attacks:
            result = await self._execute_one(attack, request)
            results.append(result)

        return self._aggregate(asset_id=request.asset_id, results=results)

    async def _execute_one(
        self, attack: GeneratedAttack, request: GenerationRequest
    ) -> AttackResult:
        try:
            response: ConnectorResponse = await self._target.generate(
                prompt=attack.prompt,
                system_prompt=request.system_prompt or None,
                temperature=self._temp,
                max_tokens=self._max_tokens,
            )
        except ConnectorError as exc:
            logger.warning(
                "redteam_target_error",
                extra={"strategy_id": attack.strategy_id, "error": str(exc)},
            )
            return AttackResult(
                attack=attack,
                response_text="",
                response_input_tokens=0,
                response_output_tokens=0,
                response_cost_usd=0.0,
                response_latency_ms=0,
                verdict=JudgeVerdict(
                    compliance_score=0.0,
                    attack_succeeded=False,
                    classification="refusal",
                    confidence=0.0,
                    reasoning=f"target connector errored: {exc}",
                    source="no_judge",
                ),
                error=str(exc),
            )

        verdict = await self._judge.judge(
            attack_prompt=attack.prompt,
            response_text=response.text,
            success_indicators=attack.success_indicators,
        )
        return AttackResult(
            attack=attack,
            response_text=response.text,
            response_input_tokens=response.input_tokens,
            response_output_tokens=response.output_tokens,
            response_cost_usd=response.cost_usd,
            response_latency_ms=response.latency_ms,
            verdict=verdict,
        )

    def _aggregate(
        self, *, asset_id: str, results: list[AttackResult]
    ) -> CampaignReport:
        total = len(results)
        successful = sum(1 for r in results if r.succeeded)
        rate = (successful / total) if total else 0.0

        by_strategy: dict[str, dict[str, Any]] = {}
        by_category: dict[str, dict[str, Any]] = {}
        novel: list[AttackResult] = []
        cost = 0.0
        errors = 0

        for r in results:
            sid = r.attack.strategy_id
            cat = r.attack.category
            s_bucket = by_strategy.setdefault(
                sid, {"total": 0, "successful": 0, "category": cat}
            )
            s_bucket["total"] += 1
            if r.succeeded:
                s_bucket["successful"] += 1

            c_bucket = by_category.setdefault(cat, {"total": 0, "successful": 0})
            c_bucket["total"] += 1
            if r.succeeded:
                c_bucket["successful"] += 1

            if r.succeeded and r.attack.source == "llm_generated":
                novel.append(r)

            cost += r.response_cost_usd
            if r.error is not None:
                errors += 1

        return CampaignReport(
            asset_id=asset_id,
            total_attacks=total,
            successful_attacks=successful,
            success_rate=round(rate, 4),
            by_strategy=by_strategy,
            by_category=by_category,
            novel_findings=tuple(novel),
            total_cost_usd=round(cost, 6),
            total_target_calls=total,
            target_errors=errors,
        )
