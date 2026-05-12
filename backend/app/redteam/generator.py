"""Adversarial prompt generator.

Takes an asset's configuration and a list of attack strategies, returns
a list of attack prompts tailored to that specific target. Has two modes:

  - ``seed-only`` (default when no generator connector is configured):
    return each strategy's hand-authored seed prompts verbatim. Cheap,
    deterministic, no LLM cost.
  - ``llm-augmented``: pass the asset config to a generator connector
    and ask it to ADAPT the seeds to the target. The generator's system
    prompt is the strategy's ``generator_system_prompt``; failures fall
    back to the seed prompts so a flaky generator never produces zero
    output.

The generator is intentionally simple — adaptive attack generation
(where unsuccessful attacks inform the next variant) is a Sprint 4
follow-on.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.connectors.base import ConnectorError, ModelConnector
from app.redteam.strategies import STRATEGIES, AttackStrategy

logger = logging.getLogger("platform.redteam.generator")


@dataclass(frozen=True)
class GeneratedAttack:
    """One attack ready to execute against a target."""

    strategy_id: str
    category: str
    severity: str
    prompt: str
    source: str  # "seed" | "llm_generated"
    success_indicators: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class GenerationRequest:
    """Inputs to a generator run.

    Fields are subset of the AIAsset model used by the strategy templates.
    The generator pulls only what each strategy needs — strategies that
    don't reference tools/rag_sources can be generated from a stub
    asset for testing.
    """

    asset_id: str = ""
    asset_description: str = "an AI assistant"
    system_prompt: str = ""
    tools: tuple[str, ...] = ()
    rag_sources: tuple[str, ...] = ()


# ─────────────────────────────────────────────── Engine


class AttackGenerator:
    """Builds attack prompts from strategies + asset context."""

    def __init__(
        self,
        *,
        generator_connector: ModelConnector | None = None,
        attacks_per_strategy: int = 3,
    ) -> None:
        self._generator = generator_connector
        self._n_per_strategy = max(1, attacks_per_strategy)

    async def generate(
        self,
        *,
        request: GenerationRequest,
        strategies: list[AttackStrategy] | None = None,
    ) -> list[GeneratedAttack]:
        """Return a list of attacks for the given asset.

        ``strategies`` defaults to the full library. Callers wanting a
        focused campaign (e.g. credential_leakage only) pass a filtered
        subset.
        """
        chosen = strategies if strategies is not None else list(STRATEGIES)
        out: list[GeneratedAttack] = []

        for strategy in chosen:
            # Seed attacks come first — they're deterministic and survive
            # generator failures
            for seed in strategy.seed_prompts:
                out.append(
                    GeneratedAttack(
                        strategy_id=strategy.id,
                        category=strategy.category,
                        severity=strategy.severity,
                        prompt=seed,
                        source="seed",
                        success_indicators=strategy.success_indicators,
                    )
                )

            if self._generator is None:
                continue

            # LLM-augmented variants
            llm_variants = await self._llm_variants(strategy, request)
            for v in llm_variants:
                out.append(
                    GeneratedAttack(
                        strategy_id=strategy.id,
                        category=strategy.category,
                        severity=strategy.severity,
                        prompt=v,
                        source="llm_generated",
                        success_indicators=strategy.success_indicators,
                    )
                )

        return out

    async def _llm_variants(
        self, strategy: AttackStrategy, request: GenerationRequest
    ) -> list[str]:
        """Ask the generator connector for ``_n_per_strategy`` variants.

        Renders ``generator_system_prompt`` against the request. On any
        generator failure, returns an empty list so the seed prompts
        remain the campaign's floor.
        """
        if self._generator is None:
            return []

        system = strategy.generator_system_prompt.format(
            system_prompt=request.system_prompt or "(no system prompt)",
            asset_description=request.asset_description,
            tools=", ".join(request.tools) or "(no tools)",
            rag_sources=", ".join(request.rag_sources) or "(no RAG)",
        )

        variants: list[str] = []
        for _ in range(self._n_per_strategy):
            try:
                response = await self._generator.generate(
                    prompt=(
                        "Produce one adversarial prompt for the described target. "
                        "Output ONLY the prompt text — no preamble, no explanation."
                    ),
                    system_prompt=system,
                    temperature=0.9,
                    max_tokens=512,
                )
                text = response.text.strip()
                if text:
                    variants.append(text)
            except ConnectorError as exc:
                logger.warning(
                    "redteam_generator_failed",
                    extra={
                        "strategy_id": strategy.id,
                        "error": str(exc),
                    },
                )
                break  # don't keep retrying a broken generator
        return variants


def request_from_asset(asset: dict[str, Any]) -> GenerationRequest:
    """Convenience: build a GenerationRequest from an asset row dict."""
    tools = tuple(
        str(t.get("name", "")) if isinstance(t, dict) else str(t)
        for t in (asset.get("tools") or [])
    )
    rag = tuple(
        str(r.get("name", "")) if isinstance(r, dict) else str(r)
        for r in (asset.get("rag_sources") or [])
    )
    return GenerationRequest(
        asset_id=str(asset.get("id", "")),
        asset_description=str(asset.get("description") or asset.get("name") or ""),
        system_prompt=str(asset.get("system_prompt") or ""),
        tools=tools,
        rag_sources=rag,
    )
