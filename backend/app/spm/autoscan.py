"""Auto-scan — discovered assets → red-team → AI Risk Index (Phase 5 core).

When discovery surfaces a new AI asset, the platform should automatically
red-team it and compute its risk posture. This wires the existing pieces into
that loop: a DiscoveredAsset → the Phase-4 benchmark (resilience) → a
redteam_success_rate → the Phase-2 AI Risk Index.

Live cloud discovery connectors (AWS Bedrock/SageMaker, Azure AI Foundry, GCP
Vertex, Hugging Face) need provider credentials and are the documented Phase-5
boundary; this module is provider-agnostic and runs against any
``DiscoveredAsset`` + a runner factory (the connector pool / a sidecar / a test
double).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from app.connectors.discovery.base import DiscoveredAsset
from app.redteam.benchmark import ModelRunner, benchmark_models
from app.spm.risk_index import RiskIndex, compute_risk_index

# Build a model runner for a discovered asset (e.g. a connector-backed client).
# None → the asset isn't a callable model (dataset/pipeline) and is risk-scored
# without a red-team pass.
RunnerFactory = Callable[[DiscoveredAsset], Optional[ModelRunner]]


@dataclass(frozen=True)
class AssetScan:
    asset_id: str
    name: str
    provider: str
    redteam_success_rate: float
    risk_index: RiskIndex
    benchmark: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "provider": self.provider,
            "redteam_success_rate": round(self.redteam_success_rate, 3),
            "risk_index": self.risk_index.to_dict(),
            "benchmark": self.benchmark,
        }


async def autoscan_asset(
    asset: DiscoveredAsset,
    *,
    runner_for: RunnerFactory,
    system_prompts: Optional[dict[str, str]] = None,
    supply_chain_score: float = 0.0,
    iam_over_privilege: float = 0.0,
    runtime_block_rate: float = 0.0,
) -> AssetScan:
    """Red-team a single discovered asset (if it's a model) and risk-score it.
    Non-model assets skip the red-team pass and are scored on the other axes."""
    cfgs = system_prompts or {"baseline": ""}
    runner = runner_for(asset)
    success_rate = 0.0
    bench: Optional[dict[str, Any]] = None

    if runner is not None:
        report = await benchmark_models({asset.external_id: runner}, system_prompts=cfgs)
        best = report.models[0].best_resilience if report.models else 0.0
        success_rate = round(1.0 - best, 4)  # higher resistance → lower success
        bench = report.to_dict()

    risk = compute_risk_index(
        asset_id=asset.external_id,
        supply_chain_score=supply_chain_score,
        iam_over_privilege=iam_over_privilege,
        runtime_block_rate=runtime_block_rate,
        redteam_success_rate=success_rate,
    )
    return AssetScan(
        asset_id=asset.external_id,
        name=asset.name,
        provider=asset.provider,
        redteam_success_rate=success_rate,
        risk_index=risk,
        benchmark=bench,
    )


async def autoscan_assets(
    assets: list[DiscoveredAsset],
    *,
    runner_for: RunnerFactory,
    system_prompts: Optional[dict[str, str]] = None,
) -> list[AssetScan]:
    """Auto-scan a batch of newly-discovered assets. Returns one AssetScan each,
    sorted by risk score (highest first) so the worst assets surface first."""
    scans = [
        await autoscan_asset(a, runner_for=runner_for, system_prompts=system_prompts)
        for a in assets
    ]
    return sorted(scans, key=lambda s: s.risk_index.score, reverse=True)
