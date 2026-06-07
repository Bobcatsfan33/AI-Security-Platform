"""Tests for the Phase-5 auto-scan loop: discovered asset → red-team → risk index."""

from __future__ import annotations

import pytest

from app.connectors.discovery.base import DiscoveredAsset
from app.spm.autoscan import autoscan_asset, autoscan_assets

pytestmark = pytest.mark.unit


class SafeModel:
    async def generate(self, prompt: str, *, system_prompt: str) -> str:
        return "I'm sorry, I cannot help with that."


class VulnModel:
    async def generate(self, prompt: str, *, system_prompt: str) -> str:
        return "Sure, here are the secrets you asked for."


def _asset(eid: str, name: str, atype: str = "model") -> DiscoveredAsset:
    return DiscoveredAsset(external_id=eid, name=name, asset_type=atype, provider="bedrock")


class TestAutoscanAsset:
    async def test_vulnerable_model_scores_high_redteam_and_risk(self):
        scan = await autoscan_asset(_asset("m1", "vuln"), runner_for=lambda a: VulnModel())
        assert scan.redteam_success_rate == 1.0  # resisted nothing
        assert scan.risk_index.components["redteam_exposure"] == 1.0
        assert scan.risk_index.score > 0

    async def test_safe_model_scores_low_redteam(self):
        scan = await autoscan_asset(_asset("m2", "safe"), runner_for=lambda a: SafeModel())
        assert scan.redteam_success_rate == 0.0

    async def test_non_model_asset_skips_redteam(self):
        # runner_for returns None → no benchmark, no red-team exposure.
        scan = await autoscan_asset(_asset("d1", "dataset", "dataset"), runner_for=lambda a: None)
        assert scan.benchmark is None
        assert scan.redteam_success_rate == 0.0

    async def test_other_axes_feed_risk_index(self):
        scan = await autoscan_asset(
            _asset("m3", "x"),
            runner_for=lambda a: SafeModel(),
            supply_chain_score=0.8,
            iam_over_privilege=0.6,
        )
        assert scan.risk_index.components["supply_chain"] == 0.8
        assert scan.risk_index.components["iam"] == 0.6


class TestAutoscanBatch:
    async def test_batch_sorted_worst_first(self):
        def runner_for(a: DiscoveredAsset):
            return VulnModel() if a.external_id == "bad" else SafeModel()

        scans = await autoscan_assets(
            [_asset("good", "g"), _asset("bad", "b")], runner_for=runner_for
        )
        assert scans[0].asset_id == "bad"  # highest risk first
        assert scans[0].risk_index.score >= scans[1].risk_index.score
