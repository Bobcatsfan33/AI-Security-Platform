"""Supply-chain risk scoring tests."""

from __future__ import annotations

from typing import Any

import pytest

from app.aibom.risk import (
    PROVIDER_TRUST,
    score_supply_chain,
)


def _asset(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "asset-1",
        "provider": "openai",
        "data_classification": "internal",
        "exposure": "internal_only",
        "rag_sources": [],
        "data_lineage": [],
        "tools": [],
        "mcp_servers": [],
        "is_agentic": False,
        "blast_radius_score": 0.0,
        "regulatory_scope": [],
    }
    base.update(overrides)
    return base


@pytest.mark.unit
class TestProviderTrust:
    def test_well_known_provider_lower_risk_component(self) -> None:
        r_openai = score_supply_chain(_asset(provider="openai"))
        r_custom = score_supply_chain(_asset(provider="custom"))
        # provider_trust component: openai → 100-90=10; custom → 100-40=60
        c_openai = next(
            c for c in r_openai.components if c.name == "provider_trust"
        )
        c_custom = next(
            c for c in r_custom.components if c.name == "provider_trust"
        )
        assert c_openai.score < c_custom.score

    def test_unknown_provider_defaults_to_low_trust(self) -> None:
        r = score_supply_chain(_asset(provider="acme-llm"))
        c = next(c for c in r.components if c.name == "provider_trust")
        assert c.score >= 60  # 100 - 30 (default trust)


@pytest.mark.unit
class TestDataClassification:
    @pytest.mark.parametrize(
        "classification,expect_higher_than",
        [
            ("regulated", "public"),
            ("restricted", "internal"),
            ("confidential", "internal"),
        ],
    )
    def test_higher_classifications_higher_risk(
        self, classification: str, expect_higher_than: str
    ) -> None:
        r_high = score_supply_chain(_asset(data_classification=classification))
        r_low = score_supply_chain(_asset(data_classification=expect_higher_than))
        c_high = next(
            c for c in r_high.components if c.name == "data_classification"
        )
        c_low = next(
            c for c in r_low.components if c.name == "data_classification"
        )
        assert c_high.score > c_low.score


@pytest.mark.unit
class TestExposure:
    def test_public_exposure_higher_than_internal(self) -> None:
        r_public = score_supply_chain(_asset(exposure="public"))
        r_internal = score_supply_chain(_asset(exposure="internal_only"))
        c_public = next(c for c in r_public.components if c.name == "exposure")
        c_internal = next(
            c for c in r_internal.components if c.name == "exposure"
        )
        assert c_public.score > c_internal.score


@pytest.mark.unit
class TestPiiDetection:
    def test_explicit_pii_flag_triggers(self) -> None:
        r = score_supply_chain(
            _asset(rag_sources=[{"name": "tickets", "pii_present": True}])
        )
        c = next(c for c in r.components if c.name == "pii_in_data_lineage")
        assert c.score > 0

    def test_regulated_classification_triggers(self) -> None:
        r = score_supply_chain(
            _asset(
                data_lineage=[
                    {"source": "billing", "data_classification": "regulated"}
                ]
            )
        )
        c = next(c for c in r.components if c.name == "pii_in_data_lineage")
        assert c.score > 0

    def test_no_pii_zero(self) -> None:
        r = score_supply_chain(
            _asset(rag_sources=[{"name": "public-docs", "pii_present": False}])
        )
        c = next(c for c in r.components if c.name == "pii_in_data_lineage")
        assert c.score == 0


@pytest.mark.unit
class TestToolSurface:
    def test_more_tools_higher_score(self) -> None:
        r_few = score_supply_chain(_asset(tools=[{"name": "t1"}]))
        r_many = score_supply_chain(
            _asset(tools=[{"name": f"t{i}"} for i in range(20)])
        )
        c_few = next(c for c in r_few.components if c.name == "tool_surface")
        c_many = next(c for c in r_many.components if c.name == "tool_surface")
        assert c_many.score > c_few.score

    def test_capped_at_one_hundred(self) -> None:
        r = score_supply_chain(
            _asset(tools=[{"name": f"t{i}"} for i in range(100)])
        )
        c = next(c for c in r.components if c.name == "tool_surface")
        assert c.score == 100.0


@pytest.mark.unit
class TestAgenticBlastRadius:
    def test_agentic_adds_baseline_risk(self) -> None:
        r_agent = score_supply_chain(
            _asset(is_agentic=True, blast_radius_score=20.0)
        )
        r_static = score_supply_chain(
            _asset(is_agentic=False, blast_radius_score=20.0)
        )
        c_agent = next(
            c for c in r_agent.components if c.name == "agentic_blast_radius"
        )
        c_static = next(
            c for c in r_static.components if c.name == "agentic_blast_radius"
        )
        assert c_agent.score > 0
        assert c_static.score == 0


@pytest.mark.unit
class TestTotal:
    def test_low_risk_asset_low_total(self) -> None:
        r = score_supply_chain(
            _asset(
                provider="openai",
                data_classification="internal",
                exposure="internal_only",
            )
        )
        assert r.score < 30

    def test_high_risk_asset_high_total(self) -> None:
        r = score_supply_chain(
            _asset(
                provider="custom",
                data_classification="regulated",
                exposure="public",
                rag_sources=[{"name": "pii", "pii_present": True}],
                tools=[{"name": f"t{i}"} for i in range(10)],
                mcp_servers=[{"name": "mcp1"}, {"name": "mcp2"}],
                is_agentic=True,
                blast_radius_score=80.0,
                regulatory_scope=["HIPAA", "SOC2", "PCI"],
            )
        )
        assert r.score > 60

    def test_score_bounded(self) -> None:
        # Even the worst possible config should not exceed 100
        r = score_supply_chain(
            _asset(
                provider="acme-yolo-llm",
                data_classification="regulated",
                exposure="public",
                rag_sources=[
                    {"name": f"r{i}", "pii_present": True} for i in range(5)
                ],
                tools=[{"name": f"t{i}"} for i in range(50)],
                mcp_servers=[{"name": f"m{i}"} for i in range(50)],
                is_agentic=True,
                blast_radius_score=100.0,
                regulatory_scope=["HIPAA", "SOC2", "PCI", "FedRAMP", "EU_AI_Act"],
            )
        )
        assert 0 <= r.score <= 100

    def test_components_returned_with_total(self) -> None:
        r = score_supply_chain(_asset())
        # Every named component must be present so the dashboard can render
        # the breakdown without missing keys.
        names = {c.name for c in r.components}
        for required in (
            "provider_trust",
            "data_classification",
            "exposure",
            "pii_in_data_lineage",
            "tool_surface",
            "mcp_server_surface",
            "agentic_blast_radius",
            "regulatory_scope",
        ):
            assert required in names
