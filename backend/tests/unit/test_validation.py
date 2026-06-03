"""Detection-efficacy validation suite (Sprint 13).

Exit criterion: all four brief scenarios (§4.1-4.4) are detected end-to-end
through the real EPA stack with the benign control producing nothing.
"""

from __future__ import annotations

import pytest

from app.validation.harness import run_scenario, run_suite
from app.validation.scenarios import (
    scenario_benign_control,
    scenario_coordinated_exfiltration,
    scenario_gradual_hijack,
    scenario_propagation_chain,
    scenario_resource_exhaustion,
)

pytestmark = pytest.mark.unit


class TestBriefScenarios:
    async def test_propagation_chain_detected(self):
        r = await run_scenario(scenario_propagation_chain())
        assert r.passed, f"expected {r.expected_kinds}, got {r.detected_kinds}"
        assert "propagation_chain" in r.detected_kinds

    async def test_coordinated_exfiltration_detected(self):
        r = await run_scenario(scenario_coordinated_exfiltration())
        assert r.passed
        assert "coordinated_exfiltration" in r.detected_kinds

    async def test_gradual_hijack_detected(self):
        r = await run_scenario(scenario_gradual_hijack())
        assert r.passed
        assert "behavioral_drift" in r.detected_kinds

    async def test_resource_exhaustion_detected(self):
        r = await run_scenario(scenario_resource_exhaustion())
        assert r.passed
        assert "resource_acceleration" in r.detected_kinds

    async def test_benign_control_produces_no_detection(self):
        r = await run_scenario(scenario_benign_control())
        assert r.passed
        assert r.detected_kinds == set()


class TestSuite:
    async def test_full_suite_detects_all_attacks_no_false_positives(self):
        suite = await run_suite()
        assert suite.detection_rate == 1.0, suite.summary()
        assert suite.false_positive_rate == 0.0, suite.summary()

    async def test_summary_shape(self):
        summary = (await run_suite()).summary()
        assert summary["attacks"] == 4
        assert summary["detection_rate"] == 1.0
        # Every brief section §4.1-4.4 is represented.
        sections = {r["brief_section"] for r in summary["results"]}
        assert {"§4.1", "§4.2", "§4.3", "§4.4"}.issubset(sections)
