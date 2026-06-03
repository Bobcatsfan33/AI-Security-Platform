"""Tests for the detection-efficacy report builder (Sprint 14)."""

from __future__ import annotations

import pytest

from app.reports.efficacy import build_efficacy_report

pytestmark = pytest.mark.unit

SUMMARY = {
    "scenarios": 5,
    "attacks": 4,
    "detection_rate": 1.0,
    "false_positive_rate": 0.0,
    "results": [
        {
            "name": "multi-agent-prompt-injection-propagation",
            "brief_section": "§4.1",
            "is_attack": True,
            "expected": ["propagation_chain"],
            "detected": ["propagation_chain"],
            "passed": True,
        },
        {
            "name": "benign-steady-operation",
            "brief_section": "control",
            "is_attack": False,
            "expected": [],
            "detected": [],
            "passed": True,
        },
    ],
}


class TestBuildEfficacyReport:
    def test_renders_headline_metrics(self):
        md = build_efficacy_report(SUMMARY, org_name="Acme", generated_at="2026-06-01")
        assert "# Detection Efficacy Report" in md
        assert "Acme" in md
        assert "100.0%" in md  # detection rate
        assert "0.0%" in md  # fp rate

    def test_lists_each_scenario_with_result(self):
        md = build_efficacy_report(SUMMARY)
        assert "multi-agent-prompt-injection-propagation" in md
        assert "§4.1" in md
        assert "✅ pass" in md

    def test_failing_scenario_marked(self):
        summary = {
            **SUMMARY,
            "detection_rate": 0.5,
            "results": [
                {
                    "name": "x",
                    "brief_section": "§4.2",
                    "expected": ["coordinated_exfiltration"],
                    "detected": [],
                    "passed": False,
                }
            ],
        }
        md = build_efficacy_report(summary)
        assert "❌ FAIL" in md

    def test_baseline_comparison_shows_improvement(self):
        baseline = {"detection_rate": 0.4, "false_positive_rate": 0.6}
        md = build_efficacy_report(SUMMARY, baseline=baseline)
        assert "Versus baseline" in md
        # detection improved (0.4 -> 1.0), fp improved (0.6 -> 0.0)
        assert "improved" in md
        assert "40.0%" in md  # baseline detection
        assert "60.0%" in md  # baseline fp

    def test_includes_honest_caveat(self):
        md = build_efficacy_report(SUMMARY)
        assert "synthetic" in md.lower()
        assert "production" in md.lower()
