"""Tests that the anomaly detector operates correctly on poset graphs.

Validates the graph→detector integration after the Sprint 4 causal refactor:
a novel causal transition and a volume spike both surface as anomalies.
"""

from __future__ import annotations

import uuid

import pytest

from app.anomaly.attack_graph import _fold_rows
from app.anomaly.detector import detect_anomalies

ORG = uuid.uuid4()
ASSET = uuid.uuid4()


def _row(event_id, event_type, *, parent=None, tool=None, risk=0.0):
    return {
        "event_id": event_id,
        "parent_event_id": parent,
        "root_event_id": event_id,
        "correlation_key": event_id,
        "session_id": "s1",
        "event_type": event_type,
        "tool_name": tool,
        "action_taken": "allowed",
        "risk_score": risk,
    }


def _graph(rows, window):
    return _fold_rows(org_id=ORG, asset_id=ASSET, window=window, rows=rows)


@pytest.mark.unit
class TestDetectorOnPoset:
    def test_novel_causal_transition_is_flagged(self):
        # Baseline: request → safe tool, repeated.
        baseline_rows = []
        for i in range(20):
            baseline_rows.append(_row(f"r{i}", "request"))
            baseline_rows.append(_row(f"t{i}", "tool_call", parent=f"r{i}", tool="search"))
        baseline = _graph(baseline_rows, "7d")

        # Current window: a NEW causal edge appears — request → shell_exec,
        # three times (above the novelty floor).
        current_rows = []
        for i in range(3):
            current_rows.append(_row(f"cr{i}", "request"))
            current_rows.append(_row(f"ct{i}", "tool_call", parent=f"cr{i}", tool="shell_exec"))
        current = _graph(current_rows, "1h")

        anomalies = detect_anomalies(org_id=ORG, asset_id=ASSET, current=current, baseline=baseline)
        kinds = {a.kind for a in anomalies}
        assert "novel_transition" in kinds
        novel = next(a for a in anomalies if a.kind == "novel_transition")
        assert "shell_exec" in novel.title

    def test_quiet_current_window_yields_no_anomalies(self):
        baseline_rows = []
        for i in range(20):
            baseline_rows.append(_row(f"r{i}", "request"))
            baseline_rows.append(_row(f"t{i}", "tool_call", parent=f"r{i}", tool="search"))
        baseline = _graph(baseline_rows, "7d")

        # Current mirrors baseline behaviour — same edge, low volume.
        current_rows = [
            _row("cr0", "request"),
            _row("ct0", "tool_call", parent="cr0", tool="search"),
        ]
        current = _graph(current_rows, "1h")

        anomalies = detect_anomalies(org_id=ORG, asset_id=ASSET, current=current, baseline=baseline)
        assert all(a.kind != "novel_transition" for a in anomalies)
