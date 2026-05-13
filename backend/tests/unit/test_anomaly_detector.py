"""Tests for the anomaly detector."""

from __future__ import annotations

import uuid

from app.anomaly.attack_graph import Node, NodeStats, EdgeStats, AttackGraph
from app.anomaly.detector import detect_anomalies


def _graph(
    *,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    nodes: list[NodeStats],
    edges: list[EdgeStats],
) -> AttackGraph:
    g = AttackGraph(org_id=org_id, asset_id=asset_id, window="1h")
    for s in nodes:
        g.nodes[s.node.id] = s
        g.total_events += s.count
    for e in edges:
        g.edges[(e.src.id, e.dst.id)] = e
    return g


def test_volume_spike_detected() -> None:
    org = uuid.uuid4()
    asset = uuid.uuid4()
    # Baseline: a few nodes with similar counts → low sigma
    baseline = _graph(
        org_id=org, asset_id=asset,
        nodes=[
            NodeStats(node=Node("tool", "search"), count=10),
            NodeStats(node=Node("tool", "shell"), count=12),
            NodeStats(node=Node("request", "request"), count=11),
        ],
        edges=[],
    )
    # Current window: shell suddenly fires hundreds of times
    current = _graph(
        org_id=org, asset_id=asset,
        nodes=[
            NodeStats(node=Node("tool", "search"), count=10),
            NodeStats(node=Node("tool", "shell"), count=500),
            NodeStats(node=Node("request", "request"), count=11),
        ],
        edges=[],
    )
    anomalies = detect_anomalies(
        org_id=org, asset_id=asset, current=current, baseline=baseline
    )
    spikes = [a for a in anomalies if a.kind == "volume_spike"]
    assert any("shell" in a.title for a in spikes)


def test_novel_transition_detected() -> None:
    org = uuid.uuid4()
    asset = uuid.uuid4()
    # Baseline has request → search but never shell
    base_search = Node("tool", "search")
    base_request = Node("request", "request")
    baseline = _graph(
        org_id=org, asset_id=asset,
        nodes=[
            NodeStats(node=base_request, count=50),
            NodeStats(node=base_search, count=50),
        ],
        edges=[EdgeStats(src=base_request, dst=base_search, count=50)],
    )
    # Current introduces a new transition to shell
    cur_shell = Node("tool", "shell")
    current = _graph(
        org_id=org, asset_id=asset,
        nodes=[
            NodeStats(node=base_request, count=10),
            NodeStats(node=cur_shell, count=10),
        ],
        edges=[EdgeStats(src=base_request, dst=cur_shell, count=10)],
    )
    anomalies = detect_anomalies(
        org_id=org, asset_id=asset, current=current, baseline=baseline
    )
    novel = [a for a in anomalies if a.kind == "novel_transition"]
    assert len(novel) == 1
    assert "shell" in novel[0].title


def test_novel_transition_ignored_below_count() -> None:
    org = uuid.uuid4()
    asset = uuid.uuid4()
    base = Node("request", "request")
    new = Node("tool", "shell")
    baseline = _graph(
        org_id=org, asset_id=asset,
        nodes=[NodeStats(node=base, count=10)],
        edges=[],
    )
    current = _graph(
        org_id=org, asset_id=asset,
        nodes=[NodeStats(node=base, count=5), NodeStats(node=new, count=2)],
        edges=[EdgeStats(src=base, dst=new, count=2)],  # only 2 occurrences
    )
    anomalies = detect_anomalies(
        org_id=org, asset_id=asset, current=current, baseline=baseline
    )
    assert [a for a in anomalies if a.kind == "novel_transition"] == []


def test_risk_inflation_detected() -> None:
    org = uuid.uuid4()
    asset = uuid.uuid4()
    node = Node("response", "response")
    baseline = _graph(
        org_id=org, asset_id=asset,
        nodes=[NodeStats(node=node, count=100, avg_risk=0.10)],
        edges=[],
    )
    current = _graph(
        org_id=org, asset_id=asset,
        nodes=[NodeStats(node=node, count=100, avg_risk=0.75)],
        edges=[],
    )
    anomalies = detect_anomalies(
        org_id=org, asset_id=asset, current=current, baseline=baseline
    )
    risk = [a for a in anomalies if a.kind == "risk_inflation"]
    assert len(risk) == 1
    assert risk[0].detail["current_avg_risk"] == 0.75


def test_quiet_periods_produce_no_anomalies() -> None:
    org = uuid.uuid4()
    asset = uuid.uuid4()
    node = Node("tool", "search")
    baseline = _graph(
        org_id=org, asset_id=asset,
        nodes=[NodeStats(node=node, count=100, avg_risk=0.1)],
        edges=[],
    )
    current = _graph(
        org_id=org, asset_id=asset,
        nodes=[NodeStats(node=node, count=20, avg_risk=0.12)],
        edges=[],
    )
    anomalies = detect_anomalies(
        org_id=org, asset_id=asset, current=current, baseline=baseline
    )
    assert anomalies == []
