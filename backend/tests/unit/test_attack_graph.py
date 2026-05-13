"""Tests for the attack graph builder."""

from __future__ import annotations

import uuid

from app.anomaly.attack_graph import _classify, _fold_rows


def test_classify_maps_event_types() -> None:
    assert _classify({"event_type": "tool_call", "tool_name": "shell"}).kind == "tool"
    assert _classify({"event_type": "rag_retrieval"}).kind == "rag"
    assert _classify({"event_type": "memory_access"}).kind == "memory"
    assert _classify({"event_type": "file_access"}).kind == "file"
    assert _classify({"event_type": "external_api_call"}).kind == "external_api"
    assert _classify({"event_type": "policy_violation"}).kind == "policy_violation"
    assert _classify({"event_type": "block"}).kind == "block"
    assert _classify({"event_type": "request"}).kind == "request"
    assert _classify({"event_type": "wat"}).kind == "other"


def test_fold_groups_by_session_and_emits_edges() -> None:
    org = uuid.uuid4()
    asset = uuid.uuid4()
    rows = [
        # session A
        {"session_id": "A", "event_type": "request", "risk_score": 0.1, "action_taken": "allowed"},
        {"session_id": "A", "event_type": "tool_call", "tool_name": "search", "risk_score": 0.2},
        {"session_id": "A", "event_type": "tool_call", "tool_name": "shell", "risk_score": 0.9},
        # session B
        {"session_id": "B", "event_type": "request", "risk_score": 0.0},
        {"session_id": "B", "event_type": "tool_call", "tool_name": "search", "risk_score": 0.3},
        {"session_id": "B", "event_type": "block", "action_taken": "blocked", "risk_score": 0.8},
    ]
    graph = _fold_rows(org_id=org, asset_id=asset, window="1h", rows=rows)

    assert graph.total_events == 6
    assert graph.session_count == 2
    # Nodes present
    assert "request:request" in graph.nodes
    assert "tool:search" in graph.nodes
    assert "tool:shell" in graph.nodes
    assert "block:block" in graph.nodes
    # Blocked count routed to the block node
    assert graph.nodes["block:block"].blocked_count == 1
    # Edges connect successive events within the same session
    edges = set(graph.edges.keys())
    assert ("request:request", "tool:search") in edges
    assert ("tool:search", "tool:shell") in edges
    assert ("tool:search", "block:block") in edges
    # No cross-session edge
    assert ("tool:shell", "request:request") not in edges


def test_fold_collapses_same_node_repeats_into_count_only() -> None:
    rows = [
        {"session_id": "A", "event_type": "tool_call", "tool_name": "search"},
        {"session_id": "A", "event_type": "tool_call", "tool_name": "search"},
        {"session_id": "A", "event_type": "tool_call", "tool_name": "search"},
    ]
    graph = _fold_rows(
        org_id=uuid.uuid4(), asset_id=uuid.uuid4(), window="1h", rows=rows
    )
    assert graph.nodes["tool:search"].count == 3
    # Self-loop not recorded — repeated calls should bump count, not edges
    assert graph.edges == {}


def test_to_dict_shape_is_stable() -> None:
    rows = [
        {"session_id": "A", "event_type": "request"},
        {"session_id": "A", "event_type": "tool_call", "tool_name": "x"},
    ]
    graph = _fold_rows(
        org_id=uuid.uuid4(), asset_id=uuid.uuid4(), window="1h", rows=rows
    )
    d = graph.to_dict()
    assert set(d.keys()) >= {
        "org_id", "asset_id", "window", "total_events",
        "session_count", "nodes", "edges",
    }
    assert isinstance(d["nodes"], list)
    assert isinstance(d["edges"], list)
    for n in d["nodes"]:
        assert set(n.keys()) >= {"id", "kind", "key", "count"}
