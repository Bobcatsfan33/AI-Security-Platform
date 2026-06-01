"""Tests for the poset attack-graph builder (Sprint 4).

The anomaly module had no tests before this. These cover the causal-edge
refactor: edges are drawn from parent_event_id (poset lineage) when present,
falling back to session-temporal adjacency only for pre-Sprint-3 rows that
lack lineage. Also covers concurrency counting and the causal_subtree query.
"""

from __future__ import annotations

import uuid

import pytest

from app.anomaly.attack_graph import (
    _fold_rows,
    causal_subtree,
)

ORG = uuid.uuid4()
ASSET = uuid.uuid4()


def _row(
    event_id,
    event_type,
    *,
    parent=None,
    root=None,
    session="s1",
    tool=None,
    action="allowed",
    risk=0.0,
):
    return {
        "event_id": event_id,
        "parent_event_id": parent,
        "root_event_id": root or event_id,
        "correlation_key": root or event_id,
        "session_id": session,
        "event_type": event_type,
        "tool_name": tool,
        "action_taken": action,
        "risk_score": risk,
    }


def _fold(rows):
    return _fold_rows(org_id=ORG, asset_id=ASSET, window="1h", rows=rows)


@pytest.mark.unit
class TestCausalEdges:
    def test_edge_drawn_from_parent_not_temporal_order(self):
        # req(a) caused tool(b). They are the only events; edge request→tool.
        rows = [
            _row("a", "request"),
            _row("b", "tool_call", parent="a", tool="shell"),
        ]
        g = _fold(rows)
        assert ("request:request", "tool:shell") in g.edges
        edge = g.edges[("request:request", "tool:shell")]
        assert edge.is_causal
        assert edge.causal_count == 1

    def test_all_lineage_means_no_temporal_fallback_edges(self):
        rows = [
            _row("a", "request"),
            _row("b", "tool_call", parent="a", tool="x"),
            _row("c", "external_api_call", parent="b", tool="api"),
        ]
        g = _fold(rows)
        # Every edge is causal; the temporal fallback drew nothing.
        assert g.causal_edge_count == len(g.edges)
        assert len(g.edges) == 2  # request→tool, tool→external_api

    def test_coincidental_temporal_proximity_is_not_a_causal_edge(self):
        # Two unrelated roots in the same session, adjacent in time but with
        # NO causal link. The poset must not invent a causal edge between
        # them — this is the false-positive class RAPIDE targets.
        rows = [
            _row("a", "request", root="a"),
            _row("b", "tool_call", parent="a", tool="x", root="a"),
            # Unrelated second flow, same session, immediately after:
            _row("c", "memory_access", root="c"),  # no parent → fresh root
        ]
        g = _fold(rows)
        # 'c' has no lineage, so a temporal fallback edge tool:x → memory is
        # drawn (legacy behaviour) but flagged non-causal.
        mem_edge = g.edges.get(("tool:x", "memory:memory"))
        assert mem_edge is not None
        assert not mem_edge.is_causal  # fallback, not a real causal claim

    def test_self_loops_are_skipped(self):
        # A tool that retries itself (same node) must not create a self-edge.
        rows = [
            _row("a", "tool_call", tool="x"),
            _row("b", "tool_call", parent="a", tool="x"),
        ]
        g = _fold(rows)
        assert ("tool:x", "tool:x") not in g.edges


@pytest.mark.unit
class TestTemporalFallback:
    def test_pre_sprint3_rows_use_session_temporal_edges(self):
        # No lineage at all (parent=None, event_id absent) → legacy temporal.
        rows = [
            {"session_id": "s1", "event_type": "request", "risk_score": 0.0},
            {"session_id": "s1", "event_type": "tool_call", "tool_name": "x", "risk_score": 0.0},
        ]
        g = _fold(rows)
        edge = g.edges.get(("request:request", "tool:x"))
        assert edge is not None
        assert not edge.is_causal

    def test_separate_sessions_do_not_link(self):
        rows = [
            {"session_id": "s1", "event_type": "request", "risk_score": 0.0},
            {"session_id": "s2", "event_type": "tool_call", "tool_name": "x", "risk_score": 0.0},
        ]
        g = _fold(rows)
        assert g.edges == {}
        assert g.session_count == 2


@pytest.mark.unit
class TestConcurrency:
    def test_fanout_counts_as_concurrent_group(self):
        # request(a) fans out to two concurrent tool calls.
        rows = [
            _row("a", "request"),
            _row("b", "tool_call", parent="a", tool="x"),
            _row("c", "tool_call", parent="a", tool="y"),
        ]
        g = _fold(rows)
        assert g.concurrent_group_count == 1
        assert ("request:request", "tool:x") in g.edges
        assert ("request:request", "tool:y") in g.edges

    def test_linear_chain_has_no_concurrent_groups(self):
        rows = [
            _row("a", "request"),
            _row("b", "tool_call", parent="a", tool="x"),
            _row("c", "external_api_call", parent="b", tool="api"),
        ]
        g = _fold(rows)
        assert g.concurrent_group_count == 0


@pytest.mark.unit
class TestNodeStats:
    def test_blocked_and_risk_accumulate(self):
        rows = [
            _row("a", "request", action="blocked", risk=0.8),
            _row("b", "request", parent="a", action="allowed", risk=0.2),
        ]
        g = _fold(rows)
        stats = g.nodes["request:request"]
        assert stats.count == 2
        assert stats.blocked_count == 1
        assert stats.avg_risk == pytest.approx(0.5)

    def test_to_dict_exposes_causal_flag(self):
        rows = [_row("a", "request"), _row("b", "tool_call", parent="a", tool="x")]
        d = _fold(rows).to_dict()
        assert d["causal_edge_count"] == 1
        edge = next(e for e in d["edges"] if e["target"] == "tool:x")
        assert edge["causal"] is True


@pytest.mark.unit
class TestCausalSubtree:
    def test_returns_transitive_descendants_bfs(self):
        rows = [
            _row("a", "request"),
            _row("b", "tool_call", parent="a", tool="x"),
            _row("c", "external_api_call", parent="b", tool="api"),
            _row("d", "tool_call", parent="a", tool="y"),
        ]
        sub = causal_subtree(rows, "a")
        ids = [r["event_id"] for r in sub]
        assert ids[0] == "a"
        assert set(ids) == {"a", "b", "c", "d"}
        # BFS: direct children (b, d) appear before grandchild (c).
        assert ids.index("c") > ids.index("b")

    def test_subtree_from_midpoint_excludes_ancestors(self):
        rows = [
            _row("a", "request"),
            _row("b", "tool_call", parent="a", tool="x"),
            _row("c", "external_api_call", parent="b", tool="api"),
        ]
        sub = causal_subtree(rows, "b")
        ids = {r["event_id"] for r in sub}
        assert ids == {"b", "c"}  # 'a' (ancestor) excluded

    def test_cycle_in_malformed_data_terminates(self):
        # a→b→a (malformed). Must not infinite-loop.
        rows = [
            _row("a", "request", parent="b"),
            _row("b", "tool_call", parent="a", tool="x"),
        ]
        sub = causal_subtree(rows, "a")
        assert len(sub) <= 2  # terminates, no hang

    def test_unknown_root_returns_empty(self):
        rows = [_row("a", "request")]
        assert causal_subtree(rows, "zzz") == []
