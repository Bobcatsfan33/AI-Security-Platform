"""Attack graph builder.

Reads agent runtime events from ClickHouse and folds them into a
directed graph whose nodes are *actions* (tool calls, file accesses,
external API calls, retrievals) and whose edges represent observed
transitions within a session.

The graph is the substrate the anomaly detector operates on:
unusually-rare edges, sudden volume spikes on a node, or never-seen-
before action sequences all signal potentially compromised agents.

Design notes
------------
- One graph per (org_id, asset_id) — sessions never cross assets.
- We summarize over a time window so the graph reflects current
  behaviour, not historical noise.
- The action vocabulary maps the runtime_event taxonomy into a small,
  graph-friendly set of node *types* keyed by ``(event_type, key)``
  where ``key`` is the tool name, the file path's parent, or the
  external host. Unknown keys fall back to ``"*"`` so the graph stays
  finite even under adversarial action.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Literal

from app.telemetry.clickhouse_writer import CLICKHOUSE_TABLE, _get_client

logger = logging.getLogger("platform.anomaly.graph")


NodeKind = Literal[
    "request", "response", "tool", "rag", "memory", "file", "external_api",
    "policy_violation", "block", "downgrade", "kill_switch", "alert", "other",
]


@dataclass(frozen=True)
class Node:
    kind: NodeKind
    key: str  # tool name, file dirname, or external host

    @property
    def id(self) -> str:
        return f"{self.kind}:{self.key}"


@dataclass
class NodeStats:
    node: Node
    count: int = 0
    blocked_count: int = 0
    avg_risk: float = 0.0


@dataclass
class EdgeStats:
    src: Node
    dst: Node
    count: int = 0
    # How many of this edge's transitions were drawn from an explicit causal
    # link (parent_event_id) vs. session-temporal adjacency fallback. A
    # causal edge means "src actually caused dst", not "dst happened to
    # follow src in time" — the distinction that kills coincidental-
    # proximity false positives (RAPIDE §3.1).
    causal_count: int = 0

    @property
    def is_causal(self) -> bool:
        return self.causal_count > 0


@dataclass
class AttackGraph:
    org_id: uuid.UUID
    asset_id: uuid.UUID
    window: str
    nodes: dict[str, NodeStats] = field(default_factory=dict)
    edges: dict[tuple[str, str], EdgeStats] = field(default_factory=dict)
    total_events: int = 0
    session_count: int = 0
    # Poset metrics (Sprint 4). causal_edge_count: edges with ≥1 causal
    # transition. concurrent_group_count: number of parent events that
    # fanned out to >1 child (concurrent siblings in the poset).
    causal_edge_count: int = 0
    concurrent_group_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": str(self.org_id),
            "asset_id": str(self.asset_id),
            "window": self.window,
            "total_events": self.total_events,
            "session_count": self.session_count,
            "causal_edge_count": self.causal_edge_count,
            "concurrent_group_count": self.concurrent_group_count,
            "nodes": [
                {
                    "id": s.node.id,
                    "kind": s.node.kind,
                    "key": s.node.key,
                    "count": s.count,
                    "blocked_count": s.blocked_count,
                    "avg_risk": round(s.avg_risk, 4),
                }
                for s in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.src.id,
                    "target": e.dst.id,
                    "count": e.count,
                    "causal": e.is_causal,
                    "causal_count": e.causal_count,
                }
                for e in self.edges.values()
            ],
        }


# ─────────────────────────────────────────── classification


def _classify(event: dict[str, Any]) -> Node:
    """Map a runtime_event row to a graph Node. Pure function."""
    et = event.get("event_type") or "other"
    tool = (event.get("tool_name") or "").strip()
    if et == "tool_call" or et == "tool_result":
        return Node("tool", tool or "unknown")
    if et == "rag_retrieval":
        return Node("rag", "rag")
    if et == "memory_access":
        return Node("memory", "memory")
    if et == "file_access":
        # Use the resource path parent as the key — see telemetry schema.
        # We don't have a dedicated field, so collapse to "*".
        return Node("file", "*")
    if et == "external_api_call":
        return Node("external_api", tool or "*")
    if et in {"request", "response"}:
        return Node(et, et)  # type: ignore[arg-type]
    if et in {
        "policy_violation", "block", "downgrade", "kill_switch", "alert"
    }:
        return Node(et, et)  # type: ignore[arg-type]
    return Node("other", str(et))


# ─────────────────────────────────────────── graph builder


def build_attack_graph(
    *,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    window: str = "24h",
) -> AttackGraph:
    interval = {
        "1h": "INTERVAL 1 HOUR",
        "6h": "INTERVAL 6 HOUR",
        "24h": "INTERVAL 24 HOUR",
        "7d": "INTERVAL 7 DAY",
    }.get(window, "INTERVAL 24 HOUR")

    client = _get_client()
    rows: list[dict[str, Any]] = []
    if client is not None:
        try:
            result = client.query(
                f"""
                SELECT
                    event_id, parent_event_id, root_event_id,
                    correlation_key, session_id, timestamp, event_type,
                    tool_name, action_taken, risk_score
                FROM {CLICKHOUSE_TABLE}
                WHERE org_id = {{org_id:UUID}}
                  AND asset_id = {{asset_id:UUID}}
                  AND timestamp >= now() - {interval}
                ORDER BY timestamp
                """,
                parameters={"org_id": org_id, "asset_id": asset_id},
            )
            columns = list(result.column_names)
            rows = [dict(zip(columns, r)) for r in result.result_rows]
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "attack_graph_query_failed",
                extra={"error": str(exc)},
            )

    return _fold_rows(
        org_id=org_id, asset_id=asset_id, window=window, rows=rows
    )


_WINDOW_INTERVALS = {
    "1h": "INTERVAL 1 HOUR",
    "6h": "INTERVAL 6 HOUR",
    "24h": "INTERVAL 24 HOUR",
    "7d": "INTERVAL 7 DAY",
}


def fetch_causal_subtree(
    *,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    root_event_id: str,
    window: str = "24h",
) -> list[dict[str, Any]]:
    """Fetch the events in the window for an asset and return the causal
    subtree rooted at ``root_event_id``. ClickHouse-backed thin wrapper over
    the pure :func:`causal_subtree`; returns [] if ClickHouse is unavailable.
    """
    interval = _WINDOW_INTERVALS.get(window, "INTERVAL 24 HOUR")
    client = _get_client()
    rows: list[dict[str, Any]] = []
    if client is not None:
        try:
            result = client.query(
                f"""
                SELECT
                    event_id, parent_event_id, root_event_id,
                    correlation_key, session_id, timestamp, event_type,
                    tool_name, action_taken, risk_score
                FROM {CLICKHOUSE_TABLE}
                WHERE org_id = {{org_id:UUID}}
                  AND asset_id = {{asset_id:UUID}}
                  AND timestamp >= now() - {interval}
                ORDER BY timestamp
                """,
                parameters={"org_id": org_id, "asset_id": asset_id},
            )
            columns = list(result.column_names)
            rows = [dict(zip(columns, r)) for r in result.result_rows]
        except Exception as exc:  # noqa: BLE001
            logger.warning("causal_subtree_query_failed", extra={"error": str(exc)})
    return causal_subtree(rows, root_event_id)


def _norm(value: Any) -> str:
    """Normalise an id-ish field to a comparable string. ClickHouse returns
    UUIDs as uuid.UUID or str; NULLs as None or empty. Treat all empties as
    'absent' so lineage checks are uniform."""
    if value is None:
        return ""
    s = str(value).strip()
    # ClickHouse Nullable(UUID) renders an unset value as the zero UUID.
    if s in ("", "00000000-0000-0000-0000-000000000000"):
        return ""
    return s


def _add_edge(
    graph: AttackGraph, src: Node, dst: Node, *, causal: bool
) -> None:
    """Add or increment an edge. Self-loops (src == dst) are skipped — they
    carry no transition signal and would dominate tight tool-retry loops."""
    if src.id == dst.id:
        return
    key = (src.id, dst.id)
    edge = graph.edges.get(key)
    if edge is None:
        edge = EdgeStats(src=src, dst=dst)
        graph.edges[key] = edge
    edge.count += 1
    if causal:
        edge.causal_count += 1


def _fold_rows(
    *,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    window: str,
    rows: Iterable[dict[str, Any]],
) -> AttackGraph:
    """Fold a stream of timestamp-ordered rows into a poset graph. Pure —
    exposed separately so tests can drive it without ClickHouse.

    Edges are drawn from explicit causal lineage (``parent_event_id``) when
    present: parent_event's node → this event's node. This is the RAPIDE
    poset model — an edge means "src caused dst", not merely "dst followed
    src in time". Rows without lineage (pre-Sprint-3 telemetry) fall back to
    session-temporal adjacency so historical data still produces a graph.

    Concurrency: events sharing a parent are concurrent siblings; we count
    how many parents fanned out to >1 child.
    """
    rows = list(rows)
    graph = AttackGraph(org_id=org_id, asset_id=asset_id, window=window)
    sessions_seen: set[str] = set()
    prev_node_by_session: dict[str, Node] = {}
    risk_sum: dict[str, float] = {}

    # Pass 1: classify every event, accumulate node stats, and index nodes by
    # event_id so pass 2 can resolve a parent_event_id to its node.
    node_by_event: dict[str, Node] = {}
    children_by_parent: dict[str, list[str]] = {}

    for row in rows:
        graph.total_events += 1
        session = str(row.get("session_id") or "_no_session_")
        sessions_seen.add(session)

        node = _classify(row)
        stats = graph.nodes.get(node.id)
        if stats is None:
            stats = NodeStats(node=node)
            graph.nodes[node.id] = stats
        stats.count += 1
        if row.get("action_taken") in {"blocked"}:
            stats.blocked_count += 1
        risk_sum[node.id] = risk_sum.get(node.id, 0.0) + float(
            row.get("risk_score") or 0.0
        )

        event_id = _norm(row.get("event_id"))
        if event_id:
            node_by_event[event_id] = node
        parent_id = _norm(row.get("parent_event_id"))
        if parent_id:
            children_by_parent.setdefault(parent_id, []).append(event_id)

    # Pass 2: draw edges. Causal where the parent is known; session-temporal
    # fallback otherwise.
    for row in rows:
        node = _classify(row)
        parent_id = _norm(row.get("parent_event_id"))
        parent_node = node_by_event.get(parent_id) if parent_id else None

        if parent_node is not None:
            _add_edge(graph, parent_node, node, causal=True)
        else:
            session = str(row.get("session_id") or "_no_session_")
            prev = prev_node_by_session.get(session)
            if prev is not None:
                _add_edge(graph, prev, node, causal=False)
        # Track session position for the fallback path regardless.
        session = str(row.get("session_id") or "_no_session_")
        prev_node_by_session[session] = node

    graph.causal_edge_count = sum(1 for e in graph.edges.values() if e.is_causal)
    graph.concurrent_group_count = sum(
        1 for children in children_by_parent.values() if len(children) > 1
    )

    for node_id, stats in graph.nodes.items():
        stats.avg_risk = (
            risk_sum.get(node_id, 0.0) / stats.count if stats.count else 0.0
        )

    graph.session_count = len(sessions_seen)
    return graph


def causal_subtree(
    rows: Iterable[dict[str, Any]], root_event_id: str
) -> list[dict[str, Any]]:
    """Return the causal subtree rooted at ``root_event_id``: that event plus
    every event transitively caused by it (descendants via parent_event_id).

    This is the substrate of the analyst timeline (Phase E) — given any event
    in an incident, reconstruct the complete chain it set off. Pure and
    ClickHouse-free; rows are the event dicts. Order of the returned list is
    breadth-first from the root.
    """
    root = _norm(root_event_id)
    by_parent: dict[str, list[dict[str, Any]]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        eid = _norm(row.get("event_id"))
        if eid:
            by_id[eid] = row
        pid = _norm(row.get("parent_event_id"))
        if pid:
            by_parent.setdefault(pid, []).append(row)

    subtree: list[dict[str, Any]] = []
    seen: set[str] = set()
    frontier = [root]
    while frontier:
        current = frontier.pop(0)
        if current in seen:
            continue  # guard against cycles in malformed data
        seen.add(current)
        if current in by_id:
            subtree.append(by_id[current])
        for child in by_parent.get(current, []):
            child_id = _norm(child.get("event_id"))
            if child_id and child_id not in seen:
                frontier.append(child_id)
    return subtree
