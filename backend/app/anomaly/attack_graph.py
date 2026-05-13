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


@dataclass
class AttackGraph:
    org_id: uuid.UUID
    asset_id: uuid.UUID
    window: str
    nodes: dict[str, NodeStats] = field(default_factory=dict)
    edges: dict[tuple[str, str], EdgeStats] = field(default_factory=dict)
    total_events: int = 0
    session_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": str(self.org_id),
            "asset_id": str(self.asset_id),
            "window": self.window,
            "total_events": self.total_events,
            "session_count": self.session_count,
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
                {"source": e.src.id, "target": e.dst.id, "count": e.count}
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
                    session_id, timestamp, event_type, tool_name,
                    action_taken, risk_score
                FROM {CLICKHOUSE_TABLE}
                WHERE org_id = {{org_id:UUID}}
                  AND asset_id = {{asset_id:UUID}}
                  AND timestamp >= now() - {interval}
                ORDER BY session_id, timestamp
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


def _fold_rows(
    *,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    window: str,
    rows: Iterable[dict[str, Any]],
) -> AttackGraph:
    """Fold a stream of (session-ordered) rows into a graph. Pure —
    exposed separately so tests can drive it without ClickHouse."""
    graph = AttackGraph(org_id=org_id, asset_id=asset_id, window=window)
    sessions_seen: set[str] = set()
    prev_node_by_session: dict[str, Node] = {}
    risk_sum: dict[str, float] = {}

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

        prev = prev_node_by_session.get(session)
        if prev is not None and prev.id != node.id:
            key = (prev.id, node.id)
            edge = graph.edges.get(key)
            if edge is None:
                edge = EdgeStats(src=prev, dst=node)
                graph.edges[key] = edge
            edge.count += 1
        prev_node_by_session[session] = node

    for node_id, stats in graph.nodes.items():
        stats.avg_risk = (
            risk_sum.get(node_id, 0.0) / stats.count if stats.count else 0.0
        )

    graph.session_count = len(sessions_seen)
    return graph
