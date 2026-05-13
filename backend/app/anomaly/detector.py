"""Anomaly detector — flags suspicious agent behaviour from runtime data.

Three detection families operate on the same underlying telemetry:

1. **Volume spike** — an action node fires N standard deviations above
   its baseline rate. Picks up runaway tool loops and credential
   harvesting.

2. **Novel transition** — an edge appears in the current window that
   wasn't in the baseline window. Picks up newly-injected behaviours
   like a planner suddenly invoking ``shell_exec`` after never doing so.

3. **Risk inflation** — average risk_score on a node climbs above a
   threshold relative to baseline. Picks up gradual drift toward
   risky responses (jailbreak success rate climbing, for instance).

Detection is statistical, not ML. The baselines come from the same
telemetry table; no separate training pipeline. This keeps the system
honest under cold start — every new asset starts with no anomalies and
accumulates signal as it runs.
"""

from __future__ import annotations

import logging
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Literal

from app.anomaly.attack_graph import AttackGraph, build_attack_graph

logger = logging.getLogger("platform.anomaly.detector")


Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Anomaly:
    id: uuid.UUID
    org_id: uuid.UUID
    asset_id: uuid.UUID
    detected_at: datetime
    kind: Literal["volume_spike", "novel_transition", "risk_inflation"]
    severity: Severity
    title: str
    detail: dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────── thresholds


VOLUME_SPIKE_SIGMA = 3.0          # at least 3 stddev above baseline mean
VOLUME_SPIKE_MIN_COUNT = 10       # ignore noise below this absolute floor
RISK_INFLATION_DELTA = 0.20       # avg risk must climb at least 20 pts
RISK_INFLATION_MIN_AVG = 0.50     # current avg must be >= 0.5 to flag


# ─────────────────────────────────────────── core detector


def detect_anomalies(
    *,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    current: AttackGraph,
    baseline: AttackGraph,
) -> list[Anomaly]:
    """Compare two graphs (current short window vs longer baseline) and
    emit anomalies. Pure function — exposed so tests can drive directly."""
    anomalies: list[Anomaly] = []
    now = datetime.now(timezone.utc)

    # Reconstruct baseline per-node rates (counts / number of windows).
    # We treat baseline as a single window and compare counts directly,
    # normalising by the ratio of total events (a rough rate proxy).
    cur_total = max(current.total_events, 1)
    base_total = max(baseline.total_events, 1)
    rate_scale = cur_total / base_total

    # ─── 1. Volume spike ───────────────────────────────────────────
    base_counts = [s.count for s in baseline.nodes.values()] or [0]
    mu = sum(base_counts) / len(base_counts)
    var = sum((c - mu) ** 2 for c in base_counts) / len(base_counts)
    sigma = math.sqrt(var) if var > 0 else 1.0

    for node_id, cur_stats in current.nodes.items():
        if cur_stats.count < VOLUME_SPIKE_MIN_COUNT:
            continue
        base_count = baseline.nodes[node_id].count if node_id in baseline.nodes else 0
        expected = base_count * rate_scale
        z = (cur_stats.count - expected) / sigma
        if z >= VOLUME_SPIKE_SIGMA:
            anomalies.append(
                Anomaly(
                    id=uuid.uuid4(),
                    org_id=org_id,
                    asset_id=asset_id,
                    detected_at=now,
                    kind="volume_spike",
                    severity=_severity_for_z(z),
                    title=f"Volume spike on {cur_stats.node.kind}:{cur_stats.node.key}",
                    detail={
                        "node": node_id,
                        "current_count": cur_stats.count,
                        "expected": round(expected, 2),
                        "z_score": round(z, 2),
                    },
                )
            )

    # ─── 2. Novel transitions ──────────────────────────────────────
    baseline_edges = set(baseline.edges.keys())
    for key, edge in current.edges.items():
        if key in baseline_edges:
            continue
        if edge.count < 3:
            # An edge that fires once or twice in a busy day is too noisy
            # to alert on. Three repetitions is the smallest signal that
            # looks intentional.
            continue
        anomalies.append(
            Anomaly(
                id=uuid.uuid4(),
                org_id=org_id,
                asset_id=asset_id,
                detected_at=now,
                kind="novel_transition",
                severity="high" if edge.count >= 10 else "medium",
                title=(
                    f"Novel transition {edge.src.kind}:{edge.src.key} "
                    f"→ {edge.dst.kind}:{edge.dst.key}"
                ),
                detail={
                    "source": edge.src.id,
                    "target": edge.dst.id,
                    "count": edge.count,
                },
            )
        )

    # ─── 3. Risk inflation ─────────────────────────────────────────
    for node_id, cur_stats in current.nodes.items():
        if cur_stats.avg_risk < RISK_INFLATION_MIN_AVG:
            continue
        base_stats = baseline.nodes.get(node_id)
        base_avg = base_stats.avg_risk if base_stats else 0.0
        delta = cur_stats.avg_risk - base_avg
        if delta >= RISK_INFLATION_DELTA:
            anomalies.append(
                Anomaly(
                    id=uuid.uuid4(),
                    org_id=org_id,
                    asset_id=asset_id,
                    detected_at=now,
                    kind="risk_inflation",
                    severity="high" if cur_stats.avg_risk >= 0.8 else "medium",
                    title=(
                        f"Risk score climbing on {cur_stats.node.kind}:"
                        f"{cur_stats.node.key}"
                    ),
                    detail={
                        "node": node_id,
                        "current_avg_risk": round(cur_stats.avg_risk, 3),
                        "baseline_avg_risk": round(base_avg, 3),
                        "delta": round(delta, 3),
                    },
                )
            )

    return anomalies


def _severity_for_z(z: float) -> Severity:
    if z >= 6.0:
        return "critical"
    if z >= 4.5:
        return "high"
    return "medium"


# ─────────────────────────────────────────── convenience runner


def detect_for_asset(
    *,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    current_window: str = "1h",
    baseline_window: str = "7d",
) -> list[Anomaly]:
    """Build both graphs from ClickHouse and run detection.

    Returns an empty list if ClickHouse is unavailable or there's no
    baseline yet — the caller should not interpret "no anomalies" as
    "system healthy", only as "no signal".
    """
    current = build_attack_graph(
        org_id=org_id, asset_id=asset_id, window=current_window
    )
    baseline = build_attack_graph(
        org_id=org_id, asset_id=asset_id, window=baseline_window
    )
    if baseline.total_events == 0:
        return []
    return detect_anomalies(
        org_id=org_id, asset_id=asset_id, current=current, baseline=baseline
    )
