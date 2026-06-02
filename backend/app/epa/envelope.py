"""BehavioralEnvelope — the per-agent state an EPA maintains continuously.

This is the streaming counterpart to the batch attack graph: instead of
recomputing two windows on every API call, each Event Processing Agent keeps
a rolling model of one ``agent_instance_id`` and updates it event-by-event.

The envelope captures what "normal" looks like for an agent:
  - node_counts: how often each action node fires
  - seen_edges: the transitions observed (for novel-transition detection)
  - a Welford running mean/variance of risk_score
  - novelty history: a bounded window of "was this transition new?" booleans,
    the substrate for drift detection (abrupt vs gradual behavioural change)

Cold-start safety: an envelope is not "mature" until it has observed
``MATURITY_MIN`` events. Before maturity the EPA learns but never alerts —
mirroring the batch detector's "no baseline → no anomaly" honesty. At
maturity we freeze a baseline snapshot (risk mean, novelty rate) so drift and
risk-inflation are measured against a stable reference.

The envelope is JSON-serializable (to_dict / from_dict) so the EPA can persist
it to Redis between events and survive restarts.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

MATURITY_MIN = 50  # events before an envelope baselines and may alert
NOVELTY_WINDOW = 50  # recent events tracked for drift
RECENT_NODE_CACHE = 256  # bounded event_id→node map for causal-parent lookup
VOLUME_WINDOW = 30  # recent node-id window for rate-based volume spikes


@dataclass
class BehavioralEnvelope:
    agent_instance_id: str
    org_id: str = ""
    asset_id: str = ""
    event_count: int = 0
    node_counts: dict[str, int] = field(default_factory=dict)
    seen_edges: set[tuple[str, str]] = field(default_factory=set)

    # Welford running stats for risk_score (lifetime mean/var).
    _risk_n: int = 0
    _risk_mean: float = 0.0
    _risk_m2: float = 0.0
    # Responsive EWMA of recent risk — risk-inflation compares this against
    # the frozen baseline so a recent climb is caught in a few events rather
    # than being damped out by a long lifetime mean.
    risk_ewma: float = 0.0
    _ewma_alpha: float = 0.3

    # Frozen-at-maturity baseline snapshot.
    baseline_risk_mean: float | None = None
    baseline_novelty_rate: float | None = None

    # Drift substrate: recent novelty (1 = transition was new) + lifetime tally.
    _novelty_recent: deque[int] = field(default_factory=lambda: deque(maxlen=NOVELTY_WINDOW))
    lifetime_novel_edges: int = 0

    # Recent node-id window — volume spikes are measured as a node's SHARE of
    # recent traffic vs its lifetime share, not a cumulative count (cumulative
    # counts only grow, and a z-score that includes the spike is bounded).
    _recent_nodes: deque[str] = field(default_factory=lambda: deque(maxlen=VOLUME_WINDOW))

    # Per-session previous node + bounded recent event→node map (causal lookup).
    _prev_node_by_session: dict[str, str] = field(default_factory=dict)
    _recent_event_node: "deque[tuple[str, str]]" = field(
        default_factory=lambda: deque(maxlen=RECENT_NODE_CACHE)
    )

    # ── derived ──────────────────────────────────────────────────────
    @property
    def mature(self) -> bool:
        return self.event_count >= MATURITY_MIN

    @property
    def risk_mean(self) -> float:
        return self._risk_mean

    @property
    def risk_std(self) -> float:
        if self._risk_n < 2:
            return 0.0
        return (self._risk_m2 / self._risk_n) ** 0.5

    @property
    def recent_novelty_rate(self) -> float:
        if not self._novelty_recent:
            return 0.0
        return sum(self._novelty_recent) / len(self._novelty_recent)

    @property
    def lifetime_novelty_rate(self) -> float:
        if self.event_count == 0:
            return 0.0
        return self.lifetime_novel_edges / self.event_count

    # ── lookup helpers ───────────────────────────────────────────────
    def resolve_parent_node(self, parent_event_id: str) -> str | None:
        for eid, node in reversed(self._recent_event_node):
            if eid == parent_event_id:
                return node
        return None

    # ── mutation ─────────────────────────────────────────────────────
    def record_risk(self, risk: float) -> None:
        self._risk_n += 1
        delta = risk - self._risk_mean
        self._risk_mean += delta / self._risk_n
        self._risk_m2 += delta * (risk - self._risk_mean)
        if self._risk_n == 1:
            self.risk_ewma = risk
        else:
            self.risk_ewma = self._ewma_alpha * risk + (1 - self._ewma_alpha) * self.risk_ewma

    def peek_risk_ewma(self, risk: float) -> float:
        """The EWMA as it WOULD be after observing ``risk`` (no mutation)."""
        if self._risk_n == 0:
            return risk
        return self._ewma_alpha * risk + (1 - self._ewma_alpha) * self.risk_ewma

    def record_node(self, node_id: str) -> None:
        self.node_counts[node_id] = self.node_counts.get(node_id, 0) + 1
        self._recent_nodes.append(node_id)

    def volume_stats(self, node_id: str) -> tuple[int, float, float]:
        """Volume-spike inputs for ``node_id``:

          (recent_count, recent_share, historical_share)

        recent_* are over the recent window; historical_share is the node's
        share of all OTHER (pre-window) events. Comparing recent vs historical
        — rather than vs lifetime — keeps the spike from contaminating its own
        baseline, so a node that suddenly dominates recent traffic is caught
        even under sustained hammering, while a node that was always dominant
        is not flagged.
        """
        window = len(self._recent_nodes)
        if window == 0:
            return 0, 0.0, 0.0
        recent_count = sum(1 for n in self._recent_nodes if n == node_id)
        recent_share = recent_count / window
        hist_count = self.node_counts.get(node_id, 0) - recent_count
        hist_denom = self.event_count - window
        hist_share = hist_count / hist_denom if hist_denom > 0 else 0.0
        return recent_count, recent_share, hist_share

    def record_edge(self, edge: tuple[str, str], *, novel: bool) -> None:
        self.seen_edges.add(edge)
        self._novelty_recent.append(1 if novel else 0)
        if novel:
            self.lifetime_novel_edges += 1

    def remember_event(self, event_id: str, node_id: str) -> None:
        if event_id:
            self._recent_event_node.append((event_id, node_id))

    def maybe_freeze_baseline(self) -> None:
        """Freeze the reference snapshot exactly once, at maturity."""
        if self.baseline_risk_mean is None and self.mature:
            self.baseline_risk_mean = self._risk_mean
            self.baseline_novelty_rate = self.lifetime_novelty_rate

    # ── serialization (Redis) ────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_instance_id": self.agent_instance_id,
            "org_id": self.org_id,
            "asset_id": self.asset_id,
            "event_count": self.event_count,
            "node_counts": self.node_counts,
            "seen_edges": [list(e) for e in self.seen_edges],
            "_risk_n": self._risk_n,
            "_risk_mean": self._risk_mean,
            "_risk_m2": self._risk_m2,
            "risk_ewma": self.risk_ewma,
            "baseline_risk_mean": self.baseline_risk_mean,
            "baseline_novelty_rate": self.baseline_novelty_rate,
            "novelty_recent": list(self._novelty_recent),
            "lifetime_novel_edges": self.lifetime_novel_edges,
            "recent_nodes": list(self._recent_nodes),
            "prev_node_by_session": self._prev_node_by_session,
            "recent_event_node": [list(x) for x in self._recent_event_node],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BehavioralEnvelope":
        env = cls(agent_instance_id=d["agent_instance_id"])
        env.org_id = d.get("org_id", "")
        env.asset_id = d.get("asset_id", "")
        env.event_count = d.get("event_count", 0)
        env.node_counts = dict(d.get("node_counts", {}))
        env.seen_edges = {tuple(e) for e in d.get("seen_edges", [])}
        env._risk_n = d.get("_risk_n", 0)
        env._risk_mean = d.get("_risk_mean", 0.0)
        env._risk_m2 = d.get("_risk_m2", 0.0)
        env.risk_ewma = d.get("risk_ewma", 0.0)
        env.baseline_risk_mean = d.get("baseline_risk_mean")
        env.baseline_novelty_rate = d.get("baseline_novelty_rate")
        env._novelty_recent = deque(d.get("novelty_recent", []), maxlen=NOVELTY_WINDOW)
        env.lifetime_novel_edges = d.get("lifetime_novel_edges", 0)
        env._recent_nodes = deque(d.get("recent_nodes", []), maxlen=VOLUME_WINDOW)
        env._prev_node_by_session = dict(d.get("prev_node_by_session", {}))
        env._recent_event_node = deque(
            (tuple(x) for x in d.get("recent_event_node", [])),
            maxlen=RECENT_NODE_CACHE,
        )
        return env
