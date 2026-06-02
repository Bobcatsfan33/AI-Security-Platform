"""AgentEPA — a stateful Event Processing Agent for one agent instance.

Consumes runtime events one at a time, maintains a :class:`BehavioralEnvelope`,
and emits :class:`EpaSignal`s when behaviour deviates. This is the streaming
re-expression of the batch ``app.anomaly.detector`` families:

  - novel_transition : a causal/temporal edge never seen after maturity
  - volume_spike     : a node dominating recent traffic far beyond its
                       pre-window (historical) share — a rate, not a count
  - risk_inflation   : risk EWMA climbs past the frozen baseline
  - behavioral_drift : recent novelty rate spikes vs baseline (abrupt change =
                       possible hijack; gradual = legitimate task switch)

Evaluators read the PRE-update envelope so "is this new?" is answered against
history, then the envelope is mutated. Cold-start safe: nothing alerts before
the envelope matures.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from app.anomaly.attack_graph import _classify, _norm
from app.epa.envelope import BehavioralEnvelope

SignalKind = Literal[
    "novel_transition",
    "volume_spike",
    "risk_inflation",
    "behavioral_drift",
    "resource_acceleration",
    "agent_silent",
]
Severity = Literal["info", "low", "medium", "high", "critical"]

# Thresholds (mirror app.anomaly.detector where applicable).
VOLUME_SPIKE_MIN_COUNT = 10  # min occurrences in the recent window
VOLUME_SPIKE_MIN_SHARE = 0.5  # node must dominate ≥half of recent traffic
VOLUME_SPIKE_FACTOR = 3.0  # ...and ≥3× its lifetime share
RISK_INFLATION_DELTA = 0.20
RISK_INFLATION_MIN_AVG = 0.50
DRIFT_RATE_MIN = 0.30  # recent novelty rate must exceed this to consider drift
DRIFT_RATE_FACTOR = 3.0  # ...and be ≥ this × the lifetime baseline rate


@dataclass(frozen=True)
class EpaSignal:
    agent_instance_id: str
    org_id: str
    asset_id: str
    kind: SignalKind
    severity: Severity
    title: str
    confidence: float = 0.5
    detail: dict[str, Any] = field(default_factory=dict)


class AgentEPA:
    """Stateful monitor for one agent instance. Construct with a loaded (or
    fresh) envelope; call :meth:`process` per event; persist the envelope via
    an EnvelopeStore between events."""

    def __init__(self, envelope: BehavioralEnvelope) -> None:
        self.env = envelope

    def process(self, event: dict[str, Any], *, now: float | None = None) -> list[EpaSignal]:
        if now is None:
            now = _event_epoch(event)
        env = self.env
        org = env.org_id or _norm(event.get("org_id"))
        asset = env.asset_id or _norm(event.get("asset_id"))
        if not env.org_id:
            env.org_id, env.asset_id = org, asset

        node = _classify(event)
        node_id = node.id
        risk = float(event.get("risk_score") or 0.0)
        session = str(event.get("session_id") or "_no_session_")
        event_id = _norm(event.get("event_id"))
        parent_id = _norm(event.get("parent_event_id"))

        # Resolve the incoming transition: prefer the causal parent, fall back
        # to the previous node in the same session.
        src_id: str | None = None
        if parent_id:
            src_id = env.resolve_parent_node(parent_id)
        if src_id is None:
            src_id = env._prev_node_by_session.get(session)

        signals: list[EpaSignal] = []
        mature = env.mature  # snapshot pre-update

        # ── novel transition ─────────────────────────────────────────
        is_novel_edge = False
        edge: tuple[str, str] | None = None
        if src_id is not None and src_id != node_id:
            edge = (src_id, node_id)
            is_novel_edge = edge not in env.seen_edges
            if mature and is_novel_edge:
                signals.append(
                    EpaSignal(
                        agent_instance_id=env.agent_instance_id,
                        org_id=org,
                        asset_id=asset,
                        kind="novel_transition",
                        severity="high",
                        title=f"Novel transition {src_id} → {node_id}",
                        confidence=0.7,
                        detail={"source": src_id, "target": node_id},
                    )
                )

        # ── risk inflation ───────────────────────────────────────────
        if mature and env.baseline_risk_mean is not None:
            projected_mean = env.peek_risk_ewma(risk)
            delta = projected_mean - env.baseline_risk_mean
            if projected_mean >= RISK_INFLATION_MIN_AVG and delta >= RISK_INFLATION_DELTA:
                signals.append(
                    EpaSignal(
                        agent_instance_id=env.agent_instance_id,
                        org_id=org,
                        asset_id=asset,
                        kind="risk_inflation",
                        severity="high" if projected_mean >= 0.8 else "medium",
                        title=f"Risk score climbing on {env.agent_instance_id}",
                        confidence=0.6,
                        detail={
                            "current_avg_risk": round(projected_mean, 3),
                            "baseline_avg_risk": round(env.baseline_risk_mean, 3),
                            "delta": round(delta, 3),
                        },
                    )
                )

        # ── mutate envelope (after pre-update evaluations) ───────────
        env.event_count += 1
        env.record_node(node_id)
        env.record_risk(risk)
        if edge is not None:
            env.record_edge(edge, novel=is_novel_edge)
        env.remember_event(event_id, node_id)
        env._prev_node_by_session[session] = node_id
        tokens = int(event.get("token_count_input") or 0) + int(
            event.get("token_count_output") or 0
        )
        if now is not None:
            env.record_timing(now, tokens=tokens)

        # ── resource acceleration (API/token rate ramping) ──────────
        if mature and env.is_accelerating():
            signals.append(
                EpaSignal(
                    agent_instance_id=env.agent_instance_id,
                    org_id=org,
                    asset_id=asset,
                    kind="resource_acceleration",
                    severity="high",
                    title=f"Accelerating request rate on {env.agent_instance_id}",
                    confidence=0.6,
                    detail={
                        "mean_interval_s": round(env.mean_interval, 4),
                        "tokens_total": env.tokens_total,
                    },
                )
            )

        # ── volume spike (rate, not cumulative count) ────────────────
        # A node dominating recent traffic far beyond its lifetime share =
        # runaway loop / credential-harvest burst. Using share-of-window
        # avoids the two traps of cumulative-count z-scores: counts that only
        # grow, and an outlier inflating its own std (z bounded by √(n−1)).
        if mature:
            recent_count, recent_share, hist_share = env.volume_stats(node_id)
            if (
                recent_count >= VOLUME_SPIKE_MIN_COUNT
                and recent_share >= VOLUME_SPIKE_MIN_SHARE
                and recent_share >= VOLUME_SPIKE_FACTOR * max(hist_share, 0.02)
            ):
                signals.append(
                    EpaSignal(
                        agent_instance_id=env.agent_instance_id,
                        org_id=org,
                        asset_id=asset,
                        kind="volume_spike",
                        severity="high" if recent_share >= 0.8 else "medium",
                        title=f"Volume spike on {node_id}",
                        confidence=min(0.9, 0.4 + recent_share / 2),
                        detail={
                            "node": node_id,
                            "recent_share": round(recent_share, 3),
                            "historical_share": round(hist_share, 3),
                            "recent_count": recent_count,
                        },
                    )
                )

        # ── behavioral drift (abrupt vs gradual) ─────────────────────
        if mature and env.baseline_novelty_rate is not None:
            recent = env.recent_novelty_rate
            base = env.baseline_novelty_rate
            if recent >= DRIFT_RATE_MIN and recent >= DRIFT_RATE_FACTOR * max(base, 0.01):
                signals.append(
                    EpaSignal(
                        agent_instance_id=env.agent_instance_id,
                        org_id=org,
                        asset_id=asset,
                        kind="behavioral_drift",
                        severity="high",
                        title=f"Abrupt behavioral drift on {env.agent_instance_id}",
                        confidence=0.65,
                        detail={
                            "recent_novelty_rate": round(recent, 3),
                            "baseline_novelty_rate": round(base, 3),
                        },
                    )
                )

        # Freeze the baseline the moment we cross maturity.
        env.maybe_freeze_baseline()
        return signals


def _event_epoch(event: dict[str, Any]) -> float | None:
    """Best-effort epoch seconds from a wire event's ISO timestamp. Returns
    None when absent/unparseable so timing-based detection is simply skipped
    rather than guessing (callers pass an explicit ``now`` in tests)."""
    raw = event.get("timestamp")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def absence_signal(env: BehavioralEnvelope, *, now: float, factor: float) -> EpaSignal | None:
    """Negative/absence detection (RAPIDE §3.4): a mature agent that has gone
    silent for ``factor`` × its normal inter-event interval. Evaluated by the
    fleet's sweep, not per-event (absence is the LACK of an event)."""
    if not env.mature or env.mean_interval <= 0.0:
        return None
    silent = env.silent_for(now)
    if silent > factor * env.mean_interval:
        return EpaSignal(
            agent_instance_id=env.agent_instance_id,
            org_id=env.org_id,
            asset_id=env.asset_id,
            kind="agent_silent",
            severity="medium",
            title=f"Agent {env.agent_instance_id} went silent",
            confidence=0.55,
            detail={
                "silent_seconds": round(silent, 2),
                "expected_interval_s": round(env.mean_interval, 4),
            },
        )
    return None
