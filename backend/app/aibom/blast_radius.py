"""Computed blast radius — the reachable impact if an asset is compromised.

Tier A headline capability. Distinct from ``risk.py``'s ``blast_radius_score``,
which is a stored scalar surfaced as one factor inside supply-chain risk. Here
the number is COMPUTED from the asset's reachability — who it can reach
(downstream consumers, external actions), how far it can act (tools, MCP
servers, autonomy), and what would contain the damage (human-in-loop, no
external actions, internal-only exposure).

Two properties this module is built to guarantee, because a risk number in a
security product is only worth its basis:

* **Honest when thin.** An asset with no agentic metadata gets a low radius whose
  FACTORS say exactly why ("no downstream connections known", "no tool grants
  recorded"). A CISO trusts a number as far as its stated basis; the reasons are
  the product. Nothing is invented from a missing key — absence lowers the
  radius and is reported as absence, never as a plausible default.
* **Deterministic.** Same asset row → byte-identical decomposition. No clock, no
  randomness, no reliance on dict iteration order: factors are emitted in a
  fixed sequence and every list is sorted before it is read. A design partner
  who reruns this must get the same answer, or they trust nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.aibom.coerce import as_bool, as_list, as_positive_int, as_str

# Fixed, documented weights. Order here is the order factors are emitted, so the
# decomposition is stable regardless of input dict ordering.
_TOOL_WEIGHT = 0.20
_EXTERNAL_ACTION_WEIGHT = 0.25
_DOWNSTREAM_WEIGHT = 0.20
_AUTONOMY_WEIGHT = 0.20
_EXPOSURE_WEIGHT = 0.10
_DATA_WEIGHT = 0.05

# Exposure levels that widen blast radius, most-exposed first. A value not in
# this map contributes nothing (honest-empty), not a guessed middle.
_EXPOSURE_SCORE = {
    "public": 100.0,
    "internet": 100.0,
    "internet_facing": 100.0,
    "partner": 60.0,
    "internal": 20.0,
    "internal_only": 20.0,
}

# Data classifications that raise the IMPACT of a compromise.
_DATA_SCORE = {
    "restricted": 100.0,
    "confidential": 80.0,
    "pii": 80.0,
    "internal": 40.0,
    "public": 10.0,
}


@dataclass(frozen=True)
class BlastFactor:
    """One dimension of the blast radius, with the basis it was computed from.
    ``detail`` is the load-bearing field — it is what a reviewer reads to decide
    whether to trust ``score``."""

    name: str
    score: float  # 0–100, this dimension in isolation
    weight: float
    detail: str


@dataclass(frozen=True)
class BlastRadius:
    asset_id: str
    score: float  # 0–100, weighted
    severity: str  # low | medium | high | critical
    reach: dict[str, Any]
    factors: tuple[BlastFactor, ...]
    containment: tuple[str, ...]  # mitigations PRESENT that reduce the radius
    basis: dict[str, Any] = field(default_factory=dict)


def _sorted_strs(value: Any) -> list[str]:
    """A sorted list of the string items of a JSONB list, or [] when the value
    is not a list. Sorted so the reported reach is byte-stable regardless of how
    it was stored; a missing/non-list value is empty, never a placeholder."""
    return sorted(str(v) for v in as_list(value))


def _band(score: float) -> str:
    if score >= 75.0:
        return "critical"
    if score >= 50.0:
        return "high"
    if score >= 25.0:
        return "medium"
    return "low"


def compute_blast_radius(asset: dict[str, Any]) -> BlastRadius:
    """Compute the blast radius from an asset dict (id + agentic metadata).

    Every input is read with ``.get`` and treated as absent when missing — a
    missing key lowers the relevant factor and is reported in its ``detail``,
    never defaulted to a plausible value.
    """
    asset_id = str(asset.get("id") or "")

    tools = _sorted_strs(asset.get("tools"))
    mcp_servers = _sorted_strs(asset.get("mcp_servers"))
    downstream = _sorted_strs(asset.get("downstream_consumers"))
    external_actions = _sorted_strs(asset.get("allowed_external_actions"))

    # Strict typing: a value scores only if it is exactly the expected type. A
    # present-but-malformed value (e.g. is_agentic="false") is NOT scored and
    # says so in its factor detail — the reasons are the product and must not
    # misstate what the operator recorded.
    raw_agentic = asset.get("is_agentic")
    is_agentic = as_bool(raw_agentic) is True
    agentic_malformed = raw_agentic is not None and as_bool(raw_agentic) is None

    raw_hitl = asset.get("human_in_loop_required")
    human_in_loop = as_bool(raw_hitl) is True
    hitl_malformed = raw_hitl is not None and as_bool(raw_hitl) is None

    # max_tool_calls: absent OR malformed means "unknown", treated as unbounded
    # for the autonomy factor only when agentic. A bool, a zero, or a negative is
    # not a budget — as_positive_int rejects all three.
    raw_budget = asset.get("max_tool_calls_per_session")
    max_tool_calls = as_positive_int(raw_budget)
    budget_malformed = raw_budget is not None and max_tool_calls is None

    # Exposure / data class score only when present AND a recognised level. A
    # value that is present but unmapped ("dmz") is reported as unrecognised, not
    # as "not recorded" — the operator DID record something; we just can't score
    # it, and the reason must not imply otherwise.
    raw_exposure = asset.get("exposure")
    exposure = as_str(raw_exposure) or ""
    raw_data = asset.get("data_classification")
    data_class = as_str(raw_data) or ""

    factors: list[BlastFactor] = []

    # 1. Tool / MCP reach — the invocation surface.
    tool_n, mcp_n = len(tools), len(mcp_servers)
    tool_score = min(100.0, (tool_n + mcp_n) * 12.0)
    factors.append(
        BlastFactor(
            "tool_reach",
            tool_score,
            _TOOL_WEIGHT,
            (
                f"{tool_n} tool grant(s) and {mcp_n} MCP server(s)"
                if (tool_n or mcp_n)
                else "no tool grants recorded"
            ),
        )
    )

    # 2. External-action surface — what it can do to the outside world.
    ext_n = len(external_actions)
    ext_score = min(100.0, ext_n * 25.0)
    factors.append(
        BlastFactor(
            "external_action_surface",
            ext_score,
            _EXTERNAL_ACTION_WEIGHT,
            (
                f"{ext_n} allowed external action(s): {external_actions}"
                if ext_n
                else "no external actions granted"
            ),
        )
    )

    # 3. Downstream fan-out — who is impacted if this asset falls.
    down_n = len(downstream)
    down_score = min(100.0, down_n * 20.0)
    factors.append(
        BlastFactor(
            "downstream_fanout",
            down_score,
            _DOWNSTREAM_WEIGHT,
            (
                f"{down_n} downstream consumer(s): {downstream}"
                if down_n
                else "no downstream connections known"
            ),
        )
    )

    # 4. Autonomy — an agentic asset acting without a human gate reaches further.
    if not is_agentic:
        autonomy_score = 0.0
        if agentic_malformed:
            autonomy_detail = "is_agentic present but not a boolean — unscored (treated non-agentic)"
        else:
            autonomy_detail = "non-agentic (no autonomous action)"
    else:
        base = 50.0
        if not human_in_loop:
            base += 30.0
        if max_tool_calls is None or max_tool_calls > 10:
            base += 20.0
        autonomy_score = min(100.0, base)
        if max_tool_calls is not None:
            budget = str(max_tool_calls)
        elif budget_malformed:
            budget = "unparseable (treated unbounded)"
        else:
            budget = "unbounded"
        hitl = "unparseable (treated absent)" if hitl_malformed else str(human_in_loop)
        autonomy_detail = f"agentic; human_in_loop={hitl}; max_tool_calls={budget}"
    factors.append(BlastFactor("autonomy", autonomy_score, _AUTONOMY_WEIGHT, autonomy_detail))

    # 5. Exposure — internet-facing widens the radius.
    exp_score = _EXPOSURE_SCORE.get(exposure, 0.0)
    if exposure in _EXPOSURE_SCORE:
        exp_detail = f"exposure={exposure}"
    elif raw_exposure is None:
        exp_detail = "exposure not recorded"
    else:
        exp_detail = f"exposure={raw_exposure!r} is not a recognised level — unscored"
    factors.append(BlastFactor("exposure", exp_score, _EXPOSURE_WEIGHT, exp_detail))

    # 6. Data sensitivity — raises the impact of any compromise.
    data_score = _DATA_SCORE.get(data_class, 0.0)
    if data_class in _DATA_SCORE:
        data_detail = f"data_classification={data_class}"
    elif raw_data is None:
        data_detail = "data classification not recorded"
    else:
        data_detail = f"data_classification={raw_data!r} is not a recognised level — unscored"
    factors.append(BlastFactor("data_sensitivity", data_score, _DATA_WEIGHT, data_detail))

    total = round(sum(f.score * f.weight for f in factors), 2)
    total = max(0.0, min(100.0, total))

    # Containment — mitigations PRESENT that reduce the radius. Order fixed.
    containment: list[str] = []
    if is_agentic and human_in_loop:
        containment.append("human-in-the-loop required for agentic actions")
    if is_agentic and max_tool_calls is not None:
        containment.append(f"tool-call budget capped at {max_tool_calls} per session")
    if not external_actions:
        containment.append("no external actions granted")
    if exposure in ("internal", "internal_only"):
        containment.append("internal-only exposure")

    reach = {
        "downstream_consumers": downstream,
        "allowed_external_actions": external_actions,
        "tool_reach": {"tools": tool_n, "mcp_servers": mcp_n},
        "autonomy": {
            "is_agentic": is_agentic,
            "max_tool_calls_per_session": max_tool_calls,
            "human_in_loop_required": human_in_loop,
        },
    }

    return BlastRadius(
        asset_id=asset_id,
        score=total,
        severity=_band(total),
        reach=reach,
        factors=tuple(factors),
        containment=tuple(containment),
        basis={
            "tools": tools,
            "mcp_servers": mcp_servers,
            "exposure": exposure or None,
            "data_classification": data_class or None,
        },
    )
