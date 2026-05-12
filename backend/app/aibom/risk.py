"""Supply-chain risk scoring.

Produces a 0–100 score for an asset's supply chain. The score combines
several signals — none of which is decisive on its own — into a
composable risk indicator that a CISO can show on a dashboard and
sort/filter against.

The scoring philosophy: every score component is a transparent
contributor, and the breakdown is returned alongside the total so an
operator can see WHY the score is what it is. Opaque scoring loses
trust faster than any other dashboard feature.

This is genuinely new vs. TokenDNA — TokenDNA tracks individual agent
risk via behavioral DNA and trust graph; the platform's supply-chain
score is upstream of that, looking at static configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


# Provider trust levels — well-known providers reduce risk; unknown /
# self-hosted models the customer cannot vouch for increase it. Adjust
# only on conscious decision (drift in this table moves customer scores
# without explanation).
PROVIDER_TRUST: dict[str, int] = {
    "openai": 90,
    "anthropic": 90,
    "google": 85,
    "azure_openai": 90,
    "bedrock": 85,
    "ollama": 60,  # self-hosted — trust depends on operator vigilance
    "vllm": 55,
    "custom": 40,
}

DATA_CLASS_RISK: dict[str, int] = {
    "regulated": 30,
    "restricted": 25,
    "confidential": 18,
    "internal": 8,
    "public": 0,
}

EXPOSURE_RISK: dict[str, int] = {
    "public": 25,
    "customer_facing": 18,
    "api_only": 12,
    "internal_only": 5,
}


@dataclass(frozen=True)
class RiskComponent:
    name: str
    score: float
    weight: float
    detail: str = ""


@dataclass(frozen=True)
class SupplyChainRisk:
    asset_id: str
    score: float                    # 0–100
    components: tuple[RiskComponent, ...]
    factors: dict[str, Any] = field(default_factory=dict)


def score_supply_chain(asset: dict[str, Any]) -> SupplyChainRisk:
    """Compose a supply-chain risk score from an asset row dict."""
    asset_id = str(asset.get("id") or "")
    components: list[RiskComponent] = []
    factors: dict[str, Any] = {}

    # 1. Provider trust — invert to a risk contribution (100 - trust)
    provider = str(asset.get("provider") or "").lower()
    trust = PROVIDER_TRUST.get(provider, 30)
    provider_risk = 100 - trust
    components.append(
        RiskComponent(
            name="provider_trust",
            score=provider_risk,
            weight=0.20,
            detail=f"{provider!r} → trust {trust}/100",
        )
    )
    factors["provider"] = provider
    factors["provider_trust"] = trust

    # 2. Data classification — sensitive data → higher risk on a leak
    classification = str(asset.get("data_classification") or "internal").lower()
    class_risk = DATA_CLASS_RISK.get(classification, 8)
    components.append(
        RiskComponent(
            name="data_classification",
            score=class_risk * 100 / max(DATA_CLASS_RISK.values()),
            weight=0.15,
            detail=f"{classification!r}",
        )
    )
    factors["data_classification"] = classification

    # 3. Exposure — public-facing endpoints carry more risk
    exposure = str(asset.get("exposure") or "internal_only").lower()
    exposure_risk = EXPOSURE_RISK.get(exposure, 5)
    components.append(
        RiskComponent(
            name="exposure",
            score=exposure_risk * 100 / max(EXPOSURE_RISK.values()),
            weight=0.15,
            detail=f"{exposure!r}",
        )
    )
    factors["exposure"] = exposure

    # 4. PII in RAG / data lineage
    pii_present = _pii_present(asset)
    pii_risk = 80 if pii_present else 0
    components.append(
        RiskComponent(
            name="pii_in_data_lineage",
            score=pii_risk,
            weight=0.15,
            detail="PII detected in RAG/data_lineage" if pii_present else "no PII",
        )
    )
    factors["pii_present"] = pii_present

    # 5. Tool surface — more tools, more risk
    tool_count = len(asset.get("tools") or [])
    tool_risk = min(100.0, tool_count * 8.0)
    components.append(
        RiskComponent(
            name="tool_surface",
            score=tool_risk,
            weight=0.10,
            detail=f"{tool_count} tool(s) registered",
        )
    )
    factors["tool_count"] = tool_count

    # 6. MCP servers — same logic, slightly higher per-server weight
    mcp_count = len(asset.get("mcp_servers") or [])
    mcp_risk = min(100.0, mcp_count * 15.0)
    components.append(
        RiskComponent(
            name="mcp_server_surface",
            score=mcp_risk,
            weight=0.10,
            detail=f"{mcp_count} MCP server(s)",
        )
    )
    factors["mcp_count"] = mcp_count

    # 7. Agentic + blast radius — agentic systems with permissive tool
    # use carry materially more risk than narrow assistant configs
    is_agentic = bool(asset.get("is_agentic"))
    blast = float(asset.get("blast_radius_score") or 0.0)
    if is_agentic:
        agentic_risk = min(100.0, 40.0 + blast)
    else:
        agentic_risk = 0.0
    components.append(
        RiskComponent(
            name="agentic_blast_radius",
            score=agentic_risk,
            weight=0.10,
            detail=(
                f"agentic={is_agentic}, blast_radius_score={blast}"
                if is_agentic
                else "non-agentic"
            ),
        )
    )
    factors["is_agentic"] = is_agentic
    factors["blast_radius_score"] = blast

    # 8. Regulatory scope — anything regulated adds a flat compliance risk
    reg_scope = list(asset.get("regulatory_scope") or [])
    reg_risk = min(100.0, len(reg_scope) * 20.0)
    components.append(
        RiskComponent(
            name="regulatory_scope",
            score=reg_risk,
            weight=0.05,
            detail=f"{len(reg_scope)} framework(s): {reg_scope}",
        )
    )
    factors["regulatory_scope"] = reg_scope

    # Weighted sum, clamped to [0, 100]
    total = sum(c.score * c.weight for c in components)
    total = max(0.0, min(100.0, total))

    return SupplyChainRisk(
        asset_id=asset_id,
        score=round(total, 2),
        components=tuple(components),
        factors=factors,
    )


def _pii_present(asset: dict[str, Any]) -> bool:
    """Detect 'PII present' across RAG sources + data_lineage entries.

    We check ``data_classification`` per-source AND a ``pii_present``
    flag if the operator has annotated it; both surface the signal so
    we don't miss it on either.
    """
    sources: Iterable[Any] = []
    sources = list(sources) + list(asset.get("rag_sources") or [])
    sources = list(sources) + list(asset.get("data_lineage") or [])
    for src in sources:
        if not isinstance(src, dict):
            continue
        if src.get("pii_present") is True:
            return True
        cls = str(src.get("data_classification", "")).lower()
        if cls in ("restricted", "regulated"):
            return True
    return False
