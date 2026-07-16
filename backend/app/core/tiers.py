"""Tier registry — the single source of truth for the tiering map.

The platform keeps every capability, but polish is tiered (see
``docs/TIERS.md``, which this module backs):

* **Tier A** — the spearhead, hardened to reference quality: agent/MCP
  security, the runtime agent's policy pipeline and the surfaces that feed
  it, attack graph, blast radius, behavioural anomaly detection.
* **Tier B** — shipped, labelled *preview*: evaluations, red team, reports,
  compliance evidence packs, and the Splunk/Elastic SIEM forwarders.
* **Tier C** — dark until customer pull: frozen, feature-flagged **off** by
  default. Never deleted (the code stays on disk and stays tested).
* **Substrate** — the platform floor Tier A/B stand on (auth, assets,
  connectors, dashboards). Not a marketing surface; not gated.

Why a registry rather than flags sprinkled through the app factory: the
tier of a surface is a *claim* (``docs/TIERS.md``), and this repo's rule is
that a claim points at something mechanically checked. ``create_app`` mounts
**through** this table, so a router cannot drift from its documented tier —
mounting an unregistered router raises, and the tier here is the tier that
ships.

Tier C gating is deny-by-default: ``flag`` names a :class:`Settings`
attribute that must be truthy for the router to mount at all. An unmounted
router is not a 403 — it does not exist in the OpenAPI schema.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# OpenAPI tag stamped on every Tier B route. The frontend reads the same
# string for its preview badge; tests assert both ends.
PREVIEW_TAG = "preview"


class Tier(str, Enum):  # noqa: UP042 - (str, Enum) matches the codebase (see app/policy/types.py)
    A = "A"
    B = "B"
    C = "C"
    SUBSTRATE = "substrate"


@dataclass(frozen=True)
class RouterSpec:
    """How one router is tiered and mounted.

    ``prefix`` is relative to ``settings.api_v1_prefix`` ("" for the bare
    health router). ``flag`` is the Settings attribute gating the mount and
    is set for Tier C only — a Tier A/B surface that needed a kill switch
    would be a tiering mistake, not a flag.
    """

    prefix: str
    tier: Tier
    summary: str
    flag: str | None = None

    def __post_init__(self) -> None:
        if self.flag and self.tier is not Tier.C:
            raise ValueError(f"{self.prefix}: only Tier C routers are flag-gated")
        if self.tier is Tier.C and not self.flag:
            raise ValueError(f"{self.prefix}: Tier C routers must be flag-gated (deny-by-default)")


# Keyed by relative prefix. Order mirrors app.main's mount order.
ROUTER_TIERS: dict[str, RouterSpec] = {
    "": RouterSpec("", Tier.SUBSTRATE, "Liveness and readiness probes."),
    "/auth": RouterSpec("/auth", Tier.SUBSTRATE, "OIDC/SAML SSO, refresh, JWKS."),
    "/connectors": RouterSpec(
        "/connectors", Tier.SUBSTRATE, "Cloud/model connector config and sync."
    ),
    "/assets": RouterSpec("/assets", Tier.SUBSTRATE, "AI asset inventory."),
    "/discovery": RouterSpec("/discovery", Tier.SUBSTRATE, "Per-connector discovery status."),
    "/anomalies": RouterSpec(
        "/anomalies", Tier.A, "Attack graph, behavioural anomalies, causal subtree."
    ),
    "/dashboard": RouterSpec("/dashboard", Tier.SUBSTRATE, "Summary counts."),
    "/dashboards": RouterSpec(
        "/dashboards", Tier.SUBSTRATE, "Runtime/traffic/policy-effectiveness views."
    ),
    "/runtime": RouterSpec(
        "/runtime", Tier.A, "Runtime agent telemetry ingest, heartbeat, control."
    ),
    "/narratives": RouterSpec("/narratives", Tier.SUBSTRATE, "Tier-3 narrative workbench."),
    "/policies": RouterSpec(
        "/policies", Tier.A, "Policy CRUD; serves the runtime agent's policy cache."
    ),
    "/suppressions": RouterSpec(
        "/suppressions", Tier.SUBSTRATE, "Suppression rules and FP metrics."
    ),
    "/validation": RouterSpec(
        "/validation", Tier.SUBSTRATE, "Detection scorecard and efficacy reporting."
    ),
    "/aiguard": RouterSpec(
        "/aiguard", Tier.A, "Inline inspect; Stage-2 classify and Stage-3 judge backends."
    ),
    "/remediation": RouterSpec("/remediation", Tier.SUBSTRATE, "Remediation plan generation."),
    "/risk-index": RouterSpec(
        "/risk-index", Tier.SUBSTRATE, "Risk index computation and model introspection."
    ),
    "/benchmark": RouterSpec("/benchmark", Tier.SUBSTRATE, "Seed corpora and benchmark runs."),
    "/redteam": RouterSpec("/redteam", Tier.B, "Red team campaigns, strategies, findings."),
    "/evaluations": RouterSpec("/evaluations", Tier.B, "Evaluation lifecycle."),
    "/findings": RouterSpec("/findings", Tier.B, "Findings and remediation status."),
    "/test-cases": RouterSpec("/test-cases", Tier.B, "Test case catalogue."),
    "/threat-intel": RouterSpec(
        "/threat-intel",
        Tier.C,
        "Cross-tenant threat-intel clustering. Dark: k-anonymised clustering "
        "over one tenant is a claim with nothing behind it.",
        flag="platform_enable_threat_intel",
    ),
    "/compliance": RouterSpec("/compliance", Tier.B, "Evidence packs and framework catalogue."),
    "/reports": RouterSpec("/reports", Tier.B, "Rendered evaluation reports."),
    "/mcp": RouterSpec("/mcp", Tier.A, "MCP tool profiles, inspection, violations, call chain."),
}


def spec_for(prefix: str) -> RouterSpec:
    """Look up a router's tier. Raises for an unregistered prefix — a new
    router must be tiered before it can mount."""
    try:
        return ROUTER_TIERS[prefix]
    except KeyError:
        raise KeyError(
            f"router prefix {prefix!r} has no tier assignment. Add it to "
            "ROUTER_TIERS and to docs/TIERS.md before mounting it."
        ) from None


def prefixes_for_tier(tier: Tier) -> list[str]:
    return [p for p, spec in ROUTER_TIERS.items() if spec.tier is tier]
