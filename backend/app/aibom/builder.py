"""AI Bill of Materials constructor.

Given an :class:`AIAsset` row, assemble the full dependency graph from
the JSONB fields the asset already carries:

    model_provider → model → fine_tuning data → system_prompt →
    rag_sources → vector_db → tools → mcp_servers → plugins →
    downstream_consumers

The blueprint specifies this as Sprint 6 work. We accept the asset row
in dict form so the same function can run against the SQLAlchemy model,
a Pydantic DTO, or a hand-rolled test fixture.

Output shape is a structured BomNode tree suitable for both SPDX/
CycloneDX export (Sprint 6 follow-on) and the dashboard graph
visualization (Sprint 11). The shape is JSON-serializable.

Origin: distilled from TokenDNA modules/identity/agent_discovery.py
without the network-side discovery surface (cloud-billing inspection,
DNS log scraping) — those land in Sprint 6 follow-on. Here we assemble
a BOM from an asset's already-recorded configuration.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

NodeType = Literal[
    "asset",
    "provider",
    "model",
    "fine_tuning",
    "system_prompt",
    "rag_source",
    "vector_db",
    "tool",
    "mcp_server",
    "plugin",
    "external_service",
    "downstream_consumer",
]


@dataclass(frozen=True)
class BomNode:
    """One vertex in the AI-BOM graph."""

    id: str
    type: NodeType
    name: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BomEdge:
    """A directed edge between two BomNodes."""

    src: str
    dst: str
    relationship: str  # "depends_on", "uses", "feeds", "exports_to"


@dataclass(frozen=True)
class AIBom:
    asset_id: str
    nodes: tuple[BomNode, ...]
    edges: tuple[BomEdge, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
        }


# ─────────────────────────────────────────────── Builder


def build_bom(asset: dict[str, Any]) -> AIBom:
    """Construct an :class:`AIBom` from an asset row dict.

    Accepts the dict form produced by the asset CRUD route or by hand
    in tests. Unknown fields are ignored; missing fields produce a
    smaller BOM rather than a hard failure.
    """
    asset_id = str(asset.get("id") or "")
    asset_name = str(asset.get("name") or asset_id)

    nodes: list[BomNode] = []
    edges: list[BomEdge] = []

    # 1. The asset itself is the root node
    nodes.append(
        BomNode(
            id=f"asset:{asset_id}",
            type="asset",
            name=asset_name,
            metadata={
                "environment": asset.get("environment"),
                "exposure": asset.get("exposure"),
                "data_classification": asset.get("data_classification"),
            },
        )
    )

    # 2. Provider + model
    provider = str(asset.get("provider") or "")
    model_name = str(asset.get("model_name") or "")
    if provider:
        provider_id = f"provider:{provider}"
        nodes.append(BomNode(id=provider_id, type="provider", name=provider))
        edges.append(
            BomEdge(src=f"asset:{asset_id}", dst=provider_id, relationship="uses")
        )
        if model_name:
            model_id = f"model:{provider}:{model_name}"
            nodes.append(
                BomNode(
                    id=model_id,
                    type="model",
                    name=model_name,
                    metadata={
                        "model_version": asset.get("model_version"),
                        "hosting": asset.get("hosting"),
                    },
                )
            )
            edges.append(
                BomEdge(src=provider_id, dst=model_id, relationship="provides")
            )

    # 3. Fine-tuning lineage
    ft = asset.get("fine_tuning") or {}
    if isinstance(ft, dict) and (ft.get("dataset_source") or ft.get("method")):
        ft_id = f"ft:{asset_id}"
        nodes.append(
            BomNode(
                id=ft_id,
                type="fine_tuning",
                name=str(ft.get("dataset_source") or "fine_tuning"),
                metadata=ft,
            )
        )
        edges.append(BomEdge(src=ft_id, dst=f"asset:{asset_id}", relationship="feeds"))

    # 4. System prompt (anonymized — store only a fingerprint, not the text)
    sp = asset.get("system_prompt")
    if isinstance(sp, str) and sp:
        sp_id = f"prompt:{asset_id}"
        nodes.append(
            BomNode(
                id=sp_id,
                type="system_prompt",
                name="system_prompt",
                metadata={"length_chars": len(sp), "fingerprint": _short_fingerprint(sp)},
            )
        )
        edges.append(BomEdge(src=sp_id, dst=f"asset:{asset_id}", relationship="feeds"))

    # 5. RAG sources
    for i, rag in enumerate(asset.get("rag_sources") or []):
        if not isinstance(rag, dict):
            continue
        rag_id = f"rag:{asset_id}:{i}"
        nodes.append(
            BomNode(
                id=rag_id,
                type="rag_source",
                name=str(rag.get("name") or f"rag-{i}"),
                metadata=rag,
            )
        )
        edges.append(BomEdge(src=rag_id, dst=f"asset:{asset_id}", relationship="feeds"))

    # 6. Tools
    for i, tool in enumerate(asset.get("tools") or []):
        if not isinstance(tool, dict):
            continue
        tool_id = f"tool:{asset_id}:{tool.get('name', i)}"
        nodes.append(
            BomNode(
                id=tool_id,
                type="tool",
                name=str(tool.get("name") or f"tool-{i}"),
                metadata=tool,
            )
        )
        edges.append(
            BomEdge(src=f"asset:{asset_id}", dst=tool_id, relationship="uses")
        )

    # 7. MCP servers
    for i, mcp in enumerate(asset.get("mcp_servers") or []):
        if not isinstance(mcp, dict):
            continue
        mcp_id = f"mcp:{asset_id}:{mcp.get('name', i)}"
        nodes.append(
            BomNode(
                id=mcp_id,
                type="mcp_server",
                name=str(mcp.get("name") or f"mcp-{i}"),
                metadata=mcp,
            )
        )
        edges.append(
            BomEdge(src=f"asset:{asset_id}", dst=mcp_id, relationship="uses")
        )

    # 8. Plugins
    for i, plugin in enumerate(asset.get("plugins") or []):
        if not isinstance(plugin, dict):
            continue
        plugin_id = f"plugin:{asset_id}:{plugin.get('name', i)}"
        nodes.append(
            BomNode(
                id=plugin_id,
                type="plugin",
                name=str(plugin.get("name") or f"plugin-{i}"),
                metadata=plugin,
            )
        )
        edges.append(
            BomEdge(src=f"asset:{asset_id}", dst=plugin_id, relationship="uses")
        )

    # 9. Upstream services (external dependencies)
    for i, svc in enumerate(asset.get("upstream_services") or []):
        if not isinstance(svc, dict):
            continue
        svc_id = f"upstream:{asset_id}:{svc.get('name', i)}"
        nodes.append(
            BomNode(
                id=svc_id,
                type="external_service",
                name=str(svc.get("name") or f"upstream-{i}"),
                metadata=svc,
            )
        )
        edges.append(
            BomEdge(src=svc_id, dst=f"asset:{asset_id}", relationship="depends_on")
        )

    # 10. Downstream consumers
    for i, c in enumerate(asset.get("downstream_consumers") or []):
        if not isinstance(c, dict):
            continue
        c_id = f"downstream:{asset_id}:{c.get('name', i)}"
        nodes.append(
            BomNode(
                id=c_id,
                type="downstream_consumer",
                name=str(c.get("name") or f"downstream-{i}"),
                metadata=c,
            )
        )
        edges.append(
            BomEdge(src=f"asset:{asset_id}", dst=c_id, relationship="exports_to")
        )

    return AIBom(asset_id=asset_id, nodes=tuple(nodes), edges=tuple(edges))


def _short_fingerprint(text: str) -> str:
    """Truncated SHA-256 — fine for "did this change" comparisons, never
    used for security decisions."""
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
