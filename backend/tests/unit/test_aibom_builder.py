"""AI-BOM builder tests — pure dict-in / dataclass-out."""

from __future__ import annotations

from typing import Any

import pytest

from app.aibom.builder import AIBom, BomEdge, BomNode, build_bom


def _asset(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "asset-1",
        "name": "Test asset",
        "provider": "openai",
        "model_name": "gpt-4o",
        "model_version": "2024-08-06",
        "hosting": "saas_api",
        "environment": "production",
        "exposure": "customer_facing",
        "data_classification": "confidential",
        "system_prompt": None,
        "tools": [],
        "mcp_servers": [],
        "rag_sources": [],
        "plugins": [],
        "fine_tuning": {},
        "upstream_services": [],
        "downstream_consumers": [],
    }
    base.update(overrides)
    return base


@pytest.mark.unit
class TestBomBuilder:
    def test_minimal_asset_yields_root_provider_model(self) -> None:
        bom = build_bom(_asset())
        ids = {n.id for n in bom.nodes}
        assert "asset:asset-1" in ids
        assert "provider:openai" in ids
        assert "model:openai:gpt-4o" in ids
        # Edge from asset → provider, provider → model
        rels = {(e.src, e.dst, e.relationship) for e in bom.edges}
        assert ("asset:asset-1", "provider:openai", "uses") in rels
        assert ("provider:openai", "model:openai:gpt-4o", "provides") in rels

    def test_tools_become_nodes_with_uses_edges(self) -> None:
        bom = build_bom(
            _asset(
                tools=[
                    {"name": "lookup_user", "risk_level": "low"},
                    {"name": "send_email", "risk_level": "high"},
                ]
            )
        )
        tool_nodes = [n for n in bom.nodes if n.type == "tool"]
        assert {n.name for n in tool_nodes} == {"lookup_user", "send_email"}

    def test_rag_sources_feed_the_asset(self) -> None:
        bom = build_bom(
            _asset(
                rag_sources=[
                    {"name": "internal-docs", "data_classification": "internal"}
                ]
            )
        )
        edges = [e for e in bom.edges if e.relationship == "feeds"]
        assert any("rag:asset-1:0" == e.src for e in edges)

    def test_mcp_servers_attached(self) -> None:
        bom = build_bom(
            _asset(
                mcp_servers=[
                    {"name": "filesystem-mcp", "url": "stdio://"},
                    {"name": "github-mcp", "url": "stdio://"},
                ]
            )
        )
        mcp_nodes = [n for n in bom.nodes if n.type == "mcp_server"]
        assert len(mcp_nodes) == 2

    def test_system_prompt_yields_fingerprint_not_text(self) -> None:
        prompt_text = "You are a careful customer support assistant. Never share PII."
        bom = build_bom(_asset(system_prompt=prompt_text))
        sp_nodes = [n for n in bom.nodes if n.type == "system_prompt"]
        assert len(sp_nodes) == 1
        # The text itself is NOT in the node — only length + fingerprint
        assert sp_nodes[0].metadata["length_chars"] == len(prompt_text)
        assert len(sp_nodes[0].metadata["fingerprint"]) == 16
        assert prompt_text not in str(sp_nodes[0])

    def test_upstream_services_form_depends_on_edges(self) -> None:
        bom = build_bom(
            _asset(
                upstream_services=[
                    {"name": "user-service", "url": "https://api.users.example"}
                ]
            )
        )
        edges = [e for e in bom.edges if e.relationship == "depends_on"]
        assert any(e.dst == "asset:asset-1" for e in edges)

    def test_downstream_consumers_form_exports_to(self) -> None:
        bom = build_bom(
            _asset(
                downstream_consumers=[
                    {"name": "support-ui", "type": "web_frontend"}
                ]
            )
        )
        edges = [e for e in bom.edges if e.relationship == "exports_to"]
        assert any(e.src == "asset:asset-1" for e in edges)

    def test_fine_tuning_node_present_when_configured(self) -> None:
        bom = build_bom(
            _asset(
                fine_tuning={
                    "dataset_source": "internal_tickets_v2",
                    "method": "lora",
                }
            )
        )
        ft_nodes = [n for n in bom.nodes if n.type == "fine_tuning"]
        assert len(ft_nodes) == 1
        assert ft_nodes[0].name == "internal_tickets_v2"

    def test_empty_asset_still_produces_root_node(self) -> None:
        bom = build_bom({"id": "x", "name": "empty"})
        assert len(bom.nodes) == 1
        assert bom.nodes[0].type == "asset"
        assert bom.edges == ()

    def test_to_dict_is_json_serializable(self) -> None:
        import json

        bom = build_bom(
            _asset(tools=[{"name": "t1"}], rag_sources=[{"name": "r1"}])
        )
        # Round-trip via JSON to confirm shape is serializable
        round_tripped = json.loads(json.dumps(bom.to_dict()))
        assert round_tripped["asset_id"] == "asset-1"
        assert isinstance(round_tripped["nodes"], list)
