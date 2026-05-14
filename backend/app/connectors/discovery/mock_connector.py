"""MockConnector — deterministic fake source for tests and demos.

Always returns ten assets covering the full :class:`asset_type` enum so
end-to-end pipeline tests (connector → sync → query) can exercise every
shape without a real cloud account.

The ``stable`` config flag makes returned IDs and names deterministic
so test assertions are simple. Set it to false to get fresh UUIDs on
every call (useful for testing dedupe).
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Any

from app.connectors.discovery.base import (
    BaseConnector,
    ConnectionStatus,
    ConnectorMetadata,
    DiscoveredAsset,
)


_FIXTURE: list[dict[str, Any]] = [
    {
        "external_id": "mock-model-gpt-4o",
        "name": "GPT-4o (mock)",
        "asset_type": "model",
        "provider": "openai",
        "version": "2024-08-06",
        "description": "Mock-tracked OpenAI model deployment",
        "metadata": {"tier": "production", "modality": ["text", "vision"]},
    },
    {
        "external_id": "mock-model-claude-sonnet-4",
        "name": "Claude Sonnet 4.6 (mock)",
        "asset_type": "model",
        "provider": "anthropic",
        "version": "4.6",
        "description": "Mock-tracked Anthropic model",
        "metadata": {"tier": "production"},
    },
    {
        "external_id": "mock-endpoint-internal-rag",
        "name": "Internal RAG service",
        "asset_type": "endpoint",
        "provider": "aws_sagemaker",
        "version": "v3",
        "description": "Customer support RAG retrieval endpoint",
        "metadata": {"vpc": "vpc-12345", "scaling": "auto"},
    },
    {
        "external_id": "mock-endpoint-summarizer",
        "name": "Content summarizer endpoint",
        "asset_type": "endpoint",
        "provider": "azure_ml",
        "version": "1.2.0",
        "description": "Customer-facing summarization API",
        "metadata": {"sla": "99.5%"},
    },
    {
        "external_id": "mock-dataset-support-tickets",
        "name": "Support tickets (training set)",
        "asset_type": "dataset",
        "provider": "s3",
        "description": "Anonymized support tickets used for RAG indexing",
        "metadata": {"rows": 1_250_000, "pii_scrubbed": True},
    },
    {
        "external_id": "mock-dataset-product-docs",
        "name": "Product documentation corpus",
        "asset_type": "dataset",
        "provider": "s3",
        "description": "Markdown docs feeding the RAG retriever",
        "metadata": {"rows": 5_000, "language": "en"},
    },
    {
        "external_id": "mock-pipeline-nightly-finetune",
        "name": "Nightly fine-tune pipeline",
        "asset_type": "pipeline",
        "provider": "kubeflow",
        "version": "0.4.2",
        "description": "Re-trains the intent classifier overnight",
        "metadata": {"schedule": "0 2 * * *"},
    },
    {
        "external_id": "mock-agent-incident-bot",
        "name": "Incident triage agent",
        "asset_type": "agent",
        "provider": "langgraph",
        "description": "Routes PagerDuty incidents using an LLM",
        "metadata": {"max_tool_calls": 12},
    },
    {
        "external_id": "mock-agent-research",
        "name": "Research drafting agent",
        "asset_type": "agent",
        "provider": "internal",
        "description": "Drafts research notes with retrieval + summarization",
        "metadata": {"max_steps": 20},
    },
    {
        "external_id": "mock-tool-shell-exec",
        "name": "shell_exec tool",
        "asset_type": "tool",
        "provider": "internal",
        "description": "Restricted shell execution tool exposed to the agent",
        "metadata": {"safety_review": "approved", "owner": "platform-sec"},
    },
]


class MockConnector(BaseConnector):
    """Deterministic 10-asset fake. Use for tests + demos."""

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            name="Mock",
            description="A deterministic fake connector that returns ten "
            "sample assets covering every supported asset type.",
            icon="🧪",
            config_schema={
                "type": "object",
                "properties": {
                    "stable": {
                        "type": "boolean",
                        "default": True,
                        "description": (
                            "When true, external_ids are deterministic. "
                            "When false, fresh UUIDs are appended so "
                            "re-running discover always finds new assets."
                        ),
                    }
                },
                "additionalProperties": False,
            },
            supported_asset_types=[
                "model", "endpoint", "dataset", "pipeline", "agent", "tool"
            ],
        )

    async def discover(self) -> list[DiscoveredAsset]:
        stable = bool(self.config.get("stable", True))
        out: list[DiscoveredAsset] = []
        for entry in _FIXTURE:
            ext_id = entry["external_id"]
            if not stable:
                ext_id = f"{ext_id}-{uuid.uuid4().hex[:8]}"
            out.append(DiscoveredAsset(**{**entry, "external_id": ext_id}))
        return out

    async def sync(self, since: datetime) -> list[DiscoveredAsset]:
        # The mock never reports unchanged assets in sync mode — it
        # returns every asset whose external_id ends in an even-position
        # character to simulate partial change detection. Cheap, but
        # exercises the "incremental" path of the sync service.
        all_assets = await self.discover()
        return [a for i, a in enumerate(all_assets) if i % 2 == 0]

    async def test_connection(self) -> ConnectionStatus:
        start = time.perf_counter()
        # Always succeeds — that's the whole point of a mock.
        latency_ms = (time.perf_counter() - start) * 1000
        return ConnectionStatus(
            connected=True,
            message="Mock connector is always healthy.",
            latency_ms=round(latency_ms, 3),
        )
