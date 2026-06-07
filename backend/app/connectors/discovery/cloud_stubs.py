"""Cloud discovery connector stubs — real interface + metadata, no live crawl.

These register the major managed-AI clouds (AWS SageMaker, AWS Bedrock, Azure
ML, GCP Vertex AI, Hugging Face) with the discovery registry so the platform
*knows about* them: ``/v1/connectors/available`` renders each one's
registration form from a real, provider-accurate ``config_schema``, and an
admin can create + store a connector row for it today.

What they deliberately do **not** do is fake a crawl. The live transport for
each — the cloud SDK calls behind real credentials — is the Phase 5 work that
needs actual cloud accounts to build and verify, so:

* :meth:`test_connection` validates that the *required config fields* are
  present and then reports, honestly, that live discovery isn't wired yet
  (``connected=False``) — it never fabricates a healthy connection.
* :meth:`discover` / :meth:`sync` raise :class:`ConnectorNotImplementedError`
  with a clear message. The SyncService is fail-safe, so a triggered sync is
  recorded as ``failed`` with that message rather than silently reporting zero
  assets (which would read as "nothing to find").

This is the honest stub: the registration/UI surface is fully real; the crawl
is explicitly pending, not faked.
"""

from __future__ import annotations

from datetime import datetime
from typing import ClassVar

from app.connectors.discovery.base import (
    BaseConnector,
    ConnectionStatus,
    ConnectorMetadata,
    DiscoveredAsset,
)


class ConnectorNotImplementedError(NotImplementedError):
    """Raised by a stub connector's crawl methods — the interface and metadata
    are real, but the live cloud transport is not yet implemented."""


def _str_field(description: str, *, secret: bool = False) -> dict[str, object]:
    field: dict[str, object] = {"type": "string", "description": description}
    if secret:
        field["format"] = "password"
    return field


class CloudStubConnector(BaseConnector):
    """Shared base for the cloud discovery stubs.

    Subclasses declare the catalog metadata as class attributes; the crawl
    methods and an honest ``test_connection`` are inherited. ``required_fields``
    is the subset of ``config_schema`` properties an admin must supply — used by
    ``test_connection`` to give actionable feedback before the live transport
    exists.
    """

    # ── catalog metadata (subclasses override) ───────────────────────────
    display_name: str = "Cloud"
    description: str = ""
    icon: str = "☁️"
    supported_asset_types: ClassVar[tuple[str, ...]] = ()
    config_properties: ClassVar[dict[str, dict[str, object]]] = {}
    required_fields: ClassVar[tuple[str, ...]] = ()

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            name=cls.display_name,
            description=cls.description,
            icon=cls.icon,
            config_schema={
                "type": "object",
                "properties": dict(cls.config_properties),
                "required": list(cls.required_fields),
                "additionalProperties": False,
            },
            supported_asset_types=list(cls.supported_asset_types),
        )

    def _missing_required(self) -> list[str]:
        return [f for f in self.required_fields if not self.config.get(f)]

    async def test_connection(self) -> ConnectionStatus:
        """Never raises. Reports missing config first, then — once config is
        complete — that live discovery is not yet wired for this provider."""
        missing = self._missing_required()
        if missing:
            return ConnectionStatus(
                connected=False,
                message=(f"Missing required configuration: {', '.join(missing)}."),
            )
        return ConnectionStatus(
            connected=False,
            message=(
                f"{self.display_name} configuration is complete, but live "
                "discovery for this connector is not yet implemented "
                "(pending the cloud-SDK transport). Registration is supported; "
                "crawling is not."
            ),
        )

    async def discover(self) -> list[DiscoveredAsset]:
        raise ConnectorNotImplementedError(
            f"{self.display_name} live discovery is not yet implemented. "
            "This connector exposes a real registration interface; the cloud "
            "crawl transport is pending."
        )

    async def sync(self, since: datetime) -> list[DiscoveredAsset]:
        raise ConnectorNotImplementedError(
            f"{self.display_name} incremental sync is not yet implemented."
        )


class AwsSageMakerConnector(CloudStubConnector):
    display_name = "AWS SageMaker"
    description = (
        "Discover SageMaker model packages, endpoints, and inference " "components across a region."
    )
    icon = "🟧"
    supported_asset_types = ("model", "endpoint", "pipeline")
    required_fields = ("region",)
    config_properties: ClassVar[dict[str, dict[str, object]]] = {
        "region": _str_field("AWS region, e.g. us-east-1"),
        "role_arn": _str_field(
            "IAM role ARN to assume for read-only discovery (preferred over " "static keys)."
        ),
        "access_key_id": _str_field("AWS access key id (if not using a role)."),
        "secret_access_key": _str_field("AWS secret access key.", secret=True),
    }


class AwsBedrockConnector(CloudStubConnector):
    display_name = "AWS Bedrock"
    description = (
        "Discover Bedrock foundation models, custom models, and provisioned "
        "throughput in a region."
    )
    icon = "🟫"
    supported_asset_types = ("model",)
    required_fields = ("region",)
    config_properties: ClassVar[dict[str, dict[str, object]]] = {
        "region": _str_field("AWS region, e.g. us-east-1"),
        "role_arn": _str_field("IAM role ARN to assume for read-only access."),
    }


class AzureMlConnector(CloudStubConnector):
    display_name = "Azure Machine Learning"
    description = (
        "Discover registered models, online/batch endpoints, and pipelines in "
        "an Azure ML workspace."
    )
    icon = "🟦"
    supported_asset_types = ("model", "endpoint", "pipeline")
    required_fields = ("subscription_id", "resource_group", "workspace_name")
    config_properties: ClassVar[dict[str, dict[str, object]]] = {
        "subscription_id": _str_field("Azure subscription id (GUID)."),
        "resource_group": _str_field("Resource group containing the workspace."),
        "workspace_name": _str_field("Azure ML workspace name."),
        "tenant_id": _str_field("Entra tenant id for the service principal."),
        "client_id": _str_field("Service principal application (client) id."),
        "client_secret": _str_field("Service principal client secret.", secret=True),
    }


class GcpVertexConnector(CloudStubConnector):
    display_name = "GCP Vertex AI"
    description = (
        "Discover Vertex AI models, endpoints, and pipelines in a project and " "location."
    )
    icon = "🟥"
    supported_asset_types = ("model", "endpoint", "pipeline")
    required_fields = ("project_id", "location")
    config_properties: ClassVar[dict[str, dict[str, object]]] = {
        "project_id": _str_field("GCP project id."),
        "location": _str_field("Vertex AI region, e.g. us-central1."),
        "service_account_json": _str_field(
            "Service-account key JSON for read-only discovery.", secret=True
        ),
    }


class HuggingFaceConnector(CloudStubConnector):
    display_name = "Hugging Face"
    description = (
        "Discover models and datasets owned by an organization on the Hugging " "Face Hub."
    )
    icon = "🤗"
    supported_asset_types = ("model", "dataset")
    required_fields = ("token",)
    config_properties: ClassVar[dict[str, dict[str, object]]] = {
        "token": _str_field("Hugging Face access token (read scope).", secret=True),
        "organization": _str_field("Organization or namespace to scope discovery to (optional)."),
    }


# The bundled cloud stubs, keyed by their registry type string.
CLOUD_STUB_CONNECTORS: dict[str, type[CloudStubConnector]] = {
    "aws_sagemaker": AwsSageMakerConnector,
    "aws_bedrock": AwsBedrockConnector,
    "azure_ml": AzureMlConnector,
    "gcp_vertex": GcpVertexConnector,
    "huggingface": HuggingFaceConnector,
}
