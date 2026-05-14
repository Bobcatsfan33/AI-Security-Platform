"""Abstract discovery connector interface.

A discovery connector takes a credential blob, talks to an external
system, and emits a stream of :class:`DiscoveredAsset` records the sync
service folds into the ``ai_assets`` graph.

Two reads:
  - :meth:`discover` — full crawl on first run / re-sync
  - :meth:`sync` — incremental, only assets changed since ``since``

Concrete connectors must also implement :meth:`test_connection` (used
by the test-connection admin route) and the class-method
:meth:`get_metadata` (used by ``/v1/connectors/available`` to render
the registration UI).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class DiscoveredAsset(BaseModel):
    """The wire shape a connector emits per asset.

    ``external_id`` is the connector-scoped primary key in the source
    system. The sync service uses ``(connector_id, external_id)`` as
    the dedupe key when folding into ``ai_assets``.
    """

    model_config = ConfigDict(extra="forbid")

    external_id: str = Field(min_length=1, max_length=512)
    name: str = Field(min_length=1, max_length=512)
    asset_type: str = Field(description="model | endpoint | dataset | pipeline | agent | tool")
    provider: str = Field(min_length=1, max_length=128)
    description: Optional[str] = None
    version: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ConnectionStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connected: bool
    message: str
    latency_ms: Optional[float] = None


class ConnectorMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    icon: str
    config_schema: dict[str, Any]
    supported_asset_types: list[str]


class BaseConnector(ABC):
    """Abstract base. Subclasses MUST implement every method below."""

    def __init__(self, config: dict[str, Any]):
        self.config = config

    @abstractmethod
    async def discover(self) -> list[DiscoveredAsset]:
        """Full crawl. Returns every asset visible with this credential."""

    @abstractmethod
    async def sync(self, since: datetime) -> list[DiscoveredAsset]:
        """Incremental sync. Returns assets modified since ``since``."""

    @abstractmethod
    async def test_connection(self) -> ConnectionStatus:
        """Validate credentials + connectivity. Must not raise."""

    @classmethod
    @abstractmethod
    def get_metadata(cls) -> ConnectorMetadata:
        """Return metadata for catalog rendering and config validation."""
