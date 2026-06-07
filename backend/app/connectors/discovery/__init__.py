"""v2 discovery connectors — the ingest plane for the asset graph.

Each concrete connector implements :class:`BaseConnector` and is
registered with :func:`register`. The sync service resolves the
``connector_type`` string on a :class:`~app.db.models.connector.Connector`
row to a concrete class via :func:`get`.
"""

from app.connectors.discovery.base import (
    BaseConnector,
    ConnectionStatus,
    ConnectorMetadata,
    DiscoveredAsset,
)
from app.connectors.discovery.cloud_stubs import (
    CLOUD_STUB_CONNECTORS,
    ConnectorNotImplementedError,
)
from app.connectors.discovery.mock_connector import MockConnector
from app.connectors.discovery.registry import (
    UnknownConnectorTypeError,
    get,
    list_available,
    register,
)

# Eager-register the bundled connectors so the registry is populated at import.
register("mock", MockConnector)
# Cloud discovery stubs — real registration interface + metadata; the live
# crawl transport is Phase 5 (needs cloud accounts). See cloud_stubs.py.
for _type, _cls in CLOUD_STUB_CONNECTORS.items():
    register(_type, _cls)

__all__ = [
    "BaseConnector",
    "ConnectionStatus",
    "ConnectorMetadata",
    "ConnectorNotImplementedError",
    "DiscoveredAsset",
    "MockConnector",
    "UnknownConnectorTypeError",
    "get",
    "list_available",
    "register",
]
