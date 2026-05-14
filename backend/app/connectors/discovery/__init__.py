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
from app.connectors.discovery.mock_connector import MockConnector
from app.connectors.discovery.registry import (
    UnknownConnectorTypeError,
    get,
    list_available,
    register,
)

# Eager-register the bundled connectors so the registry is populated at import.
register("mock", MockConnector)

__all__ = [
    "BaseConnector",
    "ConnectionStatus",
    "ConnectorMetadata",
    "DiscoveredAsset",
    "MockConnector",
    "UnknownConnectorTypeError",
    "get",
    "list_available",
    "register",
]
