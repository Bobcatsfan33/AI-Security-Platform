"""Connector type registry.

Connectors register themselves by string key (``"aws_sagemaker"``,
``"openai"``, ``"mock"``, …). The sync service resolves the
``connector_type`` column on the ``connectors`` table to a concrete
class through :func:`get`.

Registration is module-level — see ``app/connectors/discovery/__init__.py``
for the bundled registrations. Third parties extend by calling
:func:`register` at import time.
"""

from __future__ import annotations

import logging
from typing import Type

from app.connectors.discovery.base import BaseConnector, ConnectorMetadata

logger = logging.getLogger("platform.connectors.registry")


_REGISTRY: dict[str, Type[BaseConnector]] = {}


class UnknownConnectorTypeError(KeyError):
    """Raised when a connector_type isn't registered."""


def register(connector_type: str, connector_class: Type[BaseConnector]) -> None:
    """Register a connector class for a given type key.

    Re-registering the same key replaces the previous class — useful
    for tests, but logged so accidental overrides are visible.
    """
    if not connector_type:
        raise ValueError("connector_type must be a non-empty string")
    if not issubclass(connector_class, BaseConnector):
        raise TypeError(
            f"{connector_class!r} does not subclass BaseConnector"
        )
    if connector_type in _REGISTRY:
        logger.warning(
            "connector_registry_overwrite",
            extra={"connector_type": connector_type},
        )
    _REGISTRY[connector_type] = connector_class


def get(connector_type: str) -> Type[BaseConnector]:
    try:
        return _REGISTRY[connector_type]
    except KeyError as exc:
        raise UnknownConnectorTypeError(connector_type) from exc


def list_available() -> list[ConnectorMetadata]:
    """Catalog payload used by the UI's connector picker."""
    out: list[ConnectorMetadata] = []
    for cls in _REGISTRY.values():
        try:
            out.append(cls.get_metadata())
        except Exception as exc:  # noqa: BLE001 — metadata is best-effort
            logger.warning(
                "connector_metadata_failed",
                extra={"class": cls.__name__, "error": str(exc)},
            )
    return out


def reset_for_tests() -> None:
    """Clear the registry. Tests that re-register can call this in setup."""
    _REGISTRY.clear()
