"""Build a :class:`ModelConnector` from a persisted ``ConnectorConfig`` row.

This revives ``app.connectors.registry.build_connector`` — the v1 factory the
v2.0 pivot dropped along with the ``connector_configs`` table. Red Teaming
already reintroduced the concrete builder as
:func:`app.redteam.model_connectors.build_model_connector`, which drives a model
from an inline :class:`ConnectorSpec`. Now that the governance revival brings
the ``connector_configs`` table (and :class:`app.db.models.connector_config.ConnectorConfig`)
back, the evaluation runner once again resolves a *persisted* connector row and
needs the ORM-row → connector factory.

A ``ConnectorConfig`` row maps one-to-one onto a ``ConnectorSpec`` (provider,
model, api_key_ref, config), so this is a thin, DRY adapter: no connector logic
is duplicated — it delegates to the single canonical builder.
"""

from __future__ import annotations

from app.connectors.base import ModelConnector
from app.db.models.connector_config import ConnectorConfig
from app.redteam.model_connectors import ConnectorSpec, build_model_connector


def build_connector(config: ConnectorConfig) -> ModelConnector:
    """Build a concrete :class:`ModelConnector` from a persisted connector row.

    Raises :class:`app.connectors.base.ConnectorConfigError` for an unsupported
    provider or a provider missing a required extra (delegated to
    :func:`app.redteam.model_connectors.build_model_connector`).
    """
    spec = ConnectorSpec(
        provider=config.provider,
        model=config.model,
        api_key_ref=config.api_key_ref or "",
        config=dict(config.config or {}),
    )
    return build_model_connector(spec)
