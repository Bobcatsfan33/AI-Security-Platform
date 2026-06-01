"""Wire serialization for streamed runtime events.

A streamed event is the same JSON-safe dict shape the ClickHouse row uses
(column name → value), so a consumer can feed the poset graph builder
(``app.anomaly.attack_graph``) without translation. UUIDs and datetimes are
rendered as strings; the consumer keeps them as strings (the graph builder
normalises ids via ``_norm`` and never parses timestamps).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from app.telemetry.runtime_event import RUNTIME_EVENTS_COLUMNS, RuntimeEvent


def _jsonify(value: Any) -> Any:
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def event_to_wire(event: RuntimeEvent) -> dict[str, Any]:
    """RuntimeEvent → JSON-safe dict keyed by column name."""
    row = dict(zip(RUNTIME_EVENTS_COLUMNS, event.to_row()))
    return {k: _jsonify(v) for k, v in row.items()}


def encode(event: RuntimeEvent) -> bytes:
    """RuntimeEvent → UTF-8 JSON bytes for the broker."""
    return json.dumps(event_to_wire(event), separators=(",", ":")).encode("utf-8")


def decode(payload: bytes) -> dict[str, Any]:
    """Broker bytes → wire dict. Raises ValueError on malformed payloads."""
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"undecodable event payload: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("event payload is not a JSON object")
    return data


def partition_key(event: RuntimeEvent) -> bytes:
    """Partition by correlation_key so a whole causal flow lands on one
    partition — the cross-agent correlation EPA (Phase C) can then consume an
    entire flow in order from a single partition. Falls back to session/asset.
    """
    key = event.correlation_key or event.session_id or str(event.asset_id)
    return key.encode("utf-8")
