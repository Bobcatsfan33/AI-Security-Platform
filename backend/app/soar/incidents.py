"""SOAR / incident-management adapters.

Three backends ship: PagerDuty, Opsgenie, and a generic webhook. Each
takes a normalised :class:`Incident` and POSTs it to the backend in the
expected shape. Adapters are constructed via :func:`build_adapters` from
``Organization.settings.soar_adapters``.

The backend that owns this code path is fail-open: a webhook outage
must never block a finding write — it logs and moves on.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, runtime_checkable

import httpx

logger = logging.getLogger("platform.soar")


Severity = Literal["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Incident:
    org_id: str
    title: str
    severity: Severity
    description: str
    source: str          # "evaluation" | "runtime_agent" | "anomaly_detector"
    asset_id: str = ""
    correlation_id: str = ""
    detected_at: datetime = datetime.now(timezone.utc)
    detail: dict[str, Any] = None  # type: ignore[assignment]


@runtime_checkable
class IncidentSink(Protocol):
    name: str
    sink_type: str

    async def open(self, incident: Incident) -> bool: ...


# ─────────────────────────────────────────── PagerDuty


class PagerDutySink:
    """PagerDuty Events API v2 (Common Event Format)."""

    sink_type = "pagerduty"

    def __init__(
        self,
        *,
        name: str,
        routing_key: str,
        client_url: str = "",
        timeout_s: float = 10.0,
    ) -> None:
        self.name = name
        self._routing_key = routing_key
        self._client_url = client_url
        self._timeout_s = timeout_s

    async def open(self, incident: Incident) -> bool:
        body = {
            "routing_key": self._routing_key,
            "event_action": "trigger",
            "dedup_key": incident.correlation_id or incident.title,
            "client": "ai-security-platform",
            "client_url": self._client_url,
            "payload": {
                "summary": incident.title,
                "severity": _pd_severity(incident.severity),
                "source": incident.source,
                "component": incident.asset_id or "unknown",
                "group": "ai-security",
                "class": incident.source,
                "custom_details": {
                    "org_id": incident.org_id,
                    "detected_at": incident.detected_at.isoformat(),
                    "description": incident.description,
                    **(incident.detail or {}),
                },
            },
        }
        return await _post(
            "https://events.pagerduty.com/v2/enqueue",
            body=body,
            headers={"Content-Type": "application/json"},
            timeout_s=self._timeout_s,
            log_name="pagerduty",
        )


def _pd_severity(s: Severity) -> str:
    return {
        "info": "info",
        "low": "warning",
        "medium": "warning",
        "high": "error",
        "critical": "critical",
    }[s]


# ─────────────────────────────────────────── Opsgenie


class OpsgenieSink:
    """Opsgenie alerting via the Alert API."""

    sink_type = "opsgenie"

    def __init__(
        self,
        *,
        name: str,
        api_key: str,
        team: str | None = None,
        region: Literal["us", "eu"] = "us",
        timeout_s: float = 10.0,
    ) -> None:
        self.name = name
        self._api_key = api_key
        self._team = team
        self._url = (
            "https://api.opsgenie.com/v2/alerts"
            if region == "us"
            else "https://api.eu.opsgenie.com/v2/alerts"
        )
        self._timeout_s = timeout_s

    async def open(self, incident: Incident) -> bool:
        body: dict[str, Any] = {
            "message": incident.title,
            "alias": incident.correlation_id or incident.title,
            "description": incident.description,
            "priority": _og_priority(incident.severity),
            "source": incident.source,
            "tags": [incident.source, incident.severity, "ai-security"],
            "entity": incident.asset_id or "ai-security-platform",
            "details": {
                "org_id": incident.org_id,
                "detected_at": incident.detected_at.isoformat(),
                **(incident.detail or {}),
            },
        }
        if self._team:
            body["responders"] = [{"type": "team", "name": self._team}]
        return await _post(
            self._url,
            body=body,
            headers={
                "Authorization": f"GenieKey {self._api_key}",
                "Content-Type": "application/json",
            },
            timeout_s=self._timeout_s,
            log_name="opsgenie",
        )


def _og_priority(s: Severity) -> str:
    return {
        "info": "P5", "low": "P4", "medium": "P3", "high": "P2", "critical": "P1",
    }[s]


# ─────────────────────────────────────────── Generic webhook


class WebhookSink:
    """Plain HTTP POST. Sends a JSON envelope that downstream systems
    can transform into their own incident shape."""

    sink_type = "webhook"

    def __init__(
        self,
        *,
        name: str,
        url: str,
        headers: dict[str, str] | None = None,
        timeout_s: float = 10.0,
    ) -> None:
        self.name = name
        self._url = url
        self._headers = headers or {}
        self._timeout_s = timeout_s

    async def open(self, incident: Incident) -> bool:
        body = {
            "title": incident.title,
            "severity": incident.severity,
            "description": incident.description,
            "source": incident.source,
            "org_id": incident.org_id,
            "asset_id": incident.asset_id,
            "correlation_id": incident.correlation_id,
            "detected_at": incident.detected_at.isoformat(),
            "detail": incident.detail or {},
        }
        return await _post(
            self._url,
            body=body,
            headers={**self._headers, "Content-Type": "application/json"},
            timeout_s=self._timeout_s,
            log_name="soar_webhook",
        )


# ─────────────────────────────────────────── HTTP helper


async def _post(
    url: str,
    *,
    body: dict[str, Any],
    headers: dict[str, str],
    timeout_s: float,
    log_name: str,
) -> bool:
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as c:
            resp = await c.post(
                url, content=json.dumps(body, default=str), headers=headers
            )
        if resp.status_code >= 400:
            logger.warning(
                "soar_non_2xx",
                extra={"sink": log_name, "status": resp.status_code},
            )
            return False
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("soar_failed", extra={"sink": log_name, "error": str(exc)})
        return False


# ─────────────────────────────────────────── factory


def build_adapters(configs: list[dict[str, Any]]) -> list[IncidentSink]:
    out: list[IncidentSink] = []
    for entry in configs:
        if not isinstance(entry, dict):
            continue
        adapter = _build_one(entry)
        if adapter is not None:
            out.append(adapter)
    return out


def _build_one(entry: dict[str, Any]) -> IncidentSink | None:
    sink_type = entry.get("type")
    name = entry.get("name") or sink_type or "soar"
    cfg = entry.get("config") or {}
    try:
        if sink_type == "pagerduty":
            return PagerDutySink(name=name, **cfg)
        if sink_type == "opsgenie":
            return OpsgenieSink(name=name, **cfg)
        if sink_type == "webhook":
            return WebhookSink(name=name, **cfg)
    except TypeError as exc:
        logger.warning(
            "soar_config_invalid",
            extra={"sink_type": sink_type, "sink_name": name, "error": str(exc)},
        )
        return None
    logger.warning("soar_unknown_sink_type", extra={"sink_type": sink_type})
    return None


async def open_in_all(
    sinks: list[IncidentSink], incident: Incident
) -> dict[str, bool]:
    out: dict[str, bool] = {}
    for sink in sinks:
        try:
            out[sink.name] = await sink.open(incident)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "soar_sink_crashed",
                extra={"sink_name": sink.name, "error": str(exc)},
            )
            out[sink.name] = False
    return out
