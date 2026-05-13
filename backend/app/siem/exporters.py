"""SIEM exporters — Splunk, Elastic, Sentinel, Datadog, Chronicle, generic.

Each exporter implements the :class:`SiemExporter` Protocol. Adapters
take batches of platform events (findings, audit log entries, runtime
telemetry events) and POST them to the configured SIEM in the SIEM's
expected shape.

Configuration lives on the Organization (settings.siem_exporters JSONB
list of {type, name, config}). The :func:`build_exporters_for_org`
function reads that config and instantiates the right adapters.

All adapters fail open — a SIEM forwarding failure must NEVER break a
platform operation. Failures are logged and counted; downstream code
treats SIEM as best-effort.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, runtime_checkable

import httpx

logger = logging.getLogger("platform.siem")


ExporterType = Literal[
    "splunk_hec",
    "elastic",
    "sentinel",
    "datadog",
    "chronicle",
    "webhook",
]


@dataclass(frozen=True)
class SiemEvent:
    """Provider-agnostic event shape. Each exporter translates this to
    its own schema (CIM for Splunk, ECS for Elastic, UDM for Chronicle).
    """

    timestamp: datetime
    org_id: str
    event_type: str            # "finding" | "audit" | "runtime_event"
    severity: str
    source: str                # "evaluation" | "runtime_agent" | "red_team"
    title: str
    detail: dict[str, Any]
    asset_id: str = ""
    correlation_id: str = ""


@runtime_checkable
class SiemExporter(Protocol):
    """Every backend implements this."""

    name: str
    exporter_type: ExporterType

    async def export(self, events: list[SiemEvent]) -> int:
        """Send a batch of events. Returns the number successfully
        accepted by the SIEM. Never raises — failures are logged."""
        ...


# ─────────────────────────────────────────── Splunk HEC


class SplunkHECExporter:
    """Splunk HTTP Event Collector — JSON-per-line POST."""

    exporter_type = "splunk_hec"

    def __init__(
        self,
        *,
        name: str,
        url: str,
        token: str,
        index: str = "main",
        sourcetype: str = "ai_security",
        timeout_s: float = 10.0,
    ) -> None:
        self.name = name
        self._url = url.rstrip("/") + "/services/collector/event"
        self._token = token
        self._index = index
        self._sourcetype = sourcetype
        self._timeout_s = timeout_s

    async def export(self, events: list[SiemEvent]) -> int:
        if not events:
            return 0
        # Splunk HEC accepts one JSON object per request OR a
        # newline-concatenated stream of objects in a single body.
        body = "".join(
            json.dumps(
                {
                    "time": e.timestamp.timestamp(),
                    "host": "ai-security-platform",
                    "source": e.source,
                    "sourcetype": self._sourcetype,
                    "index": self._index,
                    "event": _to_cim_lite(e),
                }
            )
            for e in events
        )
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as c:
                resp = await c.post(
                    self._url,
                    content=body,
                    headers={
                        "Authorization": f"Splunk {self._token}",
                        "Content-Type": "application/json",
                    },
                )
            if resp.status_code >= 400:
                logger.warning(
                    "siem_splunk_non_2xx",
                    extra={"status": resp.status_code, "body": resp.text[:200]},
                )
                return 0
        except Exception as exc:  # noqa: BLE001
            logger.warning("siem_splunk_failed", extra={"error": str(exc)})
            return 0
        return len(events)


def _to_cim_lite(e: SiemEvent) -> dict[str, Any]:
    """Loose CIM mapping. Real CIM has hundreds of fields; this hits the
    ones Splunk dashboards typically need."""
    return {
        "event_type": e.event_type,
        "severity": e.severity,
        "title": e.title,
        "src": "ai-security-platform",
        "src_user_id": e.org_id,
        "object": e.asset_id,
        "correlation_id": e.correlation_id,
        **e.detail,
    }


# ─────────────────────────────────────────── Elastic (REST bulk API)


class ElasticExporter:
    """Elastic / OpenSearch bulk-ingest. POST /_bulk with one
    ``{action}\\n{doc}\\n`` pair per event in ECS shape."""

    exporter_type = "elastic"

    def __init__(
        self,
        *,
        name: str,
        url: str,
        index: str,
        api_key: str | None = None,
        basic_auth: tuple[str, str] | None = None,
        timeout_s: float = 10.0,
    ) -> None:
        self.name = name
        self._url = url.rstrip("/") + "/_bulk"
        self._index = index
        self._api_key = api_key
        self._basic_auth = basic_auth
        self._timeout_s = timeout_s

    async def export(self, events: list[SiemEvent]) -> int:
        if not events:
            return 0
        lines: list[str] = []
        for e in events:
            lines.append(json.dumps({"index": {"_index": self._index}}))
            lines.append(json.dumps(_to_ecs(e)))
        body = "\n".join(lines) + "\n"

        headers = {"Content-Type": "application/x-ndjson"}
        if self._api_key:
            headers["Authorization"] = f"ApiKey {self._api_key}"
        auth = self._basic_auth

        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as c:
                resp = await c.post(self._url, content=body, headers=headers, auth=auth)
            if resp.status_code >= 400:
                logger.warning(
                    "siem_elastic_non_2xx",
                    extra={"status": resp.status_code, "body": resp.text[:200]},
                )
                return 0
            data = resp.json()
            if data.get("errors"):
                logger.warning("siem_elastic_bulk_errors")
        except Exception as exc:  # noqa: BLE001
            logger.warning("siem_elastic_failed", extra={"error": str(exc)})
            return 0
        return len(events)


def _to_ecs(e: SiemEvent) -> dict[str, Any]:
    """Translate to Elastic Common Schema (ECS) subset."""
    return {
        "@timestamp": e.timestamp.isoformat(),
        "event": {
            "category": "intrusion_detection",
            "kind": "alert",
            "severity": e.severity,
            "type": e.event_type,
            "action": e.source,
        },
        "organization": {"id": e.org_id},
        "message": e.title,
        "rule": {
            "ruleset": "ai-security-platform",
            "name": e.title,
        },
        "labels": {
            "asset_id": e.asset_id,
            "correlation_id": e.correlation_id,
        },
        "platform": e.detail,
    }


# ─────────────────────────────────────────── Microsoft Sentinel (HTTP Data Collector)


class SentinelExporter:
    """Sentinel via the legacy HTTP Data Collector API. Newer Sentinel
    deployments use Data Collection Endpoints + Rules — that's a Sprint
    11 follow-on if customers ask. The HTTP Data Collector still works
    for years yet and is the simplest path to first integration.
    """

    exporter_type = "sentinel"

    def __init__(
        self,
        *,
        name: str,
        workspace_id: str,
        shared_key: str,  # Sentinel primary/secondary shared key (base64)
        log_type: str = "AiSecurity",
        timeout_s: float = 10.0,
    ) -> None:
        self.name = name
        self._workspace_id = workspace_id
        self._shared_key = shared_key
        self._log_type = log_type
        self._timeout_s = timeout_s

    async def export(self, events: list[SiemEvent]) -> int:
        if not events:
            return 0
        body = json.dumps(
            [_to_sentinel(e) for e in events], default=str
        )
        url = (
            f"https://{self._workspace_id}.ods.opinsights.azure.com"
            "/api/logs?api-version=2016-04-01"
        )
        date_str = datetime.now(timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        signature = _sentinel_signature(
            workspace_id=self._workspace_id,
            shared_key=self._shared_key,
            date_str=date_str,
            content_length=len(body.encode("utf-8")),
        )
        headers = {
            "Content-Type": "application/json",
            "Log-Type": self._log_type,
            "x-ms-date": date_str,
            "Authorization": signature,
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as c:
                resp = await c.post(url, content=body, headers=headers)
            if resp.status_code >= 400:
                logger.warning(
                    "siem_sentinel_non_2xx",
                    extra={"status": resp.status_code},
                )
                return 0
        except Exception as exc:  # noqa: BLE001
            logger.warning("siem_sentinel_failed", extra={"error": str(exc)})
            return 0
        return len(events)


def _to_sentinel(e: SiemEvent) -> dict[str, Any]:
    return {
        "TimeGenerated": e.timestamp.isoformat(),
        "OrgId": e.org_id,
        "EventType": e.event_type,
        "Severity": e.severity,
        "Source": e.source,
        "Title": e.title,
        "AssetId": e.asset_id,
        "CorrelationId": e.correlation_id,
        "Detail": json.dumps(e.detail, default=str),
    }


def _sentinel_signature(
    *, workspace_id: str, shared_key: str, date_str: str, content_length: int
) -> str:
    """HMAC-SHA256 signature per the legacy Data Collector spec."""
    import base64
    import hashlib
    import hmac

    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    string_to_hash = (
        f"{method}\n{content_length}\n{content_type}\n"
        f"x-ms-date:{date_str}\n{resource}"
    )
    decoded_key = base64.b64decode(shared_key)
    h = hmac.new(decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256)
    encoded_hash = base64.b64encode(h.digest()).decode()
    return f"SharedKey {workspace_id}:{encoded_hash}"


# ─────────────────────────────────────────── Datadog Logs API


class DatadogExporter:
    """Datadog Logs API — one POST per batch, JSON array body."""

    exporter_type = "datadog"

    def __init__(
        self,
        *,
        name: str,
        api_key: str,
        site: str = "datadoghq.com",   # alt: "datadoghq.eu" / "us3.datadoghq.com"
        service: str = "ai-security-platform",
        timeout_s: float = 10.0,
    ) -> None:
        self.name = name
        self._url = f"https://http-intake.logs.{site}/api/v2/logs"
        self._api_key = api_key
        self._service = service
        self._timeout_s = timeout_s

    async def export(self, events: list[SiemEvent]) -> int:
        if not events:
            return 0
        body = json.dumps(
            [
                {
                    "ddsource": "ai-security-platform",
                    "ddtags": f"event_type:{e.event_type},severity:{e.severity}",
                    "hostname": "ai-security-platform",
                    "service": self._service,
                    "message": e.title,
                    "timestamp": int(e.timestamp.timestamp() * 1000),
                    "attributes": {
                        "org_id": e.org_id,
                        "asset_id": e.asset_id,
                        "correlation_id": e.correlation_id,
                        "source": e.source,
                        "severity": e.severity,
                        **e.detail,
                    },
                }
                for e in events
            ],
            default=str,
        )
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as c:
                resp = await c.post(
                    self._url,
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "DD-API-KEY": self._api_key,
                    },
                )
            if resp.status_code >= 400:
                logger.warning(
                    "siem_datadog_non_2xx",
                    extra={"status": resp.status_code},
                )
                return 0
        except Exception as exc:  # noqa: BLE001
            logger.warning("siem_datadog_failed", extra={"error": str(exc)})
            return 0
        return len(events)


# ─────────────────────────────────────────── Chronicle (Google SecOps UDM)


class ChronicleExporter:
    """Chronicle UDM ingestion via the Ingestion API."""

    exporter_type = "chronicle"

    def __init__(
        self,
        *,
        name: str,
        customer_id: str,
        region: str = "us",
        bearer_token: str,
        timeout_s: float = 10.0,
    ) -> None:
        self.name = name
        self._url = (
            f"https://{region}-chronicle.googleapis.com/v1alpha/"
            f"projects/{customer_id}/locations/{region}/instances/{customer_id}/"
            "events:import"
        )
        self._bearer = bearer_token
        self._timeout_s = timeout_s

    async def export(self, events: list[SiemEvent]) -> int:
        if not events:
            return 0
        body = json.dumps(
            {"events": [_to_udm(e) for e in events]}, default=str
        )
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as c:
                resp = await c.post(
                    self._url,
                    content=body,
                    headers={
                        "Authorization": f"Bearer {self._bearer}",
                        "Content-Type": "application/json",
                    },
                )
            if resp.status_code >= 400:
                logger.warning(
                    "siem_chronicle_non_2xx",
                    extra={"status": resp.status_code},
                )
                return 0
        except Exception as exc:  # noqa: BLE001
            logger.warning("siem_chronicle_failed", extra={"error": str(exc)})
            return 0
        return len(events)


def _to_udm(e: SiemEvent) -> dict[str, Any]:
    """Minimal UDM mapping. Chronicle expects deeply-structured events;
    this is the smallest valid shape for an alert/observation."""
    return {
        "metadata": {
            "event_timestamp": e.timestamp.isoformat(),
            "event_type": "USER_RESOURCE_ACCESS",
            "product_name": "ai-security-platform",
            "vendor_name": "Bobcatsfan33",
            "description": e.title,
        },
        "principal": {"user": {"userid": e.org_id}},
        "target": {"asset": {"asset_id": e.asset_id}},
        "security_result": [
            {
                "summary": e.title,
                "severity": e.severity.upper(),
                "category_details": [e.event_type],
            }
        ],
        "additional": {"correlation_id": e.correlation_id, **e.detail},
    }


# ─────────────────────────────────────────── Generic webhook


class WebhookExporter:
    """Plain HTTP POST. The lowest-common-denominator backend — works
    against any HTTPS endpoint that accepts JSON."""

    exporter_type = "webhook"

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

    async def export(self, events: list[SiemEvent]) -> int:
        if not events:
            return 0
        body = json.dumps(
            {"events": [_to_generic(e) for e in events]}, default=str
        )
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s) as c:
                resp = await c.post(
                    self._url,
                    content=body,
                    headers={**self._headers, "Content-Type": "application/json"},
                )
            if resp.status_code >= 400:
                logger.warning(
                    "siem_webhook_non_2xx",
                    extra={"status": resp.status_code},
                )
                return 0
        except Exception as exc:  # noqa: BLE001
            logger.warning("siem_webhook_failed", extra={"error": str(exc)})
            return 0
        return len(events)


def _to_generic(e: SiemEvent) -> dict[str, Any]:
    return {
        "timestamp": e.timestamp.isoformat(),
        "org_id": e.org_id,
        "event_type": e.event_type,
        "severity": e.severity,
        "source": e.source,
        "title": e.title,
        "asset_id": e.asset_id,
        "correlation_id": e.correlation_id,
        "detail": e.detail,
    }


# ─────────────────────────────────────────── Factory + multi-fanout


def build_exporters(configs: list[dict[str, Any]]) -> list[SiemExporter]:
    """Build a list of exporters from per-org configuration.

    ``configs`` is the shape stored on ``Organization.settings.siem_exporters``::

        [
          {"type": "splunk_hec", "name": "prod", "config": {"url": "...", "token": "..."}},
          {"type": "elastic",    "name": "siem", "config": {"url": "...", "index": "..."}}
        ]
    """
    out: list[SiemExporter] = []
    for entry in configs:
        if not isinstance(entry, dict):
            continue
        exporter = _build_one(entry)
        if exporter is not None:
            out.append(exporter)
    return out


def _build_one(entry: dict[str, Any]) -> SiemExporter | None:
    etype = entry.get("type")
    name = entry.get("name") or etype or "siem"
    config = entry.get("config") or {}
    try:
        if etype == "splunk_hec":
            return SplunkHECExporter(name=name, **config)
        if etype == "elastic":
            return ElasticExporter(name=name, **config)
        if etype == "sentinel":
            return SentinelExporter(name=name, **config)
        if etype == "datadog":
            return DatadogExporter(name=name, **config)
        if etype == "chronicle":
            return ChronicleExporter(name=name, **config)
        if etype == "webhook":
            return WebhookExporter(name=name, **config)
    except TypeError as exc:
        logger.warning(
            "siem_config_invalid",
            extra={"exporter_type": etype, "exporter_name": name, "error": str(exc)},
        )
        return None
    logger.warning("siem_unknown_exporter_type", extra={"type": etype})
    return None


async def export_to_all(
    exporters: list[SiemExporter], events: list[SiemEvent]
) -> dict[str, int]:
    """Send the same events to every configured exporter. Returns a
    {exporter_name: count_accepted} dict — useful for telemetry."""
    if not exporters or not events:
        return {}
    results: dict[str, int] = {}
    for ex in exporters:
        try:
            count = await ex.export(events)
            results[ex.name] = count
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "siem_exporter_crashed",
                extra={"exporter_name": ex.name, "error": str(exc)},
            )
            results[ex.name] = 0
    return results
