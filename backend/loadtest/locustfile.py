"""Load test scenarios for the AI Security Platform control plane.

Run::

    pip install locust
    locust -f backend/loadtest/locustfile.py \
        --host http://localhost:8000 \
        -u 50 -r 5 --run-time 2m \
        --csv loadtest_results

Targets four representative call paths:

  1. Asset list  (hot read)
  2. Findings list with filters
  3. Telemetry batch ingest (the highest-volume path in prod)
  4. Dashboard summary (heaviest aggregation)

Token + asset_id are read from environment so the script doesn't bake
in tenant data. Override with::

    PLATFORM_TOKEN=<jwt> ASSET_ID=<uuid> ORG_ID=<uuid> locust ...
"""

from __future__ import annotations

import json
import os
import random
import time
import uuid
from datetime import datetime, timezone

from locust import HttpUser, between, task


TOKEN = os.getenv("PLATFORM_TOKEN", "dev-token")
ASSET_ID = os.getenv("ASSET_ID", "00000000-0000-0000-0000-000000000001")
ORG_ID = os.getenv("ORG_ID", "00000000-0000-0000-0000-000000000001")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")  # for telemetry ingest


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DashboardUser(HttpUser):
    """Simulates an analyst clicking around the dashboard."""

    wait_time = between(2.0, 5.0)
    weight = 3

    def on_start(self) -> None:
        self.headers = {"Authorization": f"Bearer {TOKEN}"}

    @task(3)
    def list_assets(self) -> None:
        self.client.get("/v1/assets", headers=self.headers, name="/v1/assets")

    @task(2)
    def list_findings(self) -> None:
        params = {"severity": random.choice(["critical", "high", "medium"])}
        self.client.get(
            "/v1/findings",
            headers=self.headers,
            params=params,
            name="/v1/findings",
        )

    @task(1)
    def dashboard_runtime(self) -> None:
        self.client.get(
            "/v1/dashboards/runtime?time_range=24h",
            headers=self.headers,
            name="/v1/dashboards/runtime",
        )

    @task(1)
    def dashboard_traffic(self) -> None:
        self.client.get(
            "/v1/dashboards/traffic?time_range=24h",
            headers=self.headers,
            name="/v1/dashboards/traffic",
        )

    @task(1)
    def anomalies(self) -> None:
        self.client.get(
            f"/v1/anomalies?asset_id={ASSET_ID}",
            headers=self.headers,
            name="/v1/anomalies",
        )


class RuntimeAgentUser(HttpUser):
    """Simulates a runtime agent posting telemetry batches."""

    wait_time = between(0.5, 2.0)
    weight = 5

    def on_start(self) -> None:
        if not AGENT_API_KEY:
            self.environment.runner.quit()
            return
        self.headers = {"X-API-Key": AGENT_API_KEY}

    @task
    def ingest_batch(self) -> None:
        batch = {
            "events": [
                {
                    "event_id": str(uuid.uuid4()),
                    "org_id": ORG_ID,
                    "asset_id": ASSET_ID,
                    "session_id": f"session-{random.randint(0, 100)}",
                    "timestamp": _now_iso(),
                    "event_type": random.choice(
                        ["request", "response", "tool_call", "block"]
                    ),
                    "direction": random.choice(["inbound", "outbound"]),
                    "enforcement_level": "fast",
                    "pipeline_exit_stage": random.choice(
                        ["stage1_regex", "no_match"]
                    ),
                    "action_taken": random.choice(["allowed", "blocked"]),
                    "risk_score": round(random.random(), 2),
                    "latency_ms": random.randint(30, 800),
                }
                for _ in range(random.randint(10, 50))
            ]
        }
        self.client.post(
            "/v1/runtime/events",
            headers=self.headers,
            json=batch,
            name="/v1/runtime/events",
        )

    # ── RAPIDE detection-stack endpoints (Sprint 14 scale-test scaffolding) ──
    # NOTE: scaffolding. Meaningful numbers require a populated narrative store
    # and a running EPA consumer fleet under load — wire those before trusting
    # throughput figures here.
    @task(2)
    def list_narratives(self) -> None:
        self.client.get(
            "/v1/narratives?status=open",
            headers=self.headers,
            name="/v1/narratives",
        )

    @task(1)
    def efficacy(self) -> None:
        self.client.get(
            "/v1/validation/efficacy",
            headers=self.headers,
            name="/v1/validation/efficacy",
        )
