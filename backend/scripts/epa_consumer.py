"""EPA consumer service entrypoint.

Runs the long-lived detection service: consumes the Redpanda runtime-event
stream, drives the EPA fleet + cross-agent correlation, and persists Tier-3
narratives for the analyst workbench.

    python -m scripts.epa_consumer

Requires ``streaming_enabled`` infrastructure (Redpanda + Redis). In a
container deployment this is its own Deployment, scaled by partition count;
see deploy/ and docs/HA-DR-RUNBOOK.md.
"""

from __future__ import annotations

import asyncio
import logging

from app.epa.service import build_default

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("epa_consumer")


async def main() -> None:
    service = await build_default()
    log.info("epa_consumer_starting")
    await service.run()


if __name__ == "__main__":
    asyncio.run(main())
