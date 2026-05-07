"""Stand-in for the runtime agent's policy subscriber.

Subscribes to a Redis channel for one or more org IDs and prints every policy
invalidation message. Useful for verifying the pub/sub plumbing end-to-end:

    python -m scripts.policy_subscriber <org_id> [<org_id> ...]

In Sprint 7 this loop becomes a goroutine inside the Go runtime agent that
refreshes the local policy cache on each message.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from app.core.config import get_settings
from app.services.policy_pubsub import channel_name
from app.services.redis_client import get_redis

log = logging.getLogger("policy_subscriber")


async def main(org_ids: list[str]) -> None:
    if not org_ids:
        print("usage: python -m scripts.policy_subscriber <org_id> [<org_id> ...]")
        sys.exit(2)

    settings = get_settings()
    log.info("connecting redis_url=%s", settings.redis_url)

    redis = await get_redis()
    pubsub = redis.pubsub()
    channels = [channel_name(org_id) for org_id in org_ids]
    await pubsub.subscribe(*channels)
    log.info("subscribed channels=%s", channels)

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            log.info("policy_invalidation channel=%s data=%s", message["channel"], message["data"])
    finally:
        await pubsub.unsubscribe()
        await pubsub.aclose()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(main(sys.argv[1:]))
