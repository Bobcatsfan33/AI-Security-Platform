"""Policy invalidation pub/sub channel.

Channel naming: `policy:invalidation:{org_id}`. The runtime agent (Sprint 7)
subscribes to its org's channel on startup and refreshes its in-memory cache
on every published message. The control plane publishes on every policy
write — see app/api/v1/policies.py.

The published message is a JSON object:
    {"policy_id": "<uuid>", "version": <int>, "event": "create|update|delete"}
"""

from __future__ import annotations

import json
import uuid
from typing import Literal

from app.services.redis_client import get_redis

PolicyEvent = Literal["create", "update", "delete"]


def channel_name(org_id: uuid.UUID) -> str:
    return f"policy:invalidation:{org_id}"


async def publish_policy_change(
    *,
    org_id: uuid.UUID,
    policy_id: uuid.UUID,
    version: int,
    event: PolicyEvent,
) -> None:
    redis = await get_redis()
    payload = json.dumps(
        {
            "policy_id": str(policy_id),
            "version": version,
            "event": event,
        },
        separators=(",", ":"),
    )
    await redis.publish(channel_name(org_id), payload)
