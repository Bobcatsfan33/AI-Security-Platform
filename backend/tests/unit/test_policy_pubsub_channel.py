"""Verify the policy pub/sub channel naming convention is stable.

The runtime agent depends on this exact format — changing the channel name
breaks every deployed agent. This test exists to make any change deliberate.
"""

from __future__ import annotations

import uuid

import pytest

from app.services.policy_pubsub import channel_name


@pytest.mark.unit
class TestPolicyPubsubChannel:
    def test_channel_format(self) -> None:
        org_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
        assert channel_name(org_id) == "policy:invalidation:00000000-0000-0000-0000-000000000001"

    def test_channels_differ_per_org(self) -> None:
        a = uuid.uuid4()
        b = uuid.uuid4()
        assert channel_name(a) != channel_name(b)
