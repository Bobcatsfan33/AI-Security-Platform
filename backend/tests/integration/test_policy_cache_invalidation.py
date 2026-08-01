"""Policy cache: invalidation, hot reload, and the failure modes around them.

The compiled-policy cache is the control plane's copy of what the runtime
agent enforces. If it serves a stale snapshot, the platform enforces a policy
the operator already retired — and nothing else in the suite would notice,
because every other caller reads through this cache and would agree with it.

So these tests drive the real path: a real Postgres row, a real Redis
pub/sub round trip through ``publish_policy_change``, and the real
subscriber loop. What they pin:

  * an ``update`` message reloads from the database, so a changed row is
    visible to the next ``get()``;
  * a ``delete`` message evicts, so a retired policy stops being enforced;
  * a row deleted out from under a ``create``/``update`` evicts rather than
    leaving the previous snapshot resident (fail-closed on the cache, not
    "keep whatever we had");
  * malformed, unknown-field, and non-JSON payloads are dropped without
    disturbing resident entries or killing the subscriber — an attacker or a
    buggy publisher on the channel must not be able to blank the cache or
    stop invalidation for the whole org.

Nothing here logs a policy body or an org's data; assertions are on cache
state and identifiers only.
"""

from __future__ import annotations

import asyncio
import json
import uuid

import pytest
from sqlalchemy import text

from app.db.models.policy import Policy
from app.db.session import SessionLocal
from app.policy.cache import CompiledPolicyCache, get_cache, reset_cache_for_tests
from app.services.policy_pubsub import channel_name, publish_policy_change
from app.services.redis_client import get_redis

pytestmark = pytest.mark.integration


async def _insert_policy(
    org_id: uuid.UUID,
    *,
    status: str = "active",
    version: int = 1,
    fail_behavior: str = "closed",
    denylist: list[str] | None = None,
) -> uuid.UUID:
    policy_id = uuid.uuid4()
    async with SessionLocal() as db:
        db.add(
            Policy(
                id=policy_id,
                org_id=org_id,
                name=f"p-{policy_id.hex[:8]}",
                version=version,
                status=status,
                enforcement_level="fast",
                fail_behavior=fail_behavior,
                rules=[],
                tool_allowlist=[],
                tool_denylist=denylist or [],
                tool_approval_required=[],
                rate_limits={},
                content_filters={},
                classifiers=[],
            )
        )
        await db.commit()
    return policy_id


async def _delete_policy(policy_id: uuid.UUID) -> None:
    async with SessionLocal() as db:
        await db.execute(text("DELETE FROM policies WHERE id = :id"), {"id": policy_id})
        await db.commit()


async def _set_fail_behavior(policy_id: uuid.UUID, value: str, version: int) -> None:
    async with SessionLocal() as db:
        await db.execute(
            text("UPDATE policies SET fail_behavior = :fb, version = :v WHERE id = :id"),
            {"fb": value, "v": version, "id": policy_id},
        )
        await db.commit()


async def _until(predicate, *, timeout_s: float = 5.0) -> bool:
    """Poll until the subscriber has applied a message (or give up)."""
    deadline = asyncio.get_running_loop().time() + timeout_s
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return predicate()


@pytest.fixture
def cache() -> CompiledPolicyCache:
    return CompiledPolicyCache()


class TestLoadAndEvict:
    async def test_load_compiles_the_stored_row(self, cache, test_org):
        policy_id = await _insert_policy(test_org, denylist=["shell.exec"])
        try:
            compiled = await cache.load(policy_id=policy_id)

            assert compiled is not None
            assert compiled.policy_id == str(policy_id)
            assert compiled.org_id == str(test_org)
            assert compiled.fail_behavior == "closed"
            assert "shell.exec" in compiled.tool_denylist
            assert cache.get(policy_id) is compiled
        finally:
            await _delete_policy(policy_id)

    async def test_get_returns_none_for_an_unloaded_policy(self, cache):
        assert cache.get(uuid.uuid4()) is None

    async def test_loading_a_missing_row_returns_none_and_clears_any_stale_entry(
        self, cache, test_org
    ):
        """A row deleted behind the cache's back must not stay enforceable."""
        policy_id = await _insert_policy(test_org)
        assert await cache.load(policy_id=policy_id) is not None

        await _delete_policy(policy_id)

        assert await cache.load(policy_id=policy_id) is None
        assert cache.get(policy_id) is None

    async def test_reload_replaces_the_snapshot_rather_than_merging(self, cache, test_org):
        policy_id = await _insert_policy(test_org, fail_behavior="open", denylist=["a"])
        try:
            first = await cache.load(policy_id=policy_id)
            assert first is not None and first.fail_behavior == "open"

            await _set_fail_behavior(policy_id, "closed", version=2)
            second = await cache.load(policy_id=policy_id)

            assert second is not None
            assert second.fail_behavior == "closed"
            assert second.version == 2
            assert cache.get(policy_id) is second
        finally:
            await _delete_policy(policy_id)

    async def test_evict_reports_whether_the_entry_was_present(self, cache, test_org):
        policy_id = await _insert_policy(test_org)
        try:
            await cache.load(policy_id=policy_id)

            assert cache.evict(policy_id) is True
            assert cache.get(policy_id) is None
            assert cache.evict(policy_id) is False, "a second evict is a no-op, not an error"
        finally:
            await _delete_policy(policy_id)

    async def test_warm_org_loads_only_active_policies(self, cache, test_org):
        active_a = await _insert_policy(test_org, status="active")
        active_b = await _insert_policy(test_org, status="active")
        draft = await _insert_policy(test_org, status="draft")
        archived = await _insert_policy(test_org, status="archived")
        try:
            count = await cache.warm_org(org_id=test_org)

            assert count == 2
            assert cache.get(active_a) is not None
            assert cache.get(active_b) is not None
            assert cache.get(draft) is None, "a draft is not enforceable"
            assert cache.get(archived) is None
        finally:
            for pid in (active_a, active_b, draft, archived):
                await _delete_policy(pid)

    async def test_warm_org_does_not_leak_another_orgs_policies(self, cache, test_org):
        other_org = uuid.uuid4()
        async with SessionLocal() as db:
            await db.execute(
                text("INSERT INTO organizations (id, name, slug) VALUES (:i, :n, :s)"),
                {"i": other_org, "n": "other", "s": f"other-{other_org.hex[:8]}"},
            )
            await db.commit()
        mine = await _insert_policy(test_org)
        theirs = await _insert_policy(other_org)
        try:
            assert await cache.warm_org(org_id=test_org) == 1
            assert cache.get(mine) is not None
            assert cache.get(theirs) is None, "cross-tenant policy must never be cached"
        finally:
            await _delete_policy(mine)
            await _delete_policy(theirs)
            async with SessionLocal() as db:
                await db.execute(text("DELETE FROM organizations WHERE id = :i"), {"i": other_org})
                await db.commit()

    async def test_warm_org_with_no_policies_returns_zero(self, cache, test_org):
        assert await cache.warm_org(org_id=test_org) == 0


class TestInvalidationPayloadHandling:
    """``_apply_invalidation`` is fed by an untrusted channel."""

    async def test_update_event_reloads_the_row(self, cache, test_org):
        policy_id = await _insert_policy(test_org, fail_behavior="open")
        try:
            await cache.load(policy_id=policy_id)
            await _set_fail_behavior(policy_id, "closed", version=3)

            await cache._apply_invalidation(
                {"policy_id": str(policy_id), "version": 3, "event": "update"}
            )

            entry = cache.get(policy_id)
            assert entry is not None and entry.fail_behavior == "closed"
        finally:
            await _delete_policy(policy_id)

    async def test_delete_event_evicts_without_touching_the_database(self, cache, test_org):
        policy_id = await _insert_policy(test_org)
        try:
            await cache.load(policy_id=policy_id)

            await cache._apply_invalidation(
                {"policy_id": str(policy_id), "version": 1, "event": "delete"}
            )

            assert cache.get(policy_id) is None
            # The row is still there; only the cached snapshot went away.
            assert await cache.load(policy_id=policy_id) is not None
        finally:
            await _delete_policy(policy_id)

    async def test_delete_event_for_an_uncached_policy_is_harmless(self, cache):
        await cache._apply_invalidation(
            {"policy_id": str(uuid.uuid4()), "version": 1, "event": "delete"}
        )

    async def test_update_for_a_row_that_no_longer_exists_evicts_the_stale_snapshot(
        self, cache, test_org
    ):
        policy_id = await _insert_policy(test_org)
        await cache.load(policy_id=policy_id)
        await _delete_policy(policy_id)

        await cache._apply_invalidation(
            {"policy_id": str(policy_id), "version": 2, "event": "update"}
        )

        assert cache.get(policy_id) is None

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"version": 1, "event": "update"},
            {"policy_id": "not-a-uuid", "event": "update"},
            {"policy_id": "", "event": "delete"},
            {"policy_id": None, "event": "update"},
            {"policy_id": 12345, "event": "update"},
            {"policy_id": ["a"], "event": "delete"},
        ],
        ids=[
            "empty",
            "missing-id",
            "malformed-id",
            "blank-id",
            "null-id",
            "numeric-id",
            "list-id",
        ],
    )
    async def test_malformed_payload_is_dropped_and_leaves_the_cache_intact(
        self, cache, test_org, payload
    ):
        resident = await _insert_policy(test_org)
        try:
            await cache.load(policy_id=resident)

            await cache._apply_invalidation(payload)

            assert cache.get(resident) is not None, "a bad message must not blank the cache"
        finally:
            await _delete_policy(resident)

    async def test_unknown_event_type_is_treated_as_a_reload_not_an_evict(self, cache, test_org):
        """Forward compatibility: a new event kind must not silently drop policy."""
        policy_id = await _insert_policy(test_org)
        try:
            await cache.load(policy_id=policy_id)

            await cache._apply_invalidation(
                {"policy_id": str(policy_id), "version": 1, "event": "some-future-event"}
            )

            assert cache.get(policy_id) is not None
        finally:
            await _delete_policy(policy_id)

    async def test_extra_unknown_fields_are_ignored(self, cache, test_org):
        policy_id = await _insert_policy(test_org)
        try:
            await cache.load(policy_id=policy_id)

            await cache._apply_invalidation(
                {
                    "policy_id": str(policy_id),
                    "version": 1,
                    "event": "update",
                    "injected": "x" * 5000,
                    "org_id": str(uuid.uuid4()),
                }
            )

            assert cache.get(policy_id) is not None
        finally:
            await _delete_policy(policy_id)


class TestSubscriberLifecycle:
    async def test_published_update_reaches_the_cache(self, cache, test_org):
        policy_id = await _insert_policy(test_org, fail_behavior="open")
        await cache.subscribe(org_id=test_org)
        try:
            await cache.load(policy_id=policy_id)
            await _set_fail_behavior(policy_id, "closed", version=2)

            await _publish_until_delivered(
                cache,
                test_org,
                policy_id,
                event="update",
                version=2,
                done=lambda: (cache.get(policy_id) or None) is not None
                and cache.get(policy_id).fail_behavior == "closed",
            )

            assert cache.get(policy_id).fail_behavior == "closed"
        finally:
            await cache.unsubscribe(org_id=test_org)
            await _delete_policy(policy_id)

    async def test_published_delete_evicts_through_the_channel(self, cache, test_org):
        policy_id = await _insert_policy(test_org)
        await cache.subscribe(org_id=test_org)
        try:
            await cache.load(policy_id=policy_id)

            await _publish_until_delivered(
                cache,
                test_org,
                policy_id,
                event="delete",
                version=1,
                done=lambda: cache.get(policy_id) is None,
            )

            assert cache.get(policy_id) is None
        finally:
            await cache.unsubscribe(org_id=test_org)
            await _delete_policy(policy_id)

    async def test_a_non_json_message_does_not_kill_the_subscriber(self, cache, test_org):
        """Garbage on the channel must not stop invalidation for the org."""
        policy_id = await _insert_policy(test_org)
        await cache.subscribe(org_id=test_org)
        try:
            await cache.load(policy_id=policy_id)
            redis = await get_redis()
            await redis.publish(channel_name(test_org), "}{ not json at all")
            await asyncio.sleep(0.1)

            assert not cache._tasks[test_org].done(), "subscriber must survive a bad payload"

            await _publish_until_delivered(
                cache,
                test_org,
                policy_id,
                event="delete",
                version=1,
                done=lambda: cache.get(policy_id) is None,
            )
            assert cache.get(policy_id) is None
        finally:
            await cache.unsubscribe(org_id=test_org)
            await _delete_policy(policy_id)

    @pytest.mark.parametrize(
        "raw",
        ['{"policy_id": null, "event": "update"}', '{"policy_id": 5, "event": "delete"}'],
        ids=["null-id", "numeric-id"],
    )
    async def test_a_non_string_policy_id_does_not_kill_the_subscriber(self, cache, test_org, raw):
        """A dead subscriber is silent: the org would keep enforcing stale policy.

        ``uuid.UUID(None)`` raises TypeError and ``uuid.UUID(5)`` raises
        AttributeError — neither is a ValueError, so both used to escape
        ``_apply_invalidation`` and terminate the org's listener for the
        lifetime of the process.
        """
        policy_id = await _insert_policy(test_org)
        await cache.subscribe(org_id=test_org)
        try:
            await cache.load(policy_id=policy_id)
            redis = await get_redis()
            await redis.publish(channel_name(test_org), raw)
            await asyncio.sleep(0.1)

            assert not cache._tasks[test_org].done()
            assert cache.get(policy_id) is not None

            # And invalidation still works afterwards.
            await _publish_until_delivered(
                cache,
                test_org,
                policy_id,
                event="delete",
                version=1,
                done=lambda: cache.get(policy_id) is None,
            )
        finally:
            await cache.unsubscribe(org_id=test_org)
            await _delete_policy(policy_id)

    async def test_subscribe_is_idempotent(self, cache, test_org):
        await cache.subscribe(org_id=test_org)
        first = cache._tasks[test_org]
        try:
            await cache.subscribe(org_id=test_org)
            assert cache._tasks[test_org] is first, "a second subscribe must not duplicate the task"
        finally:
            await cache.unsubscribe(org_id=test_org)

    async def test_unsubscribe_cancels_the_task_and_forgets_the_org(self, cache, test_org):
        await cache.subscribe(org_id=test_org)
        task = cache._tasks[test_org]

        await cache.unsubscribe(org_id=test_org)

        assert test_org not in cache._tasks
        assert task.cancelled() or task.done()

    async def test_unsubscribe_for_an_unknown_org_is_a_no_op(self, cache):
        await cache.unsubscribe(org_id=uuid.uuid4())

    async def test_stop_all_cancels_every_subscriber(self, cache, test_org):
        other = uuid.uuid4()
        await cache.subscribe(org_id=test_org)
        await cache.subscribe(org_id=other)

        await cache.stop_all()

        assert cache._tasks == {}

    async def test_resubscribing_after_unsubscribe_starts_a_fresh_task(self, cache, test_org):
        await cache.subscribe(org_id=test_org)
        first = cache._tasks[test_org]
        await cache.unsubscribe(org_id=test_org)

        await cache.subscribe(org_id=test_org)
        try:
            assert cache._tasks[test_org] is not first
        finally:
            await cache.unsubscribe(org_id=test_org)


class TestCacheSingleton:
    def test_get_cache_returns_one_shared_instance(self):
        reset_cache_for_tests()
        try:
            assert get_cache() is get_cache()
        finally:
            reset_cache_for_tests()

    def test_reset_drops_the_singleton(self):
        reset_cache_for_tests()
        first = get_cache()
        reset_cache_for_tests()
        assert get_cache() is not first
        reset_cache_for_tests()


async def _publish_until_delivered(cache, org_id, policy_id, *, event, version, done) -> None:
    """Publish until the subscriber has applied it.

    Redis pub/sub has no delivery guarantee before the SUBSCRIBE round trip
    completes, and ``subscribe()`` only schedules the task. Re-publishing is
    the honest way to wait for readiness without asserting on a sleep.
    """
    for _ in range(50):
        await publish_policy_change(
            org_id=org_id, policy_id=policy_id, version=version, event=event
        )
        if await _until(done, timeout_s=0.2):
            return
    raise AssertionError(
        f"invalidation {event!r} was never applied for policy {policy_id} on org {org_id}"
    )


class TestPublishedPayloadShape:
    async def test_publish_emits_the_documented_json_contract(self, test_org):
        """The deployed Go agent parses this exact shape."""
        redis = await get_redis()
        pubsub = redis.pubsub()
        await pubsub.subscribe(channel_name(test_org))
        try:
            policy_id = uuid.uuid4()
            received: dict[str, object] | None = None
            for _ in range(50):
                await publish_policy_change(
                    org_id=test_org, policy_id=policy_id, version=7, event="update"
                )
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.2)
                if message and message.get("type") == "message":
                    received = json.loads(message["data"])
                    break

            assert received == {
                "policy_id": str(policy_id),
                "version": 7,
                "event": "update",
            }
        finally:
            await pubsub.unsubscribe(channel_name(test_org))
            await pubsub.aclose()
