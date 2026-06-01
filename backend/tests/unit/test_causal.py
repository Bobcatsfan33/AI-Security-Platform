"""Tests for the poset causal spine (Sprint 3).

Covers RuntimeEvent lineage resolution (root/child threading) and the
W3C-traceparent + native-header propagation round-trip.
"""

from __future__ import annotations

import uuid

import pytest

from app.telemetry.causal import (
    HEADER_CORRELATION,
    HEADER_DEPTH,
    HEADER_PARENT,
    HEADER_ROOT,
    HEADER_TRACEPARENT,
    CausalContext,
    from_headers,
    parse_traceparent,
)
from app.telemetry.runtime_event import RuntimeEvent


def _root_event(**overrides) -> RuntimeEvent:
    base = {
        "org_id": uuid.uuid4(),
        "asset_id": uuid.uuid4(),
        "agent_instance_id": "agent-A",
        "session_id": "sess-1",
        "event_type": "request",
        "direction": "inbound",
        "enforcement_level": "fast",
        "pipeline_exit_stage": "no_match",
        "action_taken": "allowed",
    }
    base.update(overrides)
    return RuntimeEvent(**base)  # type: ignore[arg-type]


@pytest.mark.unit
class TestRootResolution:
    def test_root_event_is_its_own_root_at_depth_zero(self) -> None:
        e = _root_event()
        assert e.parent_event_id is None
        assert e.root_event_id == e.event_id
        assert e.causal_depth == 0

    def test_root_event_correlation_key_defaults_to_root_id(self) -> None:
        e = _root_event()
        assert e.correlation_key == str(e.root_event_id)

    def test_explicit_correlation_key_is_preserved(self) -> None:
        e = _root_event(correlation_key="task-42")
        assert e.correlation_key == "task-42"


@pytest.mark.unit
class TestChildThreading:
    def test_child_threads_lineage_forward(self) -> None:
        root = _root_event()
        child = root.child(event_type="tool_call", tool_name="shell_exec")

        assert child.parent_event_id == root.event_id
        assert child.root_event_id == root.root_event_id
        assert child.causal_depth == 1
        assert child.correlation_key == root.correlation_key
        assert child.event_type == "tool_call"
        assert child.tool_name == "shell_exec"

    def test_multi_hop_depth_accumulates(self) -> None:
        root = _root_event()
        a = root.child(event_type="response")
        b = a.child(event_type="tool_call")
        c = b.child(event_type="external_api_call")

        assert [a.causal_depth, b.causal_depth, c.causal_depth] == [1, 2, 3]
        # All descend from the same root — the poset stays connected.
        assert a.root_event_id == root.event_id
        assert c.root_event_id == root.event_id
        # The causal chain is reconstructable parent→child.
        assert c.parent_event_id == b.event_id
        assert b.parent_event_id == a.event_id

    def test_child_does_not_become_its_own_root(self) -> None:
        root = _root_event()
        child = root.child(event_type="tool_call")
        # parent is set, so __post_init__ must NOT overwrite root_event_id.
        assert child.root_event_id == root.event_id
        assert child.root_event_id != child.event_id

    def test_to_row_round_trips_new_columns(self) -> None:
        from app.telemetry.runtime_event import RUNTIME_EVENTS_COLUMNS

        child = _root_event().child(event_type="tool_call")
        row = dict(zip(RUNTIME_EVENTS_COLUMNS, child.to_row()))
        assert row["parent_event_id"] == child.parent_event_id
        assert row["root_event_id"] == child.root_event_id
        assert row["causal_depth"] == 1


@pytest.mark.unit
class TestPropagation:
    def test_traceparent_format_is_w3c_shaped(self) -> None:
        ctx = CausalContext(
            root_event_id=uuid.uuid4(),
            parent_event_id=uuid.uuid4(),
            correlation_key="task-9",
            causal_depth=2,
        )
        tp = ctx.traceparent()
        version, trace_id, span_id, flags = tp.split("-")
        assert version == "00"
        assert len(trace_id) == 32
        assert len(span_id) == 16
        assert flags == "01"
        # trace-id round-trips back to the root id.
        assert parse_traceparent(tp) == ctx.root_event_id

    def test_headers_round_trip(self) -> None:
        ctx = CausalContext(
            root_event_id=uuid.uuid4(),
            parent_event_id=uuid.uuid4(),
            correlation_key="task-9",
            causal_depth=3,
        )
        headers = ctx.to_headers()
        recovered = from_headers(headers)
        assert recovered == ctx

    def test_child_event_from_inbound_context(self) -> None:
        """The end-to-end path: agent B receives A's propagation headers and
        constructs an event whose lineage continues A's poset."""
        parent_event_id = uuid.uuid4()
        root_id = uuid.uuid4()
        headers = {
            HEADER_ROOT: str(root_id),
            HEADER_PARENT: str(parent_event_id),
            HEADER_CORRELATION: "task-9",
            HEADER_DEPTH: "2",
        }
        ctx = from_headers(headers)
        assert ctx is not None

        # Agent B stamps the next event with the inbound lineage.
        e = RuntimeEvent(
            org_id=uuid.uuid4(),
            asset_id=uuid.uuid4(),
            agent_instance_id="agent-B",
            session_id="sess-B",
            event_type="request",
            direction="inbound",
            enforcement_level="fast",
            pipeline_exit_stage="no_match",
            action_taken="allowed",
            parent_event_id=ctx.parent_event_id,
            root_event_id=ctx.root_event_id,
            causal_depth=ctx.causal_depth + 1,
            correlation_key=ctx.correlation_key,
        )
        assert e.root_event_id == root_id
        assert e.parent_event_id == parent_event_id
        assert e.causal_depth == 3
        assert e.correlation_key == "task-9"

    def test_malformed_traceparent_returns_none(self) -> None:
        assert parse_traceparent("garbage") is None
        assert parse_traceparent("00-tooshort-x-01") is None

    def test_missing_lineage_returns_none(self) -> None:
        assert from_headers({}) is None

    def test_traceparent_only_without_parent_returns_none(self) -> None:
        # A hop that passed through a non-AISP tracer keeps traceparent but
        # drops our native parent header — no causal edge can be drawn.
        ctx = CausalContext(
            root_event_id=uuid.uuid4(),
            parent_event_id=uuid.uuid4(),
            correlation_key="x",
            causal_depth=1,
        )
        assert from_headers({HEADER_TRACEPARENT: ctx.traceparent()}) is None

    def test_case_insensitive_header_lookup(self) -> None:
        ctx = CausalContext(
            root_event_id=uuid.uuid4(),
            parent_event_id=uuid.uuid4(),
            correlation_key="task-1",
            causal_depth=0,
        )
        upper = {k.upper(): v for k, v in ctx.to_headers().items()}
        assert from_headers(upper) == ctx
