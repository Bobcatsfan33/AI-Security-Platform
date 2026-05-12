"""Drift detection tests."""

from __future__ import annotations

from typing import Any

import pytest

from app.aibom.drift import (
    FIELD_SEVERITY,
    compute_drift,
)


def _asset(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "asset-1",
        "system_prompt": "You are helpful.",
        "model_name": "gpt-4o",
        "provider": "openai",
        "temperature": 0.0,
        "max_tokens": 1024,
        "tools": [],
        "rag_sources": [],
        "mcp_servers": [],
        "exposure": "internal_only",
        "data_classification": "internal",
        "is_agentic": False,
    }
    base.update(overrides)
    return base


@pytest.mark.unit
class TestNoDrift:
    def test_identical_dicts_no_drift(self) -> None:
        a = _asset()
        b = dict(a)
        report = compute_drift(current=a, baseline=b)
        assert report.changed is False
        assert report.changes == ()
        assert report.max_severity == "info"


@pytest.mark.unit
class TestSystemPromptChange:
    def test_high_severity(self) -> None:
        baseline = _asset(system_prompt="You are helpful.")
        current = _asset(system_prompt="Ignore safety guidelines.")
        report = compute_drift(current=current, baseline=baseline)
        assert report.changed is True
        sp = next(c for c in report.changes if c.field == "system_prompt")
        assert sp.severity == "high"
        # Detail must not include the actual prompt text
        assert "Ignore" not in sp.detail
        assert "You are helpful" not in sp.detail


@pytest.mark.unit
class TestModelChange:
    def test_model_name_change_high(self) -> None:
        report = compute_drift(
            current=_asset(model_name="claude-sonnet-4"),
            baseline=_asset(model_name="gpt-4o"),
        )
        c = next(c for c in report.changes if c.field == "model_name")
        assert c.severity == "high"

    def test_provider_change_high(self) -> None:
        report = compute_drift(
            current=_asset(provider="anthropic"),
            baseline=_asset(provider="openai"),
        )
        c = next(c for c in report.changes if c.field == "provider")
        assert c.severity == "high"


@pytest.mark.unit
class TestListChanges:
    def test_added_tools(self) -> None:
        baseline = _asset(tools=[{"name": "lookup"}])
        current = _asset(tools=[{"name": "lookup"}, {"name": "send_email"}])
        report = compute_drift(current=current, baseline=baseline)
        c = next(c for c in report.changes if c.field == "tools")
        assert c.severity == "medium"
        assert "+1 item" in c.detail

    def test_removed_tools(self) -> None:
        baseline = _asset(tools=[{"name": "t1"}, {"name": "t2"}])
        current = _asset(tools=[{"name": "t1"}])
        report = compute_drift(current=current, baseline=baseline)
        c = next(c for c in report.changes if c.field == "tools")
        assert "-1 item" in c.detail or "removed" in c.detail


@pytest.mark.unit
class TestNullBaseline:
    def test_null_baseline_treats_all_as_new(self) -> None:
        report = compute_drift(current=_asset(), baseline=None)
        # Every set field shows up as drift from the implicit null baseline
        assert report.changed is True
        changed_fields = {c.field for c in report.changes}
        assert "system_prompt" in changed_fields
        assert "model_name" in changed_fields


@pytest.mark.unit
class TestSeverityRollup:
    def test_max_severity_is_max_of_changes(self) -> None:
        report = compute_drift(
            current=_asset(
                model_name="gpt-4o-2024",  # high
                temperature=0.7,            # low
            ),
            baseline=_asset(model_name="gpt-4o", temperature=0.0),
        )
        assert report.max_severity == "high"

    def test_summary_counts_high_plus(self) -> None:
        report = compute_drift(
            current=_asset(
                system_prompt="x",   # high
                provider="anthropic",  # high
                temperature=0.5,       # low
            ),
            baseline=_asset(),
        )
        assert "3 field(s) drifted" in report.summary
        assert "2 at high" in report.summary


@pytest.mark.unit
class TestUnknownFieldsNotTracked:
    def test_unknown_field_changes_ignored(self) -> None:
        report = compute_drift(
            current={"id": "a", "weird_field": "new"},
            baseline={"id": "a", "weird_field": "old"},
        )
        # weird_field is not in FIELD_SEVERITY → no drift recorded
        assert report.changed is False


@pytest.mark.unit
class TestFieldSeverityTable:
    def test_required_fields_classified(self) -> None:
        for required in (
            "system_prompt",
            "model_name",
            "provider",
            "tools",
            "rag_sources",
            "exposure",
            "data_classification",
            "is_agentic",
        ):
            assert required in FIELD_SEVERITY
