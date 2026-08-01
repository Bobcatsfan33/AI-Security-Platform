"""Instrumentation must be safe to run in production and honest about failure.

Two failure modes drive these tests.

**Cardinality.** A label whose values come from request data creates a time
series per distinct value. The first unbounded label is almost always a tenant
id, which is simultaneously an outage risk and a data-exposure one: metrics
stores are rarely access-controlled the way the application is, so a tenant id
in a label is tenant identity published to everyone with dashboard access.

**Canary inversion.** A canary that reports green while detection is broken is
worse than no canary, because it is quoted. So both directions are asserted:
the attack probe must fail the canary when it is allowed, and the benign probe
must fail it when it is blocked.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest
from prometheus_client import REGISTRY

from app.observability import metrics as m
from app.observability.canary import (
    CanaryOutcome,
    check_benign_allowed,
    check_prompt_injection_detected,
    main,
    publish,
    run_all,
)

pytestmark = pytest.mark.unit

_REPO = pathlib.Path(__file__).resolve().parents[3]
_RULES = _REPO / "deploy" / "observability" / "rules" / "control-plane.rules.yml"
_RULES_TEST = _REPO / "deploy" / "observability" / "rules" / "control-plane.rules_test.yml"
_DASHBOARD = _REPO / "deploy" / "observability" / "dashboards" / "control-plane.json"
_CANARY_MANIFEST = _REPO / "deploy" / "observability" / "canary" / "canary-cronjob.yaml"

# Label names that must never appear on any metric. Not a stylistic list: each
# of these is either unbounded or identifies a tenant, and most are both.
_FORBIDDEN_LABELS = frozenset(
    {
        "org",
        "org_id",
        "tenant",
        "tenant_id",
        "user",
        "user_id",
        "email",
        "session",
        "session_id",
        "correlation_key",
        "agent_instance_id",
        "asset_id",
        "event_id",
        "trace_id",
        "path",  # raw paths are unbounded; `route` templates are not
        "ip",
        "remote_addr",
        "api_key",
        "token",
    }
)


def _aisp_collectors():
    for collector in list(REGISTRY._collector_to_names):
        for metric in collector.collect():
            if metric.name.startswith("aisp_"):
                yield collector, metric


class TestLabelCardinalityDiscipline:
    def test_no_metric_carries_a_tenant_identifying_or_unbounded_label(self):
        offenders = []
        for collector, metric in _aisp_collectors():
            names = set(getattr(collector, "_labelnames", ()) or ())
            bad = names & _FORBIDDEN_LABELS
            if bad:
                offenders.append(f"{metric.name}: {sorted(bad)}")

        assert not offenders, (
            "these metrics carry forbidden labels — each is unbounded, "
            "tenant-identifying, or both:\n  " + "\n  ".join(offenders)
        )

    @pytest.mark.parametrize(
        ("recorder", "allowed", "kwargs"),
        [
            (m.record_fail_open, m.FAIL_OPEN_STAGES, {}),
            (m.record_region_rejection, m.REGION_ENTRY_POINTS, {}),
            (m.record_auth_anomaly, m.AUTH_REASONS, {}),
            (m.record_audit_chain_failure, m.AUDIT_CHECKS, {}),
        ],
    )
    def test_an_unexpected_label_value_is_collapsed_not_passed_through(
        self, recorder, allowed, kwargs
    ):
        """The guard against a caller that starts emitting a request-derived
        string. Passing it through would create a series per request, and the
        resulting outage looks like a metrics problem rather than a labelling
        bug."""
        hostile = "org-2f8c1e-user-4471-" + "x" * 40

        recorder(hostile, **kwargs)  # must not raise, must not create a series

        emitted = {
            sample.labels[next(iter(sample.labels))]
            for _, metric in _aisp_collectors()
            for sample in metric.samples
            if sample.labels
        }
        assert hostile not in emitted

    def test_the_bounded_helper_falls_back_rather_than_rejecting(self):
        """Fails safe for cardinality, not for fidelity: dropping the
        observation entirely would lose the signal, so it is bucketed."""
        assert m._bounded("expired", m.AUTH_REASONS, "other") == "expired"
        assert m._bounded("something-new", m.AUTH_REASONS, "other") == "other"

    def test_every_alertable_condition_has_a_metric(self):
        """The named P16a conditions, each pinned to the metric that carries
        it. A rule referencing a metric nobody emits is a rule that can never
        fire."""
        exported = {metric.name for _, metric in _aisp_collectors()}
        for name in (
            "aisp_fail_open",
            "aisp_policy_absent",
            "aisp_tenant_region_rejections",
            "aisp_auth_anomalies",
            "aisp_audit_chain_verification_failures",
            "aisp_pipeline_backlog_events",
            "aisp_epa_heartbeat_age_seconds",
            "aisp_canary_result",
        ):
            assert any(e.startswith(name) for e in exported), f"no metric for {name}"


class TestRecorders:
    def test_the_gauges_record_what_they_are_given(self):
        m.set_epa_heartbeat_age(42.5)
        m.set_pipeline_backlog("epa_consumer", 1234)

        assert REGISTRY.get_sample_value("aisp_epa_heartbeat_age_seconds") == 42.5
        assert (
            REGISTRY.get_sample_value("aisp_pipeline_backlog_events", {"stage": "epa_consumer"})
            == 1234
        )

    def test_policy_absence_distinguishes_the_two_decisions(self):
        """'Nothing to check' and 'checked and permitted' are the same HTTP
        result and completely different security events."""
        m.record_policy_absent(failed_closed=True)
        m.record_policy_absent(failed_closed=False)

        assert (
            REGISTRY.get_sample_value("aisp_policy_absent_total", {"decision": "failed_closed"})
            >= 1
        )
        assert (
            REGISTRY.get_sample_value("aisp_policy_absent_total", {"decision": "failed_open"}) >= 1
        )

    def test_an_unknown_backlog_stage_does_not_create_a_series(self):
        m.set_pipeline_backlog("not-a-real-stage", 5)

        assert (
            REGISTRY.get_sample_value("aisp_pipeline_backlog_events", {"stage": "not-a-real-stage"})
            is None
        )


class TestCanary:
    def test_it_passes_when_an_attack_is_blocked_and_benign_is_allowed(self):
        def inspect(text: str) -> str:
            return "block" if "ignore all previous" in text else "allow"

        outcomes = run_all(inspect)

        assert [o.scenario for o in outcomes] == ["prompt_injection_detected", "benign_allowed"]
        assert all(o.passed for o in outcomes)

    def test_it_fails_when_a_known_attack_is_allowed(self):
        """The scenario the canary exists for: every probe green, detection
        silently doing nothing."""
        outcome = check_prompt_injection_detected(lambda _text: "allow")

        assert outcome.passed is False
        assert "action=allow" in outcome.detail

    def test_it_fails_when_benign_traffic_is_blocked(self):
        """The half people forget. A detector that blocks everything passes the
        attack probe perfectly while being unusable."""
        outcome = check_benign_allowed(lambda _text: "block")

        assert outcome.passed is False

    def test_an_exception_is_a_failure_not_a_crash(self):
        """A raised exception means the detection path is unavailable — exactly
        what the canary is for. Propagating it would leave the gauge stale at
        its last good value, which reads as healthy."""

        def broken(_text: str) -> str:
            raise ConnectionError("detector unreachable")

        outcome = check_prompt_injection_detected(broken)

        assert outcome.passed is False
        assert "ConnectionError" in outcome.detail

    def test_publishing_is_fixed_cardinality(self):
        """One series per scenario, forever. A canary that adds a series per
        run eventually takes down the metrics store it was monitoring."""
        for run_index in range(25):
            publish([CanaryOutcome("prompt_injection_detected", run_index % 2 == 0, 0.01, "x")])

        series = [
            sample
            for _, metric in _aisp_collectors()
            if metric.name == "aisp_canary_result"
            for sample in metric.samples
        ]
        assert len(series) == 1

    def test_publishing_records_pass_and_fail_as_one_and_zero(self):
        publish([CanaryOutcome("benign_allowed", True, 0.02)])
        assert REGISTRY.get_sample_value("aisp_canary_result", {"scenario": "benign_allowed"}) == 1

        publish([CanaryOutcome("benign_allowed", False, 0.02)])
        assert REGISTRY.get_sample_value("aisp_canary_result", {"scenario": "benign_allowed"}) == 0

    def test_an_unknown_scenario_does_not_create_a_series(self):
        publish([CanaryOutcome("invented-scenario", True, 0.01)])

        assert (
            REGISTRY.get_sample_value("aisp_canary_result", {"scenario": "invented-scenario"})
            is None
        )

    def test_the_entry_point_exits_nonzero_when_a_scenario_fails(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "app.observability.canary.run_all",
            lambda *a, **k: [
                CanaryOutcome("prompt_injection_detected", False, 0.01, "action=allow")
            ],
        )

        assert main([]) == 1
        assert "FAIL" in capsys.readouterr().out

    def test_the_entry_point_exits_zero_when_everything_passes(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "app.observability.canary.run_all",
            lambda *a, **k: [CanaryOutcome("benign_allowed", True, 0.01, "action=allow")],
        )

        assert main([]) == 0
        assert "PASS" in capsys.readouterr().out

    def test_the_probes_contain_no_tenant_data(self):
        """The canary runs continuously in production, so its inputs must be
        hard-coded strings rather than sampled traffic."""
        from app.observability import canary

        source = pathlib.Path(canary.__file__).read_text(encoding="utf-8")
        assert "_INJECTION_PROBE" in source
        assert "ignore all previous instructions" in source
        # No sampling of live data anywhere in the module.
        assert "SessionLocal" not in source
        assert "select(" not in source


class TestRulesAndDashboardsAreConsistentWithTheCode:
    """The rules and dashboards live outside the Python package, so nothing
    stops them referencing a metric that was renamed or never existed. These
    tie them back."""

    def _referenced_metrics(self, text: str) -> set[str]:
        return set(re.findall(r"\baisp_[a-z0-9_]+\b", text))

    def _exported_metric_names(self) -> set[str]:
        names = set()
        for _, metric in _aisp_collectors():
            names.add(metric.name)
            # Counters expose _total, histograms _bucket/_sum/_count.
            names.update(
                {
                    f"{metric.name}_total",
                    f"{metric.name}_bucket",
                    f"{metric.name}_sum",
                    f"{metric.name}_count",
                }
            )
        return names

    def test_every_metric_referenced_by_an_alert_rule_is_actually_exported(self):
        referenced = self._referenced_metrics(_RULES.read_text(encoding="utf-8"))
        missing = sorted(referenced - self._exported_metric_names())

        assert not missing, f"alert rules reference metrics nothing emits: {missing}"

    def test_every_metric_referenced_by_the_dashboard_is_actually_exported(self):
        referenced = self._referenced_metrics(_DASHBOARD.read_text(encoding="utf-8"))
        missing = sorted(referenced - self._exported_metric_names())

        assert not missing, f"dashboard panels reference metrics nothing emits: {missing}"

    def test_every_named_alert_condition_has_a_rule(self):
        rules = _RULES.read_text(encoding="utf-8")
        for alert in (
            "AispFailOpen",
            "AispPolicyAbsentFailedOpen",
            "AispRegionalMismatchSpike",
            "AispAuthAnomalySpike",
            "AispAuditChainVerificationFailed",
            "AispPipelineBacklogGrowing",
            "AispEpaHeartbeatStale",
            "AispCanaryFailing",
        ):
            assert f"alert: {alert}" in rules, f"no rule for {alert}"

    def test_every_alert_has_a_runbook_link_and_a_severity(self):
        """An alert without a runbook is a page with no next step."""
        import yaml

        spec = yaml.safe_load(_RULES.read_text(encoding="utf-8"))
        for group in spec["groups"]:
            for rule in group["rules"]:
                name = rule["alert"]
                assert rule["labels"].get("severity") in {"critical", "warning"}, name
                assert rule["annotations"].get("runbook_url", "").startswith("https://"), name

    def test_every_alert_is_covered_by_a_promtool_test(self):
        """A rule with no test is a hypothesis. This is the ratchet that keeps
        it that way."""
        import yaml

        spec = yaml.safe_load(_RULES.read_text(encoding="utf-8"))
        declared = {rule["alert"] for group in spec["groups"] for rule in group["rules"]}
        tested = set(re.findall(r"alertname:\s*(\w+)", _RULES_TEST.read_text(encoding="utf-8")))

        assert not declared - tested, f"alerts with no promtool test: {sorted(declared - tested)}"

    def test_the_dashboard_covers_every_required_view(self):
        dashboard = json.loads(_DASHBOARD.read_text(encoding="utf-8"))
        titles = " ".join(p["title"] for p in dashboard["panels"]).lower()

        for required in ("availability", "latency", "detection continuity", "ingestion"):
            assert required in titles, f"dashboard has no {required} section"

    def test_the_dashboard_is_not_editable_in_the_ui(self):
        """Dashboard-as-code only works if the UI cannot silently diverge from
        the file; otherwise the next deploy reverts someone's work and they
        stop trusting it."""
        assert json.loads(_DASHBOARD.read_text(encoding="utf-8"))["editable"] is False

    def test_the_canary_manifest_will_not_deploy_with_a_placeholder_digest(self):
        """A committed manifest carrying a real digest goes stale the day after
        it is written and then quietly deploys an old build."""
        manifest = _CANARY_MANIFEST.read_text(encoding="utf-8")

        assert "REPLACE_WITH_APPROVED_DIGEST" in manifest
        assert ":latest" not in manifest
