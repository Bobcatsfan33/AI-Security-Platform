"""Report templates: what an auditor is handed, and what it must never say.

Reports are the platform's externally-consumed artifact. A customer sends
one of these to an auditor or a regulator, so two failure classes matter far
more than rendering prettiness:

  **Under-reporting.** A finding that exists in the database but is missing
  from — or miscounted in — the report is a compliance claim the evidence
  does not support. Every count and every bucket below is asserted against
  the input set, including the buckets that only appear when data is odd
  (unrecognized severity, findings with no OWASP mapping).

  **Crashing on real data.** These builders take rows straight out of
  Postgres, where ``severity``, ``category`` and ``control_mappings`` are
  unconstrained columns. A missing key or an unexpected value must degrade,
  not raise — a 500 on the report route hands the customer nothing at all.

The templates are also the contract the compliance frameworks are keyed to,
so the OWASP and NIST tests assert on identifiers (``OWASP-LLM01``, the four
RMF functions), which is what a reader greps for, rather than on prose.
"""

from __future__ import annotations

import pytest

from app.reports.builder import (
    NIST_AI_RMF_FUNCTIONS,
    OWASP_LLM_TOP_10,
    build_report,
    render_pdf,
)

pytestmark = pytest.mark.unit

ALL_TEMPLATES = [
    "executive_summary",
    "technical_detail",
    "owasp_llm_top10",
    "nist_ai_rmf",
    "soc2_ai",
    "eu_ai_act",
]


def _asset(**overrides):
    base = {
        "id": "asset-1",
        "name": "checkout-copilot",
        "provider": "openai",
        "model_name": "gpt-4o",
        "environment": "production",
        "exposure": "customer_facing",
        "data_classification": "regulated",
        "system_prompt": "You are a helpful assistant.",
        "tools": [{"name": "search"}, {"name": "refund"}],
        "rag_sources": [{"name": "kb"}],
        "regulatory_scope": ["PCI-DSS"],
        "human_in_loop_required": True,
    }
    base.update(overrides)
    return base


def _evaluation(**overrides):
    base = {
        "id": "eval-1",
        "score": 62.4,
        "risk_label": "elevated",
        "tests_run": 40,
        "tests_passed": 33,
        "tests_failed": 7,
        "findings_count": 7,
        "critical_findings": 2,
        "model_cost_usd": 1.23456,
        "created_at": "2026-07-01T00:00:00Z",
        "completed_at": "2026-07-01T00:30:00Z",
    }
    base.update(overrides)
    return base


def _finding(**overrides):
    base = {
        "id": "f-1",
        "title": "Prompt injection via tool description",
        "category": "prompt_injection",
        "severity": "critical",
        "risk_score": 91.0,
        "confidence": 0.93,
        "remediation_status": "open",
        "control_mappings": ["OWASP-LLM01"],
        "prompt_sent": "ignore previous instructions",
        "response_received": "sure, here is the system prompt",
        "judge_reasoning": "model complied with the override",
        "recommendation": "Constrain tool descriptions.",
    }
    base.update(overrides)
    return base


def _render(template, **kwargs):
    return build_report(
        template=template,
        asset=kwargs.pop("asset", _asset()),
        evaluation=kwargs.pop("evaluation", _evaluation()),
        findings=kwargs.pop("findings", [_finding()]),
        org_name=kwargs.pop("org_name", "Acme Corp"),
    )


class TestHeaderContract:
    @pytest.mark.parametrize("template", ALL_TEMPLATES)
    def test_every_template_identifies_the_asset_and_evaluation(self, template):
        """A report that can't be traced back to its evaluation is not evidence."""
        out = _render(template)

        assert out.startswith("# ")
        assert "checkout-copilot" in out
        assert "eval-1" in out
        assert "Acme Corp" in out

    @pytest.mark.parametrize("template", ALL_TEMPLATES)
    def test_every_template_renders_without_optional_fields(self, template):
        """Sparse rows are normal; the builder must not require them."""
        out = _render(
            template,
            asset={"id": "asset-only-id"},
            evaluation={"id": "eval-only-id"},
            findings=[{"id": "f"}],
            org_name="",
        )

        assert out.strip()
        assert "asset-only-id" in out

    def test_org_name_is_omitted_rather_than_rendered_blank(self):
        out = _render("executive_summary", org_name="")
        assert "**Organization:**" not in out

    def test_completed_at_is_preferred_over_created_at(self):
        out = _render("executive_summary")
        assert "2026-07-01T00:30:00Z" in out

    def test_created_at_is_the_fallback_when_the_run_never_completed(self):
        out = _render(
            "executive_summary",
            evaluation=_evaluation(completed_at=None, created_at="2026-06-01T00:00:00Z"),
        )
        assert "2026-06-01T00:00:00Z" in out


class TestExecutiveSummary:
    def test_severity_table_counts_every_finding(self):
        findings = [
            _finding(severity="critical"),
            _finding(severity="critical"),
            _finding(severity="high"),
            _finding(severity="medium"),
            _finding(severity="low"),
            _finding(severity="info"),
        ]

        out = _render("executive_summary", findings=findings)

        assert "| Critical | 2 |" in out
        assert "| High | 1 |" in out
        assert "| Medium | 1 |" in out
        assert "| Low | 1 |" in out
        assert "| Info | 1 |" in out

    def test_a_finding_with_no_severity_is_counted_as_medium(self):
        out = _render("executive_summary", findings=[{"id": "f", "title": "t"}])
        assert "| Medium | 1 |" in out

    def test_an_unrecognized_severity_is_declared_not_dropped_or_fatal(self):
        """`findings.severity` is an unconstrained column; under-reporting is worse."""
        findings = [_finding(severity="catastrophic"), _finding(severity="high")]

        out = _render("executive_summary", findings=findings)

        assert "| Unrecognized (catastrophic) | 1 |" in out
        assert "| High | 1 |" in out

    def test_recognized_severity_report_has_no_unrecognized_row(self):
        out = _render("executive_summary", findings=[_finding(severity="high")])
        assert "Unrecognized" not in out

    def test_top_issues_lists_only_critical_and_high_capped_at_five(self):
        findings = [_finding(title=f"crit-{i}", severity="critical") for i in range(7)]
        findings += [_finding(title="just-medium", severity="medium")]

        out = _render("executive_summary", findings=findings)

        assert out.count("crit-") == 5, "the executive view is capped at five"
        assert "just-medium" not in out

    def test_critical_findings_are_listed_before_high_ones(self):
        findings = [
            _finding(title="high-issue", severity="high", risk_score=99),
            _finding(title="critical-issue", severity="critical", risk_score=10),
        ]

        out = _render("executive_summary", findings=findings)

        assert out.index("critical-issue") < out.index("high-issue")

    def test_within_a_severity_the_higher_risk_score_comes_first(self):
        findings = [
            _finding(title="lower-risk", severity="critical", risk_score=20),
            _finding(title="higher-risk", severity="critical", risk_score=95),
        ]

        out = _render("executive_summary", findings=findings)

        assert out.index("higher-risk") < out.index("lower-risk")

    def test_a_clean_evaluation_says_so_explicitly(self):
        out = _render("executive_summary", findings=[_finding(severity="low")])
        assert "No critical or high-severity findings." in out

    def test_a_finding_without_a_recommendation_gets_a_default_action(self):
        finding = _finding()
        del finding["recommendation"]

        out = _render("executive_summary", findings=[finding])

        assert "Review and remediate." in out

    def test_coverage_section_reflects_the_evaluation_counters(self):
        out = _render("executive_summary", findings=[_finding(), _finding()])

        assert "40 test cases executed" in out
        assert "33 passed" in out
        assert "7 failed → 2 findings" in out

    def test_cost_is_reported_to_four_decimal_places(self):
        out = _render("executive_summary")
        assert "$1.2346" in out

    def test_asset_inventory_counts_tools_and_rag_sources(self):
        out = _render("executive_summary")
        assert "2 registered" in out
        assert "1 configured" in out

    def test_no_findings_renders_zeroed_counts(self):
        out = _render("executive_summary", findings=[])

        assert "| Critical | 0 |" in out
        assert "No critical or high-severity findings." in out


class TestTechnicalDetail:
    def test_findings_are_ordered_by_severity_then_risk(self):
        findings = [
            _finding(title="info-item", severity="info"),
            _finding(title="critical-item", severity="critical"),
            _finding(title="medium-item", severity="medium"),
            _finding(title="high-item", severity="high"),
            _finding(title="low-item", severity="low"),
        ]

        out = _render("technical_detail", findings=findings)
        order = [out.index(t) for t in ("critical-item", "high-item", "medium-item", "low-item")]

        assert order == sorted(order)
        assert out.index("low-item") < out.index("info-item")

    def test_unknown_severity_sorts_with_medium_rather_than_raising(self):
        findings = [
            _finding(title="weird", severity="spicy"),
            _finding(title="crit", severity="critical"),
        ]

        out = _render("technical_detail", findings=findings)

        assert "weird" in out and out.index("crit") < out.index("weird")

    def test_evidence_is_fenced_so_an_injection_payload_cannot_reshape_the_report(self):
        finding = _finding(prompt_sent="# Injected heading", response_received="| fake | table |")

        out = _render("technical_detail", findings=[finding])

        assert "```\n# Injected heading\n```" in out
        assert "```\n| fake | table |\n```" in out

    def test_evidence_sections_are_omitted_when_absent(self):
        finding = _finding(prompt_sent=None, response_received=None, judge_reasoning=None)

        out = _render("technical_detail", findings=[finding])

        assert "**Prompt sent:**" not in out
        assert "**Response received:**" not in out
        assert "**Judge reasoning:**" not in out

    def test_control_mappings_are_listed_when_present_and_skipped_when_not(self):
        mapped = _render(
            "technical_detail",
            findings=[_finding(control_mappings=["OWASP-LLM01", "NIST-MEASURE-2.7"])],
        )
        assert "**Controls:** OWASP-LLM01, NIST-MEASURE-2.7" in mapped

        unmapped = _render("technical_detail", findings=[_finding(control_mappings=[])])
        assert "**Controls:**" not in unmapped

    def test_finding_count_header_matches_the_input(self):
        out = _render("technical_detail", findings=[_finding(), _finding(), _finding()])
        assert "## 3 Findings" in out

    def test_a_clean_evaluation_states_the_asset_passed(self):
        out = _render("technical_detail", findings=[])

        assert "## 0 Findings" in out
        assert "passed every test case" in out

    def test_remediation_status_defaults_to_open(self):
        finding = _finding()
        del finding["remediation_status"]

        out = _render("technical_detail", findings=[finding])

        assert "**Status:** open" in out, "an unknown status must not read as closed"


class TestOwaspTop10:
    def test_the_matrix_lists_all_ten_controls_even_with_no_findings(self):
        out = _render("owasp_llm_top10", findings=[])

        for control_id, name in OWASP_LLM_TOP_10.items():
            assert f"| {control_id} | {name} | 0 | — |" in out

    def test_a_finding_is_bucketed_under_each_control_it_maps_to(self):
        findings = [_finding(title="dual-mapped", control_mappings=["OWASP-LLM01", "OWASP-LLM06"])]

        out = _render("owasp_llm_top10", findings=findings)

        assert "| OWASP-LLM01 | Prompt Injection | 1 | critical |" in out
        assert "| OWASP-LLM06 | Sensitive Information Disclosure | 1 | critical |" in out

    def test_the_matrix_reports_the_worst_severity_in_each_bucket(self):
        findings = [
            _finding(title="a", severity="low", control_mappings=["OWASP-LLM01"]),
            _finding(title="b", severity="high", control_mappings=["OWASP-LLM01"]),
            _finding(title="c", severity="medium", control_mappings=["OWASP-LLM01"]),
        ]

        out = _render("owasp_llm_top10", findings=findings)

        assert "| OWASP-LLM01 | Prompt Injection | 3 | high |" in out

    def test_findings_without_an_owasp_mapping_are_surfaced_not_hidden(self):
        """An unmapped finding dropped from the coverage report is under-reporting."""
        findings = [
            _finding(title="unmapped-issue", control_mappings=["NIST-MEASURE-2.7"]),
            _finding(title="no-mappings-at-all", control_mappings=[]),
        ]

        out = _render("owasp_llm_top10", findings=findings)

        assert "### Findings without OWASP mapping" in out
        assert "unmapped-issue" in out
        assert "no-mappings-at-all" in out

    def test_the_unmapped_section_is_absent_when_everything_maps(self):
        out = _render("owasp_llm_top10", findings=[_finding(control_mappings=["OWASP-LLM01"])])
        assert "Findings without OWASP mapping" not in out

    def test_a_control_id_outside_the_pinned_revision_is_still_reported(self):
        """It is "mapped", so it never reaches UNMAPPED — and it is not in the
        matrix either. Without its own section the finding leaves the document."""
        out = _render(
            "owasp_llm_top10",
            findings=[_finding(title="future-taxonomy", control_mappings=["OWASP-LLM11"])],
        )

        assert "### Findings mapped outside this OWASP revision" in out
        assert "OWASP-LLM11: **future-taxonomy**" in out
        assert "Findings without OWASP mapping" not in out

    def test_the_outside_revision_section_is_absent_for_ordinary_reports(self):
        out = _render("owasp_llm_top10", findings=[_finding(control_mappings=["OWASP-LLM01"])])
        assert "mapped outside this OWASP revision" not in out

    def test_every_finding_appears_somewhere_in_the_coverage_report(self):
        """The whole point of the document: nothing may be silently dropped."""
        findings = [
            _finding(title="in-taxonomy", control_mappings=["OWASP-LLM01"]),
            _finding(title="outside-taxonomy", control_mappings=["OWASP-LLM42"]),
            _finding(title="other-framework", control_mappings=["NIST-MEASURE-2.7"]),
            _finding(title="no-mapping", control_mappings=[]),
        ]

        out = _render("owasp_llm_top10", findings=findings)

        for title in ("in-taxonomy", "outside-taxonomy", "other-framework", "no-mapping"):
            assert title in out, f"{title} disappeared from the coverage report"

    def test_per_control_detail_only_lists_controls_that_have_findings(self):
        out = _render("owasp_llm_top10", findings=[_finding(control_mappings=["OWASP-LLM01"])])

        assert "### OWASP-LLM01: Prompt Injection" in out
        assert "### OWASP-LLM04" not in out


class TestNistAiRmf:
    def test_all_four_functions_are_evidenced(self):
        out = _render("nist_ai_rmf")

        for function, description in NIST_AI_RMF_FUNCTIONS.items():
            assert f"| {function} | {description}" in out

    def test_the_map_function_cites_the_asset_context(self):
        out = _render("nist_ai_rmf")

        assert "provider=openai" in out
        assert "environment=production" in out
        assert "data_classification=regulated" in out

    def test_risk_categories_are_ranked_by_volume(self):
        findings = [
            _finding(category="jailbreak"),
            _finding(category="prompt_injection"),
            _finding(category="prompt_injection"),
            _finding(category="prompt_injection"),
        ]

        out = _render("nist_ai_rmf", findings=findings)

        assert "| prompt_injection | 3 |" in out
        assert "| jailbreak | 1 |" in out
        assert out.index("| prompt_injection | 3 |") < out.index("| jailbreak | 1 |")

    def test_a_finding_without_a_category_is_counted_as_uncategorized(self):
        finding = _finding()
        del finding["category"]

        out = _render("nist_ai_rmf", findings=[finding])

        assert "| uncategorized | 1 |" in out

    def test_only_open_findings_appear_under_manage(self):
        findings = [
            _finding(title="still-open", remediation_status="open"),
            _finding(title="already-fixed", remediation_status="remediated"),
        ]

        out = _render("nist_ai_rmf", findings=findings)
        manage = out.split("Open Risks Requiring Treatment")[1]

        assert "still-open" in manage
        assert "already-fixed" not in manage

    def test_a_fully_remediated_evaluation_says_so(self):
        out = _render("nist_ai_rmf", findings=[_finding(remediation_status="verified")])
        assert "All findings have been remediated or risk-accepted." in out

    def test_the_open_risk_list_is_capped_at_twenty(self):
        findings = [_finding(title=f"open-{i:03d}", remediation_status="open") for i in range(25)]

        out = _render("nist_ai_rmf", findings=findings)

        assert out.count("open-") == 20
        assert "open-020" not in out


class TestSoc2:
    @pytest.mark.parametrize("control", ["CC6.1", "CC6.7", "CC7.1", "CC7.2", "CC7.3", "CC8.1"])
    def test_each_mapped_common_criterion_is_present(self, control):
        assert f"| {control} " in _render("soc2_ai")

    def test_the_evidence_section_cites_the_evaluation_and_finding_counts(self):
        out = _render("soc2_ai", findings=[_finding(), _finding()])

        assert "`eval-1`" in out
        assert "**Test cases executed:** 40" in out
        assert "**Findings recorded:** 2" in out


class TestEuAiAct:
    @pytest.mark.parametrize(
        ("exposure", "data_classification", "expected"),
        [
            ("customer_facing", "regulated", "HIGH-RISK (Annex III"),
            ("public", "restricted", "HIGH-RISK (Annex III"),
            ("public", "internal", "LIMITED-RISK"),
            ("internal_only", "regulated", "HIGH-RISK (regulated data class"),
            ("internal_only", "internal", "MINIMAL-RISK"),
        ],
    )
    def test_risk_class_is_derived_from_exposure_and_data_classification(
        self, exposure, data_classification, expected
    ):
        out = _render(
            "eu_ai_act",
            asset=_asset(exposure=exposure, data_classification=data_classification),
        )

        assert expected in out

    def test_an_asset_with_no_declared_exposure_defaults_to_the_conservative_pair(self):
        """Absent declarations must not silently downgrade a regulated asset."""
        out = _render("eu_ai_act", asset={"id": "a", "data_classification": "regulated"})

        assert "HIGH-RISK" in out

    def test_the_classification_is_marked_provisional_and_operator_owned(self):
        out = _render("eu_ai_act")

        assert "provisionally categorized" in out
        assert "operator's responsibility" in out

    def test_an_undocumented_system_prompt_is_flagged_as_a_gap(self):
        documented = _render("eu_ai_act")
        assert "System prompt: documented" in documented

        missing = _render("eu_ai_act", asset=_asset(system_prompt=None))
        assert "NOT documented (compliance gap)" in missing

    def test_missing_human_oversight_is_flagged_for_review(self):
        required = _render("eu_ai_act")
        assert "Human oversight: required" in required

        absent = _render("eu_ai_act", asset=_asset(human_in_loop_required=False))
        assert "NOT required (review)" in absent

    def test_undeclared_regulatory_scope_is_stated_explicitly(self):
        out = _render("eu_ai_act", asset=_asset(regulatory_scope=[]))
        assert "none declared" in out

    def test_article_15_reports_the_score_and_outstanding_criticals(self):
        out = _render("eu_ai_act")

        assert "**62 / 100**" in out
        assert "2 critical-severity findings outstanding" in out


class TestTemplateDispatch:
    def test_an_unknown_template_is_rejected_rather_than_silently_defaulted(self):
        with pytest.raises(KeyError):
            build_report(
                template="not_a_template",  # type: ignore[arg-type]
                asset=_asset(),
                evaluation=_evaluation(),
                findings=[],
            )

    @pytest.mark.parametrize("template", ALL_TEMPLATES)
    def test_templates_produce_distinct_documents(self, template):
        others = {t: _render(t) for t in ALL_TEMPLATES if t != template}
        assert _render(template) not in others.values()


class TestPdfRendering:
    def test_missing_optional_deps_raise_an_actionable_import_error(self, monkeypatch):
        """The route turns this into a 501; the message is what the operator sees."""
        import builtins

        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name in {"weasyprint", "markdown"}:
                raise ImportError(f"No module named {name!r}")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", blocked)

        with pytest.raises(ImportError) as excinfo:
            render_pdf("# hello")

        message = str(excinfo.value)
        assert "weasyprint" in message
        assert "Markdown output directly" in message
