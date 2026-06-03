"""Detection-efficacy report — measured, not asserted.

Renders the validation-suite results (Sprint 13) into a Markdown report that
slots alongside the OWASP/NIST/SOC2 templates. Where the strategic brief
*claims* an 85–95% alert reduction and <5% false positives, this reports the
platform's own MEASURED detection rate and false-positive rate, with an
optional before/after comparison against a recorded baseline.

PDF rendering reuses app.reports.builder.render_pdf.
"""

from __future__ import annotations

from typing import Any, Optional


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _delta_row(label: str, before: float, after: float, *, lower_is_better: bool) -> str:
    delta = after - before
    improved = (delta < 0) if lower_is_better else (delta > 0)
    arrow = "▼" if delta < 0 else ("▲" if delta > 0 else "—")
    verdict = (
        "improved" if improved and delta != 0 else ("regressed" if delta != 0 else "unchanged")
    )
    return f"| {label} | {_pct(before)} | {_pct(after)} | {arrow} {_pct(abs(delta))} ({verdict}) |"


def build_efficacy_report(
    suite_summary: dict[str, Any],
    *,
    baseline: Optional[dict[str, Any]] = None,
    org_name: str = "",
    generated_at: str = "",
) -> str:
    """Build a Markdown detection-efficacy report from a SuiteResult.summary().

    ``baseline`` (optional) is a prior summary with ``detection_rate`` and
    ``false_positive_rate`` to render a before/after comparison.
    """
    detection_rate = float(suite_summary.get("detection_rate", 0.0))
    fp_rate = float(suite_summary.get("false_positive_rate", 0.0))
    results = suite_summary.get("results", [])
    attacks = int(suite_summary.get("attacks", 0))

    lines: list[str] = []
    lines.append("# Detection Efficacy Report")
    lines.append("")
    if org_name:
        lines.append(f"**Organization:** {org_name}  ")
    if generated_at:
        lines.append(f"**Generated:** {generated_at}  ")
    lines.append(
        "**Method:** purple-team replay of synthetic multi-agent attack flows "
        "through the live EPA detection stack."
    )
    lines.append("")

    # ── headline ────────────────────────────────────────────────────
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Scenarios run | {suite_summary.get('scenarios', len(results))} |")
    lines.append(f"| Attack scenarios | {attacks} |")
    lines.append(f"| **Detection rate** | **{_pct(detection_rate)}** |")
    lines.append(f"| **False-positive rate** | **{_pct(fp_rate)}** |")
    lines.append("")

    # ── baseline comparison ──────────────────────────────────────────
    if baseline:
        lines.append("## Versus baseline")
        lines.append("")
        lines.append("| Metric | Baseline | Current | Change |")
        lines.append("| --- | --- | --- | --- |")
        lines.append(
            _delta_row(
                "Detection rate",
                float(baseline.get("detection_rate", 0.0)),
                detection_rate,
                lower_is_better=False,
            )
        )
        lines.append(
            _delta_row(
                "False-positive rate",
                float(baseline.get("false_positive_rate", 0.0)),
                fp_rate,
                lower_is_better=True,
            )
        )
        lines.append("")

    # ── per-scenario ─────────────────────────────────────────────────
    lines.append("## Scenario results")
    lines.append("")
    lines.append("| Scenario | Brief | Expected | Detected | Result |")
    lines.append("| --- | --- | --- | --- | --- |")
    for r in results:
        expected = ", ".join(r.get("expected", [])) or "—"
        detected = ", ".join(r.get("detected", [])) or "—"
        result = "✅ pass" if r.get("passed") else "❌ FAIL"
        lines.append(
            f"| {r.get('name', '')} | {r.get('brief_section', '')} | "
            f"{expected} | {detected} | {result} |"
        )
    lines.append("")

    # ── honest caveat ────────────────────────────────────────────────
    lines.append("## Interpretation")
    lines.append("")
    lines.append(
        "These figures are measured against **synthetic** attack scenarios, not "
        "production traffic. They validate that the configured detections fire "
        "for the modeled threats (the brief's §4.1–4.4) and that a benign control "
        "produces no alerts. Production efficacy must be confirmed with replayed "
        "real telemetry and analyst-labelled outcomes before any external claim."
    )
    lines.append("")
    return "\n".join(lines)
