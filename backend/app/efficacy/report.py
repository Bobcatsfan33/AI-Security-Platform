"""Machine-readable report + a receipt a human will actually read.

The JSON is the artifact; the receipt exists because JSON does not stop anyone
quoting a number out of it. Every section of the receipt that carries a metric
also carries the evidence class, so a figure cannot travel without the caveat
that makes it honest.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from app.efficacy.runner import AUTHORIZED_LABEL, RunResult

_SYNTHETIC_BANNER = """\
!!  EVIDENCE CLASS: SYNTHETIC-DEMONSTRATION  !!

These numbers describe SYNTHETIC corpora written to exercise the harness. They
are NOT a measurement of detection efficacy on real or representative traffic
and MUST NOT be quoted as one, internally or externally.

What would make them evidence, none of which has happened:
  * an authorized corpus sampled from real deployments
    (a manifest with representative=true and a named authorization), and
  * an evaluation run by an independent party.

EXT-EFFICACY remains OPEN and blocking."""

_AUTHORIZED_BANNER = """\
EVIDENCE CLASS: AUTHORIZED-CORPUS

Every contributing corpus declares representative=true with a named
authorization. Independent evaluation is a separate gate and is not implied by
this run."""


def build_report(result: RunResult, *, generated_at: str | None = None) -> dict[str, Any]:
    """The machine-readable artifact."""
    evidence_class = result.evidence_class
    return {
        "schema": "aisp.efficacy.report/1",
        "generated_at": generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "evidence_class": evidence_class,
        "representative": evidence_class == AUTHORIZED_LABEL,
        "independent_evaluation": False,
        "external_gate": {
            "id": "EXT-EFFICACY",
            "status": "open",
            "note": (
                "This harness is engineering. The gate needs authorized "
                "representative corpora and an independent evaluator, neither "
                "of which this run provides."
            ),
        },
        "bindings": result.bindings,
        "resumed_case_verdicts": result.resumed,
        "surfaces": {
            surface: {
                "overall": metrics.as_dict(),
                "slices": [m.as_dict() for m in result.per_slice.get(surface, {}).values()],
            }
            for surface, metrics in sorted(result.overall.items())
        },
        # Slices that were REQUESTED and deliberately not evaluated. Present in
        # the report rather than omitted: a missing slice reads as an oversight,
        # a declared refusal reads as a decision.
        "unevaluated_slices": [
            {"slice": name, "reason": reason}
            for name, reason in sorted(result.unevaluated_slices.items())
        ],
    }


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.4f}"


def _fmt_ci(interval: dict[str, Any]) -> str:
    return f"[{interval['low']:.4f}, {interval['high']:.4f}]"


def render_receipt(report: dict[str, Any]) -> str:
    """A human-readable summary that carries its own caveat."""
    lines: list[str] = []
    banner = (
        _AUTHORIZED_BANNER if report["evidence_class"] == AUTHORIZED_LABEL else _SYNTHETIC_BANNER
    )
    lines.append("=" * 72)
    lines.append(" DETECTION EFFICACY REPORT")
    lines.append("=" * 72)
    lines.append(banner)
    lines.append("")
    lines.append(f"generated    : {report['generated_at']}")
    lines.append(f"git revision : {report['bindings'].get('git_revision', 'unknown')}")
    lines.append(f"resumed      : {report['resumed_case_verdicts']} case verdicts replayed")
    lines.append("")

    lines.append("CORPORA (hash-pinned)")
    for corpus in report["bindings"].get("corpora", []):
        mark = "authorized" if corpus["representative"] else "SYNTHETIC"
        lines.append(
            f"  {corpus['id']}  split={corpus['split']}  cases={corpus['cases']}  [{mark}]"
        )
        lines.append(f"    sha256     : {corpus['sha256']}")
        lines.append(f"    source     : {corpus['provenance'].get('source', '?')}")
        lines.append(f"    labeled by : {corpus['labeling_protocol'].get('method', '?')}")
    lines.append("")

    lines.append("EVALUATED CONFIGURATION (bound to these results)")
    for binding in report["bindings"].get("surfaces", []):
        detail = "  ".join(f"{k}={v}" for k, v in sorted(binding.items()) if k != "surface")
        lines.append(f"  {binding['surface']}: {detail}")
    lines.append("")

    for surface, payload in report["surfaces"].items():
        lines.append("-" * 72)
        lines.append(f" SURFACE: {surface}")
        lines.append("-" * 72)
        rows = [("overall", payload["overall"])] + [(m["slice"], m) for m in payload["slices"]]
        header = f"  {'slice':<34} {'prec':>8} {'recall':>8} {'FPR':>8} {'n':>6}"
        lines.append(header)
        for label, metrics in rows:
            counts = metrics["counts"]
            total = sum(counts.values())
            short = label.split(":")[-1]
            lines.append(
                f"  {short:<34} {_fmt(metrics['precision']):>8} "
                f"{_fmt(metrics['recall']):>8} "
                f"{_fmt(metrics['false_positive_rate']):>8} {total:>6}"
            )
        lines.append("")
        overall = payload["overall"]
        lines.append(f"  recall 95% CI    : {_fmt_ci(overall['recall_ci'])}")
        lines.append(f"  precision 95% CI : {_fmt_ci(overall['precision_ci'])}")
        lines.append(f"  FPR 95% CI       : {_fmt_ci(overall['false_positive_rate_ci'])}")
        lines.append(f"  CI method        : {overall['recall_ci']['method']}")
        latency = overall["latency_ms"]
        lines.append(
            f"  latency ms       : p50={_fmt(latency['p50'])} "
            f"p95={_fmt(latency['p95'])} p99={_fmt(latency['p99'])}"
        )
        lines.append("")

    if report["unevaluated_slices"]:
        lines.append("-" * 72)
        lines.append(" SLICES DELIBERATELY NOT EVALUATED")
        lines.append("-" * 72)
        for entry in report["unevaluated_slices"]:
            lines.append(f"  {entry['slice']}:")
            lines.append(f"    {entry['reason']}")
        lines.append("")

    lines.append("=" * 72)
    lines.append(
        f" EXT-EFFICACY: {report['external_gate']['status'].upper()} — "
        "this run does not discharge it."
    )
    lines.append("=" * 72)
    return "\n".join(lines)


def write_report(report: dict[str, Any], json_path, receipt_path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    receipt_path.write_text(render_receipt(report) + "\n", encoding="utf-8")
