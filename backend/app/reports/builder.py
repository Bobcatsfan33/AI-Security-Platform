"""Report generation — Markdown + compliance-framework templates.

Templates:

  executive_summary  — risk score, top findings, trend snippet
  technical_detail   — every finding with prompt/response evidence
  owasp_llm_top10    — coverage matrix mapping findings → OWASP IDs
  nist_ai_rmf        — MAP / MEASURE / MANAGE / GOVERN function coverage
  soc2_ai            — controls-mapping evidence package
  eu_ai_act          — risk classification + transparency requirements

All emit Markdown by default. PDF rendering happens via weasyprint when
requested (optional dep — install ``platform[pdf]`` to enable).
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Literal

ReportTemplate = Literal[
    "executive_summary",
    "technical_detail",
    "owasp_llm_top10",
    "nist_ai_rmf",
    "soc2_ai",
    "eu_ai_act",
]


# Static OWASP LLM Top 10 — referenced by templates and control_mappings
OWASP_LLM_TOP_10: dict[str, str] = {
    "OWASP-LLM01": "Prompt Injection",
    "OWASP-LLM02": "Insecure Output Handling / Indirect Injection",
    "OWASP-LLM03": "Training Data Poisoning",
    "OWASP-LLM04": "Model Denial of Service",
    "OWASP-LLM05": "Supply Chain Vulnerabilities",
    "OWASP-LLM06": "Sensitive Information Disclosure",
    "OWASP-LLM07": "Insecure Plugin Design",
    "OWASP-LLM08": "Excessive Agency",
    "OWASP-LLM09": "Overreliance",
    "OWASP-LLM10": "Model Theft",
}


# NIST AI RMF functions
NIST_AI_RMF_FUNCTIONS: dict[str, str] = {
    "GOVERN": "Cultivate a culture of risk management",
    "MAP": "Establish context for risk identification",
    "MEASURE": "Analyze, assess, benchmark, and monitor risks",
    "MANAGE": "Prioritize and act on risks",
}


# ─────────────────────────────────────────────── Builder


def build_report(
    *,
    template: ReportTemplate,
    asset: dict[str, Any],
    evaluation: dict[str, Any],
    findings: list[dict[str, Any]],
    org_name: str = "",
) -> str:
    """Build a Markdown report for one evaluation. Returns the rendered text."""
    builders = {
        "executive_summary": _executive_summary,
        "technical_detail": _technical_detail,
        "owasp_llm_top10": _owasp_top10,
        "nist_ai_rmf": _nist_ai_rmf,
        "soc2_ai": _soc2_ai,
        "eu_ai_act": _eu_ai_act,
    }
    builder = builders[template]
    return builder(asset=asset, evaluation=evaluation, findings=findings, org_name=org_name)


def render_pdf(markdown: str) -> bytes:
    """Render Markdown to PDF via weasyprint.

    Optional dep — install platform[pdf] (or just ``pip install
    weasyprint``) to enable. Raises ImportError when absent.
    """
    try:
        import markdown as md_lib
        from weasyprint import HTML  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "PDF rendering requires `markdown` + `weasyprint`. "
            "Install with `pip install markdown weasyprint` or use the "
            "Markdown output directly."
        ) from exc

    html_body = md_lib.markdown(markdown, extensions=["tables", "fenced_code"])
    html = (
        '<html><head><meta charset="utf-8"><style>'
        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;"
        "max-width:800px;margin:2em auto;color:#1e293b;line-height:1.5}"
        "h1{border-bottom:2px solid #1e293b;padding-bottom:.3em}"
        "h2{border-bottom:1px solid #cbd5e1;padding-bottom:.2em;margin-top:2em}"
        "code{background:#f1f5f9;padding:.1em .3em;border-radius:3px}"
        "pre{background:#f1f5f9;padding:1em;border-radius:5px;overflow-x:auto}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #cbd5e1;padding:.4em .6em;text-align:left}"
        "th{background:#f1f5f9}"
        ".sev-critical{color:#dc2626;font-weight:600}"
        ".sev-high{color:#ea580c;font-weight:600}"
        ".sev-medium{color:#ca8a04}"
        "</style></head><body>" + html_body + "</body></html>"
    )
    buf = io.BytesIO()
    HTML(string=html).write_pdf(buf)
    return buf.getvalue()


# ─────────────────────────────────────────────── Templates


def _header(template_name: str, asset: dict[str, Any], evaluation: dict[str, Any], org_name: str) -> str:
    return (
        f"# {template_name}\n\n"
        f"**Asset:** {asset.get('name', asset.get('id'))}  \n"
        f"**Evaluation:** `{evaluation.get('id', '')}`  \n"
        f"**Score:** {evaluation.get('score', 0):.0f} / 100"
        f" ({evaluation.get('risk_label') or '—'})  \n"
        f"**Date:** {evaluation.get('completed_at') or evaluation.get('created_at')}  \n"
        + (f"**Organization:** {org_name}  \n" if org_name else "")
        + "\n"
    )


def _executive_summary(
    *,
    asset: dict[str, Any],
    evaluation: dict[str, Any],
    findings: list[dict[str, Any]],
    org_name: str,
) -> str:
    out = io.StringIO()
    out.write(_header("Executive Summary", asset, evaluation, org_name))

    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.get("severity", "medium")] += 1

    out.write("## Risk Posture\n\n")
    out.write(
        "| Severity | Count |\n|---|---|\n"
        f"| Critical | {sev_counts['critical']} |\n"
        f"| High | {sev_counts['high']} |\n"
        f"| Medium | {sev_counts['medium']} |\n"
        f"| Low | {sev_counts['low']} |\n"
        f"| Info | {sev_counts['info']} |\n\n"
    )

    out.write("## Asset Context\n\n")
    out.write(
        f"- **Provider:** {asset.get('provider', '—')} / {asset.get('model_name', '—')}\n"
        f"- **Environment:** {asset.get('environment', '—')}\n"
        f"- **Exposure:** {asset.get('exposure', '—')}\n"
        f"- **Data classification:** {asset.get('data_classification', '—')}\n"
        f"- **Tools:** {len(asset.get('tools') or [])} registered\n"
        f"- **RAG sources:** {len(asset.get('rag_sources') or [])} configured\n\n"
    )

    critical_high = sorted(
        [f for f in findings if f.get("severity") in ("critical", "high")],
        key=lambda f: (f.get("severity") == "high", -float(f.get("risk_score", 0))),
    )[:5]
    if critical_high:
        out.write("## Top 5 Issues Requiring Attention\n\n")
        for idx, f in enumerate(critical_high, 1):
            out.write(
                f"{idx}. **{f.get('title', 'Untitled')}** "
                f"({f.get('severity')}) — {f.get('category')}\n"
                f"   {f.get('recommendation', 'Review and remediate.')}\n\n"
            )
    else:
        out.write("## Top Issues\n\nNo critical or high-severity findings.\n\n")

    out.write("## Test Coverage\n\n")
    out.write(
        f"- {evaluation.get('tests_run', 0)} test cases executed\n"
        f"- {evaluation.get('tests_passed', 0)} passed\n"
        f"- {evaluation.get('tests_failed', 0)} failed → {len(findings)} findings\n"
        f"- Evaluation cost: ${evaluation.get('model_cost_usd', 0):.4f}\n\n"
    )

    return out.getvalue()


def _technical_detail(
    *,
    asset: dict[str, Any],
    evaluation: dict[str, Any],
    findings: list[dict[str, Any]],
    org_name: str,
) -> str:
    out = io.StringIO()
    out.write(_header("Technical Findings Report", asset, evaluation, org_name))
    out.write(f"## {len(findings)} Findings\n\n")

    if not findings:
        out.write("No findings — the asset passed every test case in this evaluation.\n")
        return out.getvalue()

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered = sorted(
        findings,
        key=lambda f: (severity_order.get(f.get("severity", "medium"), 2), -float(f.get("risk_score", 0))),
    )

    for f in ordered:
        out.write(
            f"### {f.get('title', 'Untitled')} ({f.get('severity', '—').upper()})\n\n"
            f"- **Category:** {f.get('category', '—')}\n"
            f"- **Risk score:** {f.get('risk_score', 0):.0f} / 100\n"
            f"- **Confidence:** {f.get('confidence', 0):.2f}\n"
            f"- **Status:** {f.get('remediation_status', 'open')}\n"
        )
        controls = f.get("control_mappings") or []
        if controls:
            out.write(f"- **Controls:** {', '.join(controls)}\n")
        out.write("\n")

        if f.get("judge_reasoning"):
            out.write(f"**Judge reasoning:** {f['judge_reasoning']}\n\n")

        if f.get("prompt_sent"):
            out.write("**Prompt sent:**\n\n```\n" + f["prompt_sent"] + "\n```\n\n")
        if f.get("response_received"):
            out.write("**Response received:**\n\n```\n" + f["response_received"] + "\n```\n\n")

        if f.get("recommendation"):
            out.write(f"**Remediation:** {f['recommendation']}\n\n")
        out.write("---\n\n")

    return out.getvalue()


def _owasp_top10(
    *,
    asset: dict[str, Any],
    evaluation: dict[str, Any],
    findings: list[dict[str, Any]],
    org_name: str,
) -> str:
    out = io.StringIO()
    out.write(_header("OWASP LLM Top 10 Coverage", asset, evaluation, org_name))

    # Bucket findings by OWASP control ID
    by_owasp: dict[str, list[dict[str, Any]]] = {k: [] for k in OWASP_LLM_TOP_10}
    by_owasp["UNMAPPED"] = []
    for f in findings:
        controls = f.get("control_mappings") or []
        owasp_ids = [c for c in controls if c.startswith("OWASP-LLM")]
        if not owasp_ids:
            by_owasp["UNMAPPED"].append(f)
            continue
        for cid in owasp_ids:
            by_owasp.setdefault(cid, []).append(f)

    out.write("## Coverage Matrix\n\n")
    out.write("| ID | Category | Findings | Worst severity |\n|---|---|---|---|\n")
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    for cid, name in OWASP_LLM_TOP_10.items():
        bucket = by_owasp.get(cid, [])
        worst = "—"
        if bucket:
            worst = max(
                bucket, key=lambda f: severity_rank.get(f.get("severity", "info"), 0)
            ).get("severity", "—")
        out.write(f"| {cid} | {name} | {len(bucket)} | {worst} |\n")
    out.write("\n")

    out.write("## Findings by Control\n\n")
    for cid, name in OWASP_LLM_TOP_10.items():
        bucket = by_owasp.get(cid, [])
        if not bucket:
            continue
        out.write(f"### {cid}: {name}\n\n")
        for f in bucket:
            out.write(
                f"- **{f.get('title')}** ({f.get('severity')}) "
                f"— risk {f.get('risk_score', 0):.0f}\n"
            )
        out.write("\n")

    if by_owasp["UNMAPPED"]:
        out.write("### Findings without OWASP mapping\n\n")
        for f in by_owasp["UNMAPPED"]:
            out.write(f"- {f.get('title')} ({f.get('severity')})\n")
        out.write("\n")

    return out.getvalue()


def _nist_ai_rmf(
    *,
    asset: dict[str, Any],
    evaluation: dict[str, Any],
    findings: list[dict[str, Any]],
    org_name: str,
) -> str:
    out = io.StringIO()
    out.write(_header("NIST AI RMF Evidence Package", asset, evaluation, org_name))

    out.write("## Function Coverage\n\n")
    out.write(
        "| Function | Description | Coverage |\n|---|---|---|\n"
        "| GOVERN | "
        + NIST_AI_RMF_FUNCTIONS["GOVERN"]
        + " | Org policies + audit log demonstrate organizational risk management. |\n"
        "| MAP | "
        + NIST_AI_RMF_FUNCTIONS["MAP"]
        + f" | Asset registry: provider={asset.get('provider')}, "
        f"environment={asset.get('environment')}, "
        f"data_classification={asset.get('data_classification')}. |\n"
        "| MEASURE | "
        + NIST_AI_RMF_FUNCTIONS["MEASURE"]
        + f" | {evaluation.get('tests_run', 0)} test cases evaluated; "
        f"{len(findings)} findings recorded with severity + risk scores. |\n"
        "| MANAGE | "
        + NIST_AI_RMF_FUNCTIONS["MANAGE"]
        + " | Remediation workflow tracks each finding through open → remediated/verified. |\n\n"
    )

    out.write("## Categorized Risks (MEASURE function)\n\n")
    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f.get("category", "uncategorized")] = (
            by_cat.get(f.get("category", "uncategorized"), 0) + 1
        )
    out.write("| Risk category | Findings |\n|---|---|\n")
    for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
        out.write(f"| {cat} | {count} |\n")
    out.write("\n")

    out.write("## Open Risks Requiring Treatment (MANAGE function)\n\n")
    open_findings = [f for f in findings if f.get("remediation_status") == "open"]
    if not open_findings:
        out.write("All findings have been remediated or risk-accepted.\n")
    else:
        for f in open_findings[:20]:
            out.write(
                f"- **{f.get('title')}** ({f.get('severity')}) — {f.get('category')}\n"
            )
    return out.getvalue()


def _soc2_ai(
    *,
    asset: dict[str, Any],
    evaluation: dict[str, Any],
    findings: list[dict[str, Any]],
    org_name: str,
) -> str:
    out = io.StringIO()
    out.write(_header("SOC 2 AI Controls Evidence", asset, evaluation, org_name))

    out.write("## Common Criteria — AI Subset\n\n")
    out.write(
        "| Control | Evidence |\n|---|---|\n"
        "| CC6.1 (Logical access) | RBAC enforced; OIDC/SAML/SCIM identity federation; hash-chained audit log of every authentication event. |\n"
        "| CC6.7 (Restricted data transmission) | Outbound LLM traffic routed through runtime agent; all prompts/responses inspected; PII patterns blocked at policy. |\n"
        "| CC7.1 (System monitoring) | Per-asset evaluation history; runtime telemetry to ClickHouse; SIEM forward for production policy violations. |\n"
        "| CC7.2 (Anomaly detection) | Stage 2 ML classifier (when enabled); red team campaigns surface novel attack patterns. |\n"
        "| CC7.3 (Security event response) | Findings carry remediation workflow with named owner; kill-switch commands push to runtime agents in seconds. |\n"
        "| CC8.1 (Change management) | change_log JSONB on AIAsset records every config mutation with timestamp + actor. |\n\n"
    )

    out.write("## Evidence Artifacts\n\n")
    out.write(
        f"- **Evaluation ID:** `{evaluation.get('id')}`\n"
        f"- **Test cases executed:** {evaluation.get('tests_run', 0)}\n"
        f"- **Findings recorded:** {len(findings)}\n"
        f"- **Audit log entries:** captured in app/security/audit_log.py (hash-chained)\n"
        f"- **Asset change history:** captured in AIAsset.change_log JSONB\n"
        f"- **Evaluation completed:** {evaluation.get('completed_at') or evaluation.get('created_at')}\n\n"
    )

    return out.getvalue()


def _eu_ai_act(
    *,
    asset: dict[str, Any],
    evaluation: dict[str, Any],
    findings: list[dict[str, Any]],
    org_name: str,
) -> str:
    out = io.StringIO()
    out.write(_header("EU AI Act Compliance Snapshot", asset, evaluation, org_name))

    exposure = asset.get("exposure", "internal_only")
    data_class = asset.get("data_classification", "internal")
    risk_class = _eu_risk_class(exposure, data_class)

    out.write(f"## Risk Classification\n\n**This asset is provisionally categorized as: {risk_class}**\n\n")
    out.write(
        "*Note: Final risk classification is the operator's responsibility "
        "under the EU AI Act. This report provides a starting point based "
        "on the asset's declared exposure + data classification.*\n\n"
    )

    out.write("## Article 9 — Risk Management System\n\n")
    out.write(
        f"- {evaluation.get('tests_run', 0)} test cases executed across "
        f"prompt injection, jailbreak, data exfiltration, unsafe tool use, "
        f"and OWASP LLM Top 10 categories.\n"
        f"- {len(findings)} risks identified with severity + risk score.\n"
        f"- Remediation workflow tracks each risk to closure.\n\n"
    )

    out.write("## Article 10 — Data Governance\n\n")
    out.write(
        f"- Data classification: {data_class}\n"
        f"- Regulatory scope: {asset.get('regulatory_scope') or 'none declared'}\n"
        f"- RAG sources: {len(asset.get('rag_sources') or [])} documented\n\n"
    )

    out.write("## Article 13 — Transparency Requirements\n\n")
    out.write(
        f"- System prompt: {'documented' if asset.get('system_prompt') else 'NOT documented (compliance gap)'}\n"
        f"- Tool capabilities: {len(asset.get('tools') or [])} registered with intent profiles (MCP inspector)\n"
        f"- Human oversight: {'required' if asset.get('human_in_loop_required') else 'NOT required (review)'}\n\n"
    )

    out.write("## Article 15 — Accuracy & Cybersecurity\n\n")
    score = evaluation.get("score", 0)
    out.write(
        f"- Composite health score: **{score:.0f} / 100** "
        f"({evaluation.get('risk_label') or '—'})\n"
        f"- {evaluation.get('critical_findings', 0)} critical-severity findings outstanding.\n"
        f"- Continuous monitoring: runtime agent inspects every LLM call against the configured policy.\n"
    )

    return out.getvalue()


def _eu_risk_class(exposure: str, data_class: str) -> str:
    if exposure in ("public", "customer_facing") and data_class in ("regulated", "restricted"):
        return "HIGH-RISK (Annex III — operators must conduct conformity assessment)"
    if exposure == "public":
        return "LIMITED-RISK (transparency obligations under Article 13)"
    if data_class == "regulated":
        return "HIGH-RISK (regulated data class; verify Annex III applicability)"
    return "MINIMAL-RISK (no specific obligations; voluntary code of conduct recommended)"
