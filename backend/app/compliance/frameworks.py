"""AI risk-framework control mapping.

Distinct from :mod:`app.compliance.evidence_pack` (which packages SOC 2 /
ISO 27001 / FedRAMP audit evidence): this module maps AI-specific *risk
findings* (attack categories + detector categories) to controls across the
frameworks the product advertises — OWASP LLM Top 10, NIST AI RMF, EU AI
Act, ISO/IEC 42001, and MITRE ATLAS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

FRAMEWORKS = ("owasp_llm", "nist_ai_rmf", "eu_ai_act", "iso_42001", "mitre_atlas")

# finding category -> {framework: [control ids]}
_MAP: dict[str, dict[str, list[str]]] = {
    "prompt_injection": {
        "owasp_llm": ["LLM01:2025 Prompt Injection"],
        "nist_ai_rmf": ["MEASURE 2.7", "MANAGE 2.1"],
        "eu_ai_act": ["Art.15 Accuracy, robustness, cybersecurity"],
        "iso_42001": ["A.6.2.4 System security"],
        "mitre_atlas": ["AML.T0051 LLM Prompt Injection"],
    },
    "indirect_injection": {
        "owasp_llm": ["LLM01:2025 Prompt Injection"],
        "mitre_atlas": ["AML.T0051.001 Indirect"],
        "nist_ai_rmf": ["MEASURE 2.7"],
    },
    "jailbreak": {
        "owasp_llm": ["LLM01:2025 Prompt Injection"],
        "mitre_atlas": ["AML.T0054 LLM Jailbreak"],
        "eu_ai_act": ["Art.15"],
    },
    "credentials": {
        "owasp_llm": ["LLM06:2025 Sensitive Information Disclosure"],
        "nist_ai_rmf": ["MANAGE 2.2"],
        "iso_42001": ["A.8.3 Data management"],
        "eu_ai_act": ["Art.10 Data governance"],
    },
    "pii": {
        "owasp_llm": ["LLM06:2025 Sensitive Information Disclosure", "LLM02:2025 Sensitive data"],
        "eu_ai_act": ["Art.10 Data governance", "GDPR Art.5"],
        "nist_ai_rmf": ["MAP 5.1", "MANAGE 2.2"],
        "iso_42001": ["A.8.3 Data management"],
    },
    "toxicity": {
        "owasp_llm": ["LLM05:2025 Improper Output Handling"],
        "eu_ai_act": ["Art.5 Prohibited practices"],
        "nist_ai_rmf": ["MEASURE 2.11"],
    },
    "malicious_url": {
        "owasp_llm": ["LLM05:2025 Improper Output Handling"],
        "mitre_atlas": ["AML.T0051"],
    },
    "source_code": {
        "owasp_llm": ["LLM06:2025 Sensitive Information Disclosure"],
        "iso_42001": ["A.8.3 Data management"],
    },
    "unsafe_tool_use": {
        "owasp_llm": ["LLM07:2025 System Prompt Leakage", "LLM08:2025 Excessive Agency"],
        "nist_ai_rmf": ["GOVERN 1.3"],
    },
    "off_topic": {
        "nist_ai_rmf": ["MEASURE 2.6"],
        "iso_42001": ["A.6.2.2 AI system objectives"],
    },
    "legal_advice": {"eu_ai_act": ["Art.5"], "iso_42001": ["A.9.2 Intended use"]},
    "financial_advice": {"eu_ai_act": ["Art.5"], "iso_42001": ["A.9.2 Intended use"]},
}


@dataclass(frozen=True)
class ComplianceMapping:
    categories: tuple[str, ...]
    by_framework: dict[str, list[str]]
    by_category: dict[str, dict[str, list[str]]]
    coverage: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "categories": list(self.categories),
            "by_framework": self.by_framework,
            "by_category": self.by_category,
            "coverage": self.coverage,
        }


def map_findings(categories: list[str]) -> ComplianceMapping:
    """Map a set of finding categories to controls across all frameworks."""
    by_cat: dict[str, dict[str, list[str]]] = {}
    by_fw: dict[str, list[str]] = {fw: [] for fw in FRAMEWORKS}
    for cat in categories:
        m = _MAP.get(cat)
        if not m:
            continue
        by_cat[cat] = m
        for fw, controls in m.items():
            for c in controls:
                if c not in by_fw[fw]:
                    by_fw[fw].append(c)
    coverage = {fw: len(ctrls) for fw, ctrls in by_fw.items()}
    return ComplianceMapping(
        categories=tuple(categories),
        by_framework=by_fw,
        by_category=by_cat,
        coverage=coverage,
    )
