"""Scanner taxonomy — the four top-level red-teaming domains.

Mirrors the product's "Security, Safety, Hallucination & Trustworthiness,
Business Alignment" grouping. Each scanner maps to attack categories
(see :mod:`app.redteam.strategies`) and to the AI Guard detectors used to
remediate findings in that domain.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Scanner:
    id: str
    domain: str
    name: str
    attack_categories: tuple[str, ...]
    remediation_detectors: tuple[str, ...] = field(default_factory=tuple)


SCANNERS: tuple[Scanner, ...] = (
    # ---- Security ----
    Scanner(
        "sec_prompt_injection",
        "security",
        "Prompt injection",
        ("prompt_injection", "indirect_injection"),
        ("prompt_injection", "invisible_text"),
    ),
    Scanner(
        "sec_jailbreak", "security", "Jailbreak / guardrail bypass", ("jailbreak",), ("jailbreak",)
    ),
    Scanner(
        "sec_credential_leak",
        "security",
        "Credential & secret leakage",
        ("credential_leakage",),
        ("credentials_secrets",),
    ),
    Scanner(
        "sec_data_exfil",
        "security",
        "Data exfiltration",
        ("data_exfiltration",),
        ("context_aware_pii", "source_code"),
    ),
    Scanner(
        "sec_encoded",
        "security",
        "Encoded / obfuscated attacks",
        ("encoded_attack",),
        ("invisible_text", "gibberish"),
    ),
    Scanner(
        "sec_tool_abuse",
        "security",
        "Unsafe tool use / privilege escalation",
        ("unsafe_tool_use", "privilege_escalation"),
        ("prompt_injection",),
    ),
    Scanner("sec_dos", "security", "Model denial of service", ("model_denial_of_service",), ()),
    # ---- Safety ----
    Scanner(
        "safe_toxicity", "safety", "Toxicity & harassment", ("output_manipulation",), ("toxicity",)
    ),
    Scanner(
        "safe_self_harm",
        "safety",
        "Self-harm & dangerous content",
        ("output_manipulation",),
        ("toxicity",),
    ),
    Scanner(
        "safe_illegal",
        "safety",
        "Illegal / harmful instructions",
        ("jailbreak", "output_manipulation"),
        ("toxicity", "jailbreak"),
    ),
    # ---- Hallucination & Trustworthiness ----
    Scanner(
        "hall_factuality",
        "hallucination",
        "Factual accuracy / fabrication",
        ("output_manipulation",),
        (),
    ),
    Scanner(
        "hall_overrefusal", "hallucination", "Over-refusal / availability", (), ("llm_refusal",)
    ),
    # ---- Business Alignment ----
    Scanner("biz_off_topic", "business_alignment", "Off-topic / scope drift", (), ("off_topic",)),
    Scanner("biz_competition", "business_alignment", "Competitor mentions", (), ("competition",)),
    Scanner("biz_brand", "business_alignment", "Brand & reputation", (), ("brand_reputation",)),
    Scanner(
        "biz_regulated_advice",
        "business_alignment",
        "Regulated advice (legal/financial)",
        (),
        ("legal_advice", "financial_advice"),
    ),
)

DOMAINS = ("security", "safety", "hallucination", "business_alignment")
_BY_CATEGORY: dict[str, list[Scanner]] = {}
for _s in SCANNERS:
    for _c in _s.attack_categories:
        _BY_CATEGORY.setdefault(_c, []).append(_s)


def for_category(category: str) -> tuple[Scanner, ...]:
    return tuple(_BY_CATEGORY.get(category, ()))


def by_domain(domain: str) -> tuple[Scanner, ...]:
    return tuple(s for s in SCANNERS if s.domain == domain)
